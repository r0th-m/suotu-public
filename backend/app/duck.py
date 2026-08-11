"""DuckDB 事件/实体层(log.duckdb):机器派生,可随时从 case.db + 金库重建。

落库通道(主机取证平台实测教训平移):executemany 每行一次 Python→C++ 往返极慢,
走 csv.writer(RFC4180)+ 原生 COPY,显式列清单免嗅探;
None → 空字段 → read_csv nullstr='' 还原 NULL。
datetime 显式格式化 + 显式 timestampformat,防 CSV 嗅探定错日期掩码。

并发:模块级单写者锁(RLock),同进程多连接共享库实例,写串行读不锁。

全文检索(§4.5 2026-08-05 实测定稿):唯一路径 = raw LIKE(grep 语义,
千万行 0.7s 实测);DuckDB FTS 扩展已实测否决(索引不增量维护/全表打分
spill 崩/WAL 重放毁库三宗罪,见 PROGRESS.md),代码层不保留任何 FTS 路径。
"""
from __future__ import annotations

import csv
import tempfile
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Sequence

import duckdb

from . import config

_BATCH = 20000  # 分批 COPY 窗口(流式,不攒全量)

# DuckDB 单写者锁:所有写操作持锁串行;RLock 允许同线程嵌套。
_WRITE_LOCK = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS log_events (
  id VARCHAR NOT NULL,
  source_id VARCHAR NOT NULL,          -- 归属不可空(防串味不变量)
  line_no BIGINT NOT NULL,             -- 原文物理行号(证据链锚点)
  ts_raw VARCHAR,                      -- 原始层:行内时间原样(无则 NULL,不伪造)
  ts_utc TIMESTAMP,                    -- 归一层:时区声明已知才填;否则 NULL 标「时区未知」
  norm_json VARCHAR NOT NULL,          -- 归一字段(mini-ECS,schemaless JSON,不丢数据)
  raw VARCHAR NOT NULL,                -- 原文行完整保留(事件是原子)
  sha256 VARCHAR NOT NULL              -- 源文件哈希(锚到「源+行+哈希」)
);
CREATE TABLE IF NOT EXISTS entities (
  raw_value VARCHAR NOT NULL,
  canonical_key VARCHAR NOT NULL,
  entity_type VARCHAR NOT NULL,        -- ip | domain | account
  qualifier VARCHAR NOT NULL CHECK (qualifier IN ('global','host_scoped')),
  source_id VARCHAR NOT NULL,
  line_no BIGINT NOT NULL,
  ts_utc TIMESTAMP
);
"""

_EVENT_COLS = ("id", "source_id", "line_no", "ts_raw", "ts_utc",
               "norm_json", "raw", "sha256")
_EVENT_TYPES = {"line_no": "BIGINT", "ts_utc": "TIMESTAMP"}
_ENTITY_COLS = ("raw_value", "canonical_key", "entity_type", "qualifier",
                "source_id", "line_no", "ts_utc")
_ENTITY_TYPES = {"line_no": "BIGINT", "ts_utc": "TIMESTAMP"}

# FTS 已实测否决(2026-08-05 千万行压测,见 PROGRESS.md):
# ①索引不随插入增量维护,批边界重建比解析本身还贵(901s vs 775s);
# ②match_bm25 全表打分在千万文档下临时存储 spill 崩(7.6GB+);
# ③含 FTS schema drop 的 WAL 无法重放(DependencyException),库直接报废。
# 结论:全文检索唯一路径 = raw LIKE(grep 语义,千万行 0.7s 实测)。
_CONN: duckdb.DuckDBPyConnection | None = None
_CONN_LOCK = threading.Lock()


def connect(db_file: Path | None = None) -> duckdb.DuckDBPyConnection:
    """打开(必要时建库建表)并返回连接;memory_limit 硬上限防 OOM。"""
    path = db_file or config.duck_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(path))
    conn.execute(f"SET memory_limit = '{config.duck_memory_limit()}'")
    conn.execute(SCHEMA)
    return conn


def get_conn() -> duckdb.DuckDBPyConnection:
    """进程级共享连接(DuckDB 文件库单进程单实例,避免多连接互踩)。"""
    global _CONN
    with _CONN_LOCK:
        if _CONN is None:
            _CONN = connect()
        return _CONN


def reset() -> None:
    """关闭共享连接(测试换数据目录时调用)。"""
    global _CONN
    with _CONN_LOCK:
        if _CONN is not None:
            try:
                _CONN.close()
            except Exception:
                pass
            _CONN = None


def _chunks(rows: Iterable[Sequence], size: int = _BATCH) -> Iterator[list[Sequence]]:
    buf: list[Sequence] = []
    for r in rows:
        buf.append(r)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def _copy_batch(conn: duckdb.DuckDBPyConnection, table: str,
                batch: list[Sequence], columns: Sequence[str],
                types: dict[str, str]) -> None:
    """一批行 → 临时 CSV → INSERT INTO ... SELECT read_csv(显式列清单免嗅探)。

    DuckDB 的 COPY FROM 不支持列清单,走 read_csv(同一 CSV 读取器与全部
    格式选项,语义等价);列类型与表结构对齐,TIMESTAMP 列走显式格式。
    """
    tmp = Path(tempfile.gettempdir()) / f"suotu_{table}_{uuid.uuid4().hex}.csv"
    try:
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            # lineterminator 显式 \n(2026-08-05 实测:csv 默认 \r\n 与多行块
            # raw 内嵌 \n 混排时,DuckDB 嗅探器直接认不出方言;
            # 统一 LF 后稳定可读,证据字节不变——记录分隔符不等于证据内容)
            w = csv.writer(f, lineterminator="\n")  # QUOTE_MINIMAL = RFC4180
            for row in batch:
                w.writerow([
                    "" if v is None else
                    v.strftime("%Y-%m-%d %H:%M:%S.%f")
                    if isinstance(v, datetime) else v
                    for v in row])
        path_sql = str(tmp).replace("\\", "/").replace("'", "''")
        colspec = "{" + ", ".join(
            f"'{c}': '{types.get(c, 'VARCHAR')}'" for c in columns) + "}"
        conn.execute(
            f"INSERT INTO {table} ({', '.join(columns)})"
            f" SELECT * FROM read_csv('{path_sql}', header=false,"
            f" quote='\"', escape='\"', nullstr='', columns={colspec},"
            f" timestampformat='%Y-%m-%d %H:%M:%S.%f')")
    finally:
        tmp.unlink(missing_ok=True)


def insert_events(conn: duckdb.DuckDBPyConnection, rows: Iterable[Sequence]) -> int:
    """分批插入事件;rows 每项按 _EVENT_COLS 顺序。返回插入条数。"""
    with _WRITE_LOCK:
        n = 0
        for batch in _chunks(rows):
            _copy_batch(conn, "log_events", batch, _EVENT_COLS, _EVENT_TYPES)
            n += len(batch)
        return n


def insert_entities(conn: duckdb.DuckDBPyConnection, rows: Iterable[Sequence]) -> int:
    """分批插入实体出现记录;rows 每项按 _ENTITY_COLS 顺序。"""
    with _WRITE_LOCK:
        n = 0
        for batch in _chunks(rows):
            _copy_batch(conn, "entities", batch, _ENTITY_COLS, _ENTITY_TYPES)
            n += len(batch)
        return n


class RowCsvWriter:
    """行元组 → RFC4180 CSV 流式写器(并行 worker 与 _copy_batch 同一方言;
    lineterminator 显式 \\n——2026-08-05 实测混行尾会让 read_csv 嗅探炸)。"""

    def __init__(self, path: Path):
        self._fh = open(path, "w", newline="", encoding="utf-8")
        self._w = csv.writer(self._fh, lineterminator="\n")
        self.count = 0

    def write_rows(self, rows: Iterable[Sequence]) -> None:
        for row in rows:
            self._w.writerow([
                "" if v is None else
                v.strftime("%Y-%m-%d %H:%M:%S.%f")
                if isinstance(v, datetime) else v
                for v in row])
            self.count += 1

    def close(self) -> None:
        self._fh.close()


def copy_csv_file(conn: duckdb.DuckDBPyConnection, table: str, csv_path: Path,
                  columns: Sequence[str], types: dict[str, str],
                  expect_rows: int | None = None) -> None:
    """外部产 CSV(RowCsvWriter 方言)直灌入库——并行 worker 文件的落库口。

    与 _copy_batch 同一读取语义;expect_rows 对账=插入前后表计数差
    (列存 count 近免费,不做 CSV 预读全扫),不符即 ROLLBACK 零残留。
    """
    with _WRITE_LOCK:
        path_sql = str(csv_path).replace("\\", "/").replace("'", "''")
        colspec = "{" + ", ".join(
            f"'{c}': '{types.get(c, 'VARCHAR')}'" for c in columns) + "}"
        before = (conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                  if expect_rows is not None else 0)
        conn.execute("BEGIN")
        try:
            conn.execute(
                f"INSERT INTO {table} ({', '.join(columns)})"
                f" SELECT * FROM read_csv('{path_sql}', header=false,"
                f" quote='\"', escape='\"', nullstr='', columns={colspec},"
                f" timestampformat='%Y-%m-%d %H:%M:%S.%f')")
            if expect_rows is not None:
                after = conn.execute(
                    f"SELECT count(*) FROM {table}").fetchone()[0]
                if after - before != expect_rows:
                    raise ValueError(
                        f"CSV 对账失败 {csv_path.name}: 声明 {expect_rows} 行,"
                        f"实入 {after - before} 行")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")


def delete_source(conn: duckdb.DuckDBPyConnection, source_id: str) -> None:
    """重解析前清掉该源的派生行(幂等;派生物可丢弃重建)。"""
    with _WRITE_LOCK:
        conn.execute("DELETE FROM log_events WHERE source_id = ?", (source_id,))
        conn.execute("DELETE FROM entities WHERE source_id = ?", (source_id,))