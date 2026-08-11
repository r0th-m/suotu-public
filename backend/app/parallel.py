"""并行化基建(2026-08-10,平移主机取证平台「并行化一期」结构,用户拍板顺序项 ④)。

与主机取证平台同一结构铁律:
- worker 进程**纯计算**:按「行区间」解析单行安全格式 → 事件/实体两路
  CSV(duck.RowCsvWriter 方言);worker 不碰任何数据库;
- 主进程唯一写者:duck.copy_csv_file 直灌(插入前后表计数差对账,
  失败 ROLLBACK),log_sources 状态/审计/时间范围全留主进程;
- `SUOTU_PARALLEL_WORKERS`:缺省 min(cpu,8) 下限 2;显式 1 → 串行原路径;
  非法值 → 1(不猜)。

逐行安全格式(line_safe)才并行:
- 内置 nginx_combined / apache_common / raw_t0(模块标 LINE_SAFE=True);
- desc 描述文件:kind ∈ {regex, json} 且无 multiline(csv 有表头状态,
  iis_w3c 有 #Fields 头状态,multiline 续行有跨行状态——全部留串行);
- 锚点不变式:worker 按主进程预算的 (起始行号, 字节偏移) 直跳寻址,
  line_no 恒为原文物理行号(1 起),与串行逐行一致。

诚实边界:事件 id 是 uuid4(串行也随机),等价断言口径=除 id 外全列
集合相等(顺序无关);多行/表头格式不在并行面内是刻意收窄,不是遗漏。
"""
from __future__ import annotations

import io
import json
import multiprocessing as mp
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

_ENV = "SUOTU_PARALLEL_WORKERS"

# 小于该体积不值得一池进程(spawn 冷启动摊不回来),如实走串行
MIN_PARALLEL_BYTES = 16 * 1024 * 1024
# 行区间粒度(主进程预扫索引的档距)
CHUNK_LINES = 250_000


def workers_from_env() -> int:
    raw = os.environ.get(_ENV, "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            return 1
    return max(2, min(os.cpu_count() or 2, 8))


def line_safe(mod, format_id: str) -> bool:
    """格式是否逐行无状态(可并行);拿不准一律 False 留串行(不猜)。"""
    from . import formats
    if getattr(mod, "LINE_SAFE", False):
        return True
    if format_id.startswith(formats.DESC_PREFIX):
        return (getattr(mod, "kind", None) in ("regex", "json")
                and getattr(mod, "_start_re", None) is None)
    return False


def build_line_index(path: Path, chunk_lines: int = CHUNK_LINES) -> list[tuple[int, int]]:
    """主进程预扫(单趟二进制):返回 [(起始行号, 字节偏移)] 档距索引。

    1MB 块数 \\n(0x0A 在 UTF-8/GBK 都不可能出现在多字节字符内部,
    偏移落点恒为字符边界);只读,文件全程不解码(6.7GB 级约秒级)。
    """
    index = [(1, 0)]
    line_no = 1
    pos = 0
    total = path.stat().st_size
    with path.open("rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            start = 0
            while True:
                nl = block.find(b"\n", start)
                if nl < 0:
                    break
                line_no += 1
                nxt = pos + nl + 1
                # 落点在 EOF 之外(文件以 \n 收尾)不产生空区间索引
                if (line_no - 1) % chunk_lines == 0 and line_no > 1 \
                        and nxt < total:
                    index.append((line_no, nxt))
                start = nl + 1
            pos += len(block)
    return index


# ----------------------------------------------------------------- worker 侧

def _worker_init() -> None:
    """spawn 子进程冷启动:导入 formats/ingest(注册表与实体抽取)。"""
    from . import formats, ingest  # noqa: F401


def parse_chunk_task(task: dict) -> dict:
    """worker 入口:解析 [start_line, end_line) 行区间 → CSV + 计数。

    task/result 全可 pickle;result 的 CSV 路径由主进程 COPY 后删除。
    事件与实体单趟同出(串行分两趟是内存取舍,worker 流式写 CSV 内存恒定,
    结果集一致)。
    """
    from . import formats, normalize
    from .ingest import _extract_entities

    t0 = time.monotonic()
    res = {"events": 0, "entities": 0, "total_lines": 0, "parsed": 0,
           "bad_lines": 0, "skipped_lines": 0, "bad_samples": [],
           "csvs": {}, "error": None, "ms": 0}
    tmp_dir = Path(task["tmp_dir"])
    writers = {}
    try:
        from . import duck
        mod = formats.find_format(task["format_id"])
        if mod is None:
            raise ValueError(f"worker 内格式不可用: {task['format_id']}")
        for stream in ("events", "entities"):
            path = tmp_dir / f"{task['tag']}.{stream}.csv"
            writers[stream] = duck.RowCsvWriter(path)
            res["csvs"][stream] = str(path)
        start_line, end_line = task["start_line"], task["end_line"]
        tz = task["tz_declared"]

        def _chunk_lines():
            with open(task["path"], "rb") as fb:
                fb.seek(task["byte_offset"])
                text = io.TextIOWrapper(fb, encoding=task["encoding"],
                                        errors="replace")
                for no, line in enumerate(text, start_line):
                    if end_line is not None and no >= end_line:
                        break                     # None = 末块读到 EOF
                    yield line

        offset = start_line - 1
        for o in mod.parse(_chunk_lines()):
            o.line_no += offset               # 锚点=原文物理行号(不变式)
            res["total_lines"] += 1
            if o.kind == "skip":
                res["skipped_lines"] += 1
                continue
            if o.kind == "bad":
                res["bad_lines"] += 1
                if len(res["bad_samples"]) < 10:
                    res["bad_samples"].append(
                        f"L{o.line_no}: {o.reason or '不匹配'}")
                continue
            res["parsed"] += 1
            ts_utc = normalize.to_utc(o.dt_local, tz)
            writers["events"].write_rows([(
                uuid.uuid4().hex, task["source_id"], o.line_no,
                o.ts_raw, ts_utc, json.dumps(o.norm, ensure_ascii=False),
                o.raw, task["sha256"])])
            ents = _extract_entities(task["source_id"], o.line_no, ts_utc,
                                     o.norm)
            if ents:
                writers["entities"].write_rows(ents)
    except Exception as e:                     # 异常转错误字典,零静默
        res["error"] = f"{type(e).__name__}: {e}"[:500]
    finally:
        for w in writers.values():
            w.close()
    res["events"] = writers["events"].count if "events" in writers else 0
    res["entities"] = writers["entities"].count if "entities" in writers else 0
    res["ms"] = int((time.monotonic() - t0) * 1000)
    return res


# ----------------------------------------------------------------- 主进程侧

def run_parse_tasks(tasks: list[dict], workers: int):
    """派发解析任务,逐结果 yield(完成序)。池生命周期本函数管。"""
    ctx = mp.get_context("spawn")
    pool = ctx.Pool(workers, initializer=_worker_init)
    try:
        chunk = max(1, len(tasks) // (workers * 4))
        yield from pool.imap_unordered(parse_chunk_task, tasks, chunksize=chunk)
    finally:
        pool.close()
        pool.join()


def make_tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="suotu_par_"))


def cleanup_tmp_dir(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
