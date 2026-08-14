"""单一检索层(SUOTU_DESIGN §4.6)——全项目唯一数据查询出口。

硬约束:后续 L1 规则引擎 / 统计聚合 / playbook / AI 工具层一律经本模块
取数,不得另开查询路径;AI 工具 = 本模块的参数化封装(§6.1 工具表与
本模块函数一一对应:search→search_logs, stats→field_stats,
entity_lookup→entity_lookup, read_window→read_window/time_slice)。

- q 走 raw LIKE 全文面(grep 语义,唯一全文路径;FTS 已实测否决,
  见 duck.py 头注);
- field_filters 对 norm_json 做 json_extract_string 精确匹配;
- 结果每条带 source_id + line_no + raw + norm + sha256(锚点齐全);
- entity_lookup 的 cross_source 只允许 qualifier=global(防串味闸)。
"""
from __future__ import annotations

import json
import re
from datetime import datetime

from . import duck

# 归一字段名安全闸:进 SQL 的字段名必须小写字母/数字/下划线
# (rules.py 另有 NORM_FIELDS 白名单,此处是检索层的纵深防御,防注入)。
_FIELD_SAFE = re.compile(r"^[a-z][a-z0-9_]*$")


def _escape_like(q: str) -> str:
    """LIKE 字面量转义(防 q 里的 %/_ 变成通配符)。"""
    return q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_ts(text: str | None) -> datetime | None:
    """ISO 时间参数 → datetime;非法值如实抛 ValueError(API 层转 400)。"""
    if not text:
        return None
    return datetime.fromisoformat(text)


def _append_field_filters(where: list[str], params: list,
                          field_filters: dict) -> None:
    """归一字段过滤子句(search/aggregate 同源共用,单一检索层语义锚点)。

    键名白名单化防注入。值两种形态:字符串=精确匹配;
    {"contains": v}=子串包含 / {"eq": v}=精确匹配
    (UA/路径片段等场景,2026-08-05 用户场景:按 UA 头/方法/IP 条件检索)。
    """
    for key, value in field_filters.items():
        if not key.replace("_", "").isalnum():
            continue
        if isinstance(value, dict) and "contains" in value:
            where.append(
                f"json_extract_string(norm_json, '$.{key}')"
                " LIKE ? ESCAPE '\\'")
            params.append(f"%{_escape_like(str(value['contains']))}%")
        elif isinstance(value, dict) and "eq" in value:
            where.append(f"json_extract_string(norm_json, '$.{key}') = ?")
            params.append(str(value["eq"]))
        else:
            where.append(f"json_extract_string(norm_json, '$.{key}') = ?")
            params.append(str(value))


def search(case_id: str, q: str | None = None, source_id: str | None = None,
           field_filters: dict | None = None,
           ts_from: str | None = None, ts_to: str | None = None,
           limit: int = 50, offset: int = 0) -> dict:
    """全文 + 字段过滤 + 时间窗 + 源过滤(单一检索层主入口)。

    契约:任意已入库事件(含 raw_t0)必可被本函数检索到——q=None 时
    全量分页可达;q 有值时走 raw LIKE 全文面(grep 语义,唯一全文路径,
    FTS 已实测否决见 duck.py 头注),无盲区。
    """
    dconn = duck.get_conn()
    where: list[str] = []
    params: list = []

    # case 作用域:经 case.db 的源清单过滤(防跨案串味)
    from . import db as _db
    with _db.connect() as c:
        src_ids = [r["id"] for r in c.execute(
            "SELECT id FROM log_sources WHERE case_id = ?", (case_id,))]
    if source_id is not None:
        if source_id not in src_ids:
            return {"items": [], "total": 0,
                    "limit": limit, "offset": offset}
        src_ids = [source_id]
    if not src_ids:
        return {"items": [], "total": 0,
                "limit": limit, "offset": offset}
    where.append("source_id IN (" + ", ".join("?" for _ in src_ids) + ")")
    params.extend(src_ids)

    if q:
        where.append("raw LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(q)}%")

    if field_filters:
        _append_field_filters(where, params, field_filters)
    t0, t1 = _parse_ts(ts_from), _parse_ts(ts_to)
    if t0 is not None:
        where.append("ts_utc >= ?")
        params.append(t0)
    if t1 is not None:
        where.append("ts_utc <= ?")
        params.append(t1)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    rows_sql = (f"SELECT id, source_id, line_no, ts_raw, ts_utc, norm_json,"
                f" raw, sha256 FROM log_events{where_sql}"
                f" ORDER BY source_id, line_no LIMIT ? OFFSET ?")
    count_sql = f"SELECT COUNT(*) FROM log_events{where_sql}"
    total = dconn.execute(count_sql, params).fetchone()[0]
    rows = dconn.execute(rows_sql, [*params, limit, offset]).fetchall()
    items = [
        {
            "id": r[0], "source_id": r[1], "line_no": r[2],
            "ts_raw": r[3],
            "ts_utc": r[4].isoformat() if r[4] is not None else None,
            "norm": json.loads(r[5]) if r[5] else {},
            "raw": r[6], "sha256": r[7],
        }
        for r in rows
    ]
    return {"items": items, "total": total,
            "limit": limit, "offset": offset}


def scan_events(case_id: str, source_id: str | None = None,
                chunk: int = 20000):
    """流式分批产出案件内全部事件 —— 检索层给规则引擎的官方全量扫描通道。

    契约:
    - 与 search(q=None) 同一数据源、同一案件作用域(防跨案串味)——规则引擎
      不许自己写 SQL,全量扫描必须走这里(§4.6);
    - 产出 dict:{id, source_id, line_no, ts_utc, norm, raw},按
      (source_id, line_no) 稳定排序,LIMIT/OFFSET 分批,不整表读入内存;
    - 来源未入库任何事件的案件产出空迭代器,不报错(如实空)。
    """
    dconn = duck.get_conn()
    from . import db as _db
    with _db.connect() as c:
        src_ids = [r["id"] for r in c.execute(
            "SELECT id FROM log_sources WHERE case_id = ?", (case_id,))]
    if source_id is not None:
        src_ids = [source_id] if source_id in src_ids else []
    if not src_ids:
        return
    where = "source_id IN (" + ", ".join("?" for _ in src_ids) + ")"
    sql = (f"SELECT id, source_id, line_no, ts_utc, norm_json, raw"
           f" FROM log_events WHERE {where}"
           f" ORDER BY source_id, line_no LIMIT {int(chunk)} OFFSET ?")
    offset = 0
    while True:
        rows = dconn.execute(sql, [*src_ids, offset]).fetchall()
        if not rows:
            return
        for r in rows:
            yield {
                "id": r[0], "source_id": r[1], "line_no": r[2],
                "ts_utc": r[3].isoformat() if r[3] is not None else None,
                "norm": json.loads(r[4]) if r[4] else {},
                "raw": r[5],
            }
        if len(rows) < chunk:
            return
        offset += chunk


def stats(case_id: str, source_id: str | None = None) -> dict:
    """按源行数/时间范围/Top src_ip/状态码分布(有字段则出,无则如实空)。"""
    dconn = duck.get_conn()
    from . import db as _db
    with _db.connect() as c:
        sources = c.execute(
            "SELECT id, name, status, line_count, time_range FROM log_sources"
            " WHERE case_id = ?", (case_id,)).fetchall()
    ids = [s["id"] for s in sources]
    if source_id is not None:
        ids = [source_id] if source_id in ids else []
    out = {"sources": [dict(s) for s in sources], "by_source": {}}
    for sid in ids:
        entry: dict = {}
        cnt = dconn.execute(
            "SELECT COUNT(*), MIN(ts_utc), MAX(ts_utc) FROM log_events"
            " WHERE source_id = ?", (sid,)).fetchone()
        entry["events"] = cnt[0]
        entry["ts_min"] = cnt[1].isoformat() if cnt[1] else None
        entry["ts_max"] = cnt[2].isoformat() if cnt[2] else None
        entry["top_src_ip"] = [
            {"value": r[0], "count": r[1]} for r in dconn.execute(
                "SELECT json_extract_string(norm_json, '$.src_ip') AS v,"
                " COUNT(*) FROM log_events WHERE source_id = ? AND v IS NOT NULL"
                " GROUP BY v ORDER BY COUNT(*) DESC LIMIT 10", (sid,)).fetchall()
        ]
        entry["status_dist"] = [
            {"value": r[0], "count": r[1]} for r in dconn.execute(
                "SELECT json_extract_string(norm_json, '$.status') AS v,"
                " COUNT(*) FROM log_events WHERE source_id = ? AND v IS NOT NULL"
                " GROUP BY v ORDER BY COUNT(*) DESC", (sid,)).fetchall()
        ]
        out["by_source"][sid] = entry
    return out


def entity_lookup(case_id: str, value: str, cross_source: bool = False) -> dict:
    """canonical_key/raw_value 实体查找。

    防串味闸:cross_source=True(跨源聚合)只允许 qualifier=global 的实体
    (公网 IP 等);host_scoped 实体只在案件内如实列出,不参与跨源。
    """
    dconn = duck.get_conn()
    from . import db as _db
    with _db.connect() as c:
        src_ids = [r["id"] for r in c.execute(
            "SELECT id FROM log_sources WHERE case_id = ?", (case_id,))]
    if not src_ids:
        return {"items": [], "cross_source": cross_source}
    where = ["source_id IN (" + ", ".join("?" for _ in src_ids) + ")",
             "(raw_value = ? OR canonical_key = ?)"]
    params: list = [*src_ids, value, value]
    if cross_source:
        where.append("qualifier = 'global'")
    rows = dconn.execute(
        "SELECT raw_value, canonical_key, entity_type, qualifier, source_id,"
        f" line_no, ts_utc FROM entities WHERE {' AND '.join(where)}"
        " ORDER BY source_id, line_no LIMIT 500", params).fetchall()
    items = [
        {"raw_value": r[0], "canonical_key": r[1], "entity_type": r[2],
         "qualifier": r[3], "source_id": r[4], "line_no": r[5],
         "ts_utc": r[6].isoformat() if r[6] is not None else None}
        for r in rows
    ]
    return {"items": items, "cross_source": cross_source,
            "note": "cross_source 仅 qualifier=global" if cross_source else None}


def read_window(source_id: str, line_from: int, line_to: int) -> dict:
    """带行号原文段(锚点不丢,L3 精读/查看器共用)。"""
    dconn = duck.get_conn()
    rows = dconn.execute(
        "SELECT line_no, ts_raw, ts_utc, norm_json, raw FROM log_events"
        " WHERE source_id = ? AND line_no BETWEEN ? AND ?"
        " ORDER BY line_no", (source_id, line_from, line_to)).fetchall()
    return {
        "source_id": source_id, "line_from": line_from, "line_to": line_to,
        "lines": [
            {"line_no": r[0], "ts_raw": r[1],
             "ts_utc": r[2].isoformat() if r[2] is not None else None,
             "norm": json.loads(r[3]) if r[3] else {}, "raw": r[4]}
            for r in rows
        ],
    }


# ==================== M2 统计聚合(检索层扩函数,rules.py 统计规则的唯一取数口) ====================
# 纪律:本层只出聚合行,不做「是否命中」的判定(判定在 rules.py 统计算子);
# 案件作用域与 search/scan_events 同一套解析逻辑,防跨案串味。

def _case_source_ids(case_id: str) -> list[str]:
    """案件 → 源 id 清单(与 search/scan_events 同一作用域解析)。"""
    from . import db as _db
    with _db.connect() as c:
        return [r["id"] for r in c.execute(
            "SELECT id FROM log_sources WHERE case_id = ?", (case_id,))]


def _field_expr(field: str) -> str:
    """归一字段 → json_extract_string 表达式(字段名过安全闸,防注入)。"""
    if not _FIELD_SAFE.match(field):
        raise ValueError(f"非法归一字段名: {field!r}")
    return f"json_extract_string(norm_json, '$.{field}')"


def _check_source(case_id: str, source_id: str) -> bool:
    """source 必须属于 case,否则一律空结果(防跨案串味,不报错不猜)。"""
    return source_id in _case_source_ids(case_id)


def agg_divergence(case_id: str, source_id: str, key_fields: list[str],
                   diverge_field: str, metric: str) -> list[dict]:
    """same_key_divergence 取数:按 键字段+分化字段 GROUP BY,出每桶
    计数/metric 均值/代表行(组内最小行号)/首时间。

    无分化字段或缺任一键字段的事件不参与(如实不计,不拿 NULL 凑桶);
    metric 非数值的行 TRY_CAST 为 NULL,AVG 自然忽略。
    """
    if not _check_source(case_id, source_id):
        return []
    keys = [_field_expr(f) for f in key_fields]
    dv, mv = _field_expr(diverge_field), _field_expr(metric)
    not_null = " AND ".join(f"{k} IS NOT NULL" for k in keys)
    sql = (
        f"SELECT {', '.join(keys)}, {dv},"
        f" COUNT(*), AVG(TRY_CAST({mv} AS DOUBLE)),"
        f" MIN(line_no), MIN(ts_utc)"
        f" FROM log_events WHERE source_id = ? AND {not_null}"
        f" AND {dv} IS NOT NULL"
        f" GROUP BY {', '.join(str(i + 1) for i in range(len(keys) + 1))}")
    rows = duck.get_conn().execute(sql, (source_id,)).fetchall()
    return [
        {"key": list(r[:len(keys)]), "diverge": r[len(keys)],
         "count": r[len(keys) + 1], "avg": r[len(keys) + 2],
         "first_line": r[len(keys) + 3],
         "first_ts": r[len(keys) + 4].isoformat()
         if r[len(keys) + 4] is not None else None}
        for r in rows
    ]


def agg_value_keys(case_id: str, source_id: str, value_field: str,
                   key_fields: list[str]) -> list[dict]:
    """cross_key_same_value 取数:按 值字段×键字段 GROUP BY,出每对
    计数/首末时间/代表行。稀有度(全局频次)与排除由 rules.py 判定。"""
    if not _check_source(case_id, source_id):
        return []
    keys = [_field_expr(f) for f in key_fields]
    vf = _field_expr(value_field)
    not_null = " AND ".join(f"{k} IS NOT NULL" for k in keys)
    ncols = len(keys) + 1
    sql = (
        f"SELECT {vf}, {', '.join(keys)},"
        f" COUNT(*), MIN(ts_utc), MAX(ts_utc), MIN(line_no)"
        f" FROM log_events WHERE source_id = ? AND {vf} IS NOT NULL"
        f" AND {not_null}"
        f" GROUP BY {', '.join(str(i + 1) for i in range(ncols))}")
    rows = duck.get_conn().execute(sql, (source_id,)).fetchall()
    return [
        {"value": r[0], "key": list(r[1:ncols]), "count": r[ncols],
         "first_ts": r[ncols + 1].isoformat()
         if r[ncols + 1] is not None else None,
         "last_ts": r[ncols + 2].isoformat()
         if r[ncols + 2] is not None else None,
         "first_line": r[ncols + 3]}
        for r in rows
    ]


def agg_rate_buckets(case_id: str, source_id: str, key_fields: list[str],
                     bucket_seconds: int) -> list[dict]:
    """rate_spike 取数:键字段 × 时间桶(ts_utc 截桶)计数 + 代表行。

    ts_utc 为 NULL 的事件不参与(时间未知不硬算);空桶不补零——
    z-score 基线只计有事件的桶,稀疏长空档不虚构基线(诚实边界,
    已在 rules.py 命中文案注明)。
    """
    if not _check_source(case_id, source_id):
        return []
    keys = [_field_expr(f) for f in key_fields]
    not_null = " AND ".join(f"{k} IS NOT NULL" for k in keys)
    ncols = len(keys) + 1
    sql = (
        f"SELECT {', '.join(keys)},"
        f" CAST(FLOOR(epoch(ts_utc) / ?) AS BIGINT) * ? AS bucket_start,"
        f" COUNT(*), MIN(line_no)"
        f" FROM log_events WHERE source_id = ? AND ts_utc IS NOT NULL"
        f" AND {not_null}"
        f" GROUP BY {', '.join(str(i + 1) for i in range(ncols))}")
    rows = duck.get_conn().execute(
        sql, (int(bucket_seconds), int(bucket_seconds), source_id)).fetchall()
    return [
        {"key": list(r[:len(keys)]), "bucket_start": int(r[len(keys)]),
         "count": r[ncols], "first_line": r[ncols + 1]}
        for r in rows
    ]


def agg_size_outliers(case_id: str, source_id: str, key_fields: list[str],
                      metric: str, min_group_events: int,
                      deviate_ratio: float,
                      max_outliers_per_group: int = 3) -> list[dict]:
    """size_outlier 取数(2026-08-08 用户狩猎思路):同键(路径/方法/状态码)
    组内按 metric(默认 bytes)找离群响应——主体聚在中位数附近,
    偏离超 deviate_ratio 倍的少数派逐行返回(带行号锚点)。

    两趟:①组统计(中位数+极值,DuckDB MEDIAN 向量化)筛出候选组;
    ②只对候选组拉离群行(每键限量)。median=0 的组跳过(防除零,
    如实);metric 非数值 TRY_CAST 为 NULL 自然不计。
    """
    if not _check_source(case_id, source_id):
        return []
    keys = [_field_expr(f) for f in key_fields]
    mv = _field_expr(metric)
    not_null = " AND ".join(f"{k} IS NOT NULL" for k in keys)
    ncols = len(keys)
    dconn = duck.get_conn()
    groups = dconn.execute(
        f"SELECT {', '.join(keys)}, COUNT(*),"
        f" MEDIAN(TRY_CAST({mv} AS DOUBLE)),"
        f" MAX(TRY_CAST({mv} AS DOUBLE)), MIN(TRY_CAST({mv} AS DOUBLE))"
        f" FROM log_events WHERE source_id = ? AND {not_null}"
        f" AND TRY_CAST({mv} AS DOUBLE) IS NOT NULL"
        f" GROUP BY {', '.join(str(i + 1) for i in range(ncols))}"
        f" HAVING COUNT(*) >= ?",
        (source_id, min_group_events)).fetchall()
    out: list[dict] = []
    for g in groups:
        key_vals, count, median = list(g[:ncols]), g[ncols], g[ncols + 1]
        gmax, gmin = g[ncols + 2], g[ncols + 3]
        if not median or median <= 0:
            continue                            # 中位数为 0/空:不比,防除零
        if gmax <= median * deviate_ratio and gmin >= median / deviate_ratio:
            continue                            # 全组在带内,无离群
        conds = " AND ".join(f"{_field_expr(f)} = ?" for f in key_fields)
        hi, lo = median * deviate_ratio, median / deviate_ratio
        rows = dconn.execute(
            f"SELECT line_no, TRY_CAST({mv} AS DOUBLE), ts_utc FROM log_events"
            f" WHERE source_id = ? AND {conds}"
            f" AND (TRY_CAST({mv} AS DOUBLE) > ?"
            f"      OR TRY_CAST({mv} AS DOUBLE) < ?)"
            f" ORDER BY ABS(TRY_CAST({mv} AS DOUBLE) - ?) DESC LIMIT ?",
            (source_id, *key_vals, hi, lo, median, max_outliers_per_group),
        ).fetchall()
        for line_no, val, ts in rows:
            out.append({"key": key_vals, "line_no": line_no, "value": val,
                        "group_count": count, "median": median,
                        "ts_utc": ts.isoformat() if ts is not None else None})
    return out


def source_ts_coverage(case_id: str, source_id: str) -> dict:
    """源的时间覆盖:{events, with_ts};with_ts=0 → 时序类算子如实跳过。"""
    if not _check_source(case_id, source_id):
        return {"events": 0, "with_ts": 0}
    r = duck.get_conn().execute(
        "SELECT COUNT(*), COUNT(ts_utc) FROM log_events WHERE source_id = ?",
        (source_id,)).fetchone()
    return {"events": r[0], "with_ts": r[1]}


def cross_source_global_entities(case_id: str,
                                 source_ids: list[str] | None = None) -> list[dict]:
    """跨源联动取数:qualifier=global 实体按 canonical_key × source 聚合。

    防张冠李戴闸:host_scoped(私网 IP/账户)实体 SQL 层就排除,永不跨源;
    source_ids 给定时取交集(单源扫描作用域下本函数自然出空)。
    """
    src_ids = _case_source_ids(case_id)
    if source_ids is not None:
        src_ids = [s for s in source_ids if s in src_ids]
    if not src_ids:
        return []
    where = "source_id IN (" + ", ".join("?" for _ in src_ids) + ")"
    rows = duck.get_conn().execute(
        "SELECT canonical_key, entity_type, source_id,"
        " COUNT(*), MIN(line_no), MIN(ts_utc)"
        f" FROM entities WHERE qualifier = 'global' AND {where}"
        " GROUP BY 1, 2, 3", src_ids).fetchall()
    return [
        {"canonical_key": r[0], "entity_type": r[1], "source_id": r[2],
         "count": r[3], "first_line": r[4],
         "first_ts": r[5].isoformat() if r[5] is not None else None}
        for r in rows
    ]


def corroborate_events(case_id: str, source_ids: list[str],
                       ts_from: datetime, ts_to: datetime,
                       path: str | None, src_ip: str | None,
                       limit: int = 20) -> list[dict]:
    """互证取数:兄弟源集合内,时间窗 ±window 内 path 相同或 src_ip 相同
    的事件(限量,锚点齐全)。path/src_ip 都无 → 空(无比对基准,如实)。"""
    src_ids = [s for s in source_ids if s in _case_source_ids(case_id)]
    conds = []
    params: list = []
    if path is not None:
        conds.append(f"{_field_expr('path')} = ?")
        params.append(path)
    if src_ip is not None:
        conds.append(f"{_field_expr('src_ip')} = ?")
        params.append(src_ip)
    if not src_ids or not conds:
        return []
    # log_events.ts_utc 是 naive TIMESTAMP;aware 参数统一去 tz 再比
    if ts_from.tzinfo is not None:
        ts_from = ts_from.replace(tzinfo=None)
    if ts_to.tzinfo is not None:
        ts_to = ts_to.replace(tzinfo=None)
    where = ("source_id IN (" + ", ".join("?" for _ in src_ids) + ")"
             " AND ts_utc >= ? AND ts_utc <= ? AND (" + " OR ".join(conds) + ")")
    rows = duck.get_conn().execute(
        "SELECT source_id, line_no, ts_utc, norm_json, raw FROM log_events"
        f" WHERE {where} ORDER BY ts_utc, source_id, line_no LIMIT ?",
        [*src_ids, ts_from, ts_to, *params, int(limit)]).fetchall()
    return [
        {"source_id": r[0], "line_no": r[1],
         "ts_utc": r[2].isoformat() if r[2] is not None else None,
         "norm": json.loads(r[3]) if r[3] else {}, "raw": r[4]}
        for r in rows
    ]


# ==================== M5 即席聚合(命中驱动二次排查动作,确定性零 AI) ====================

def aggregate(case_id: str, field: str, source_id: str | None = None,
              field_filters: dict | None = None,
              ts_from: str | None = None, ts_to: str | None = None,
              limit: int = 20) -> dict:
    """即席 GROUP BY 分布:「按某字段再聚类」——命中后人想看的下一个维度。

    - 与 search 同一案件作用域解析、同一 field_filters/时间窗语义
      (_append_field_filters 共用,单一检索层,不另开数据路径);
    - 字段名过 _field_expr 安全闸(非法名 → ValueError,API 层转 400;
      归一字段白名单在 API 层卡 rules.NORM_FIELDS);
    - field 值为 NULL 的事件不进桶(如实不计,与 stats 同纪律);
    - total_events = 过滤后范围内的全部事件数(含 field 为 NULL 的),
      buckets 之和可能小于它,差额即「无该字段」的量——不拿 NULL 凑桶。
    """
    dconn = duck.get_conn()
    expr = _field_expr(field)                    # 非法字段名 → ValueError
    src_ids = _case_source_ids(case_id)
    if source_id is not None:
        if source_id not in src_ids:
            return {"field": field, "total_events": 0, "buckets": []}
        src_ids = [source_id]
    if not src_ids:
        return {"field": field, "total_events": 0, "buckets": []}
    where: list[str] = [
        "source_id IN (" + ", ".join("?" for _ in src_ids) + ")"]
    params: list = list(src_ids)
    if field_filters:
        _append_field_filters(where, params, field_filters)
    t0, t1 = _parse_ts(ts_from), _parse_ts(ts_to)
    if t0 is not None:
        where.append("ts_utc >= ?")
        params.append(t0)
    if t1 is not None:
        where.append("ts_utc <= ?")
        params.append(t1)
    where_sql = " WHERE " + " AND ".join(where)
    total = dconn.execute(
        f"SELECT COUNT(*) FROM log_events{where_sql}", params).fetchone()[0]
    rows = dconn.execute(
        f"SELECT {expr} AS v, COUNT(*) AS c FROM log_events{where_sql}"
        f" AND {expr} IS NOT NULL GROUP BY v ORDER BY c DESC, v LIMIT ?",
        [*params, int(limit)]).fetchall()
    return {"field": field, "total_events": total, "limit": limit,
            "buckets": [{"value": r[0], "count": r[1]} for r in rows]}


# ---------------------------------------------------------------- 关联强度(SAG 式 PageRank)

def entity_linkage_scores(case_id: str, source_id: str | None = None,
                          damping: float = 0.85, rounds: int = 20,
                          max_entities: int = 5000,
                          max_df: int = 200) -> dict[tuple[str, int], float]:
    """事件关联强度评分(借 SAG/arXiv:2606.15971 的查询期超边思路,确定性版)。

    事件 = 日志行((source_id, line_no));实体共享构边,边权 =
    实体稀有度(1/df)× ln(1+频次);在事件图上跑加权 PageRank。
    返回 {(source_id, line_no): 强度分}。

    纪律与保险丝:
    - df=1 的实体不构成联动,直接跳过;df>max_df 的热门实体(127.0.0.1
      这类)跳过——防毛线团,稀有才有信号;
    - 参与实体总数超 max_entities 时按稀有度(升 df)截断;
    - 全确定性:同输入同输出,无 LLM 参与;分数只是排序依据,不是判定。
    """
    src_ids = _case_source_ids(case_id)
    if source_id is not None:
        src_ids = [source_id] if source_id in src_ids else []
    if not src_ids:
        return {}
    where = "source_id IN (" + ", ".join("?" for _ in src_ids) + ")"
    rows = duck.get_conn().execute(
        f"SELECT canonical_key, source_id, line_no FROM entities"
        f" WHERE {where}", src_ids).fetchall()
    by_key: dict[str, list[tuple[str, int]]] = {}
    for key, sid, line_no in rows:
        by_key.setdefault(key, []).append((sid, line_no))

    # 稀有度过滤 + 截断
    cands = [(k, occ) for k, occ in by_key.items()
             if 2 <= len(set(occ)) <= max_df]
    cands.sort(key=lambda kv: len(set(kv[1])))          # 升 df = 最稀有优先
    cands = cands[:max_entities]

    # 事件图:W(ei→ej) += (1/df) * ln(1+freq(k, ej))
    import math
    out_w: dict[tuple[str, int], dict[tuple[str, int], float]] = {}
    for _key, occ in cands:
        uniq = sorted(set(occ))
        df = len(uniq)
        w = 1.0 / df
        freq: dict[tuple[str, int], int] = {}
        for e in occ:
            freq[e] = freq.get(e, 0) + 1
        for ei in uniq:
            row = out_w.setdefault(ei, {})
            for ej in uniq:
                if ej != ei:
                    row[ej] = row.get(ej, 0.0) + w * math.log1p(freq[ej])
    nodes = sorted(out_w)
    if not nodes:
        return {}
    n = len(nodes)
    pr = {e: 1.0 / n for e in nodes}
    for _ in range(rounds):
        new = {e: (1.0 - damping) / n for e in nodes}
        for ei in nodes:
            out_sum = sum(out_w[ei].values())
            if out_sum <= 0:
                continue
            for ej, w in out_w[ei].items():
                new[ej] += damping * pr[ei] * (w / out_sum)
        pr = new
    return pr
