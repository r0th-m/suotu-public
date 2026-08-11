"""AI 工具层(M3 数据面五件套 + M5 模块状态五件,SUOTU_DESIGN §6.1)
= query.py 单一检索层 + 各模块只读视图的参数化封装。

纪律(§4.6 焊死):
- 数据面五件套与 query 模块函数一一对应,本模块不写一行 SQL;
  search_logs→query.search,field_stats→query.stats,
  entity_lookup→query.entity_lookup,time_slice/read_window→query.read_window;
- 模块状态五件(M5,用户拍板「AI 必须能读取所有模块的信息」):
  list_sources/list_hits/list_clues/get_analysis_runs/kb_explain——
  规则扫描的命中、L3 的 ai-l3-finding、人 accept 的线索、解析报告状态,
  每个模块的产物至少一条工具可达路径(契约测试断言级焊死,防「模块数据
  AI 不可见」回归——主机取证平台词典抽词门教训);
- 全部只读:只经 query 检索层/模块只读视图取数,不触碰任何写路径
  (测试断言审计零新增);
- 白名单 dispatch:未知名 → {ok:false} 错误返回,不执行;
- 参数类型/范围校验:坏参数 → {ok:false,error} 喂回 AI 自纠,不炸循环;
- entity_lookup 跨源闸不变:cross_source=True 只放行 qualifier=global;
- time_slice/read_window 带案件作用域校验(source 不属于 case → 错误,
  防跨案串味;query.read_window 本身无案件闸,这里补上);
- 结果体量上限截尾并如实标 truncated(截断不丢 total,锚点可回查)。
"""
from __future__ import annotations

import json

from . import db, ingest, kb_explainer, query, rules

LIMIT_MAX = 50                # search_logs limit 上限(§6.1 定型)
READ_WINDOW_MAX = 500         # read_window 行数上限(§6.1 定型)
TIME_SLICE_SIDE_MAX = 500     # time_slice 单侧 ±N 上限
_RESULT_CAP_CHARS = 40_000    # 单次结果回灌体量上限(字符),超了截尾 items


class ToolError(Exception):
    """工具参数/作用域不合法;消息喂回 AI 自纠(不炸循环)。"""


def _fn(name: str, description: str, properties: dict,
        required: list[str] | None = None) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": required or []}}}


TOOLS: list[dict] = [
    _fn("search_logs",
        "日志检索(单一检索层):q 全文(raw LIKE,grep 语义)+ 源过滤 + 时间窗"
        "(ts_utc ISO)。返回命中事件(含 source_id/line_no/raw/sha256 锚点)。", {
            "case_id": {"type": "string", "description": "案件 id(必填)"},
            "q": {"type": "string", "description": "全文关键字(可空=全量分页)"},
            "source_id": {"type": "string", "description": "限定日志源"},
            "ts_from": {"type": "string", "description": "时间下限 ISO 8601"},
            "ts_to": {"type": "string", "description": "时间上限 ISO 8601"},
            "limit": {"type": "integer",
                      "description": "返回条数,默认 20,上限 50"},
        }, ["case_id"]),
    _fn("field_stats",
        "字段统计(L1 统计同源):按源行数/时间范围/Top src_ip/状态码分布。", {
            "case_id": {"type": "string", "description": "案件 id(必填)"},
            "source_id": {"type": "string", "description": "限定日志源(可空=全案件)"},
        }, ["case_id"]),
    _fn("entity_lookup",
        "实体反查:按值(canonical_key 或 raw_value 精确)查实体出现记录,"
        "每条带 源+行号+时间 锚点。cross_source=true 跨源聚合只放行 "
        "qualifier=global 实体(公网 IP;防张冠李戴闸,私网/账户永不跨源)。", {
            "case_id": {"type": "string", "description": "案件 id(必填)"},
            "value": {"type": "string", "description": "实体值(IP/域名/账户)"},
            "cross_source": {"type": "boolean",
                             "description": "true=跨源聚合(仅 global 实体)"},
        }, ["case_id", "value"]),
    _fn("time_slice",
        "锚点 ±N 行取窗口(L2 播种原语):给定源与锚点行号,取前后各 N 行"
        "(默认 100,单侧上限 500),带行号原文,锚点不丢。", {
            "case_id": {"type": "string", "description": "案件 id(必填)"},
            "source_id": {"type": "string", "description": "日志源 id(必填)"},
            "line_no": {"type": "integer", "description": "锚点行号(必填)"},
            "before": {"type": "integer", "description": "锚点前 N 行,默认 100"},
            "after": {"type": "integer", "description": "锚点后 N 行,默认 100"},
        }, ["case_id", "source_id", "line_no"]),
    _fn("read_window",
        "带行号读原文段(L3 精读):按行号区间读取,单次上限 500 行。"
        "case_id 给定时校验源属于该案件(防跨案串味)。", {
            "source_id": {"type": "string", "description": "日志源 id(必填)"},
            "line_from": {"type": "integer", "description": "起始行号(必填)"},
            "line_to": {"type": "integer", "description": "结束行号(必填)"},
            "case_id": {"type": "string",
                        "description": "案件 id(给定时做作用域校验)"},
        }, ["source_id", "line_from", "line_to"]),
    # ---------------- M5 模块状态五件(全部只读) ----------------
    _fn("list_sources",
        "案件日志源清单:每个源的 登记信息/格式/解析状态/行数/时间范围/"
        "最近解析报告(含坏行数;无则 null 如实)。", {
            "case_id": {"type": "string", "description": "案件 id(必填)"},
        }, ["case_id"]),
    _fn("list_hits",
        "待审区命中清单(规则扫描/统计聚合/L3 AI 精读 ai-l3-finding 的产物"
        "全在这里):按状态过滤,每条带 规则/severity/源/行号/摘要 锚点。"
        "命中一律未入库,人审 accept 才成线索。", {
            "case_id": {"type": "string", "description": "案件 id(必填)"},
            "status": {"type": "string",
                       "description": "pending|accepted|rejected,默认 pending"},
            "limit": {"type": "integer",
                      "description": "返回条数,默认 20,上限 50"},
        }, ["case_id"]),
    _fn("list_clues",
        "已入库线索清单(人审 accept 的产物,唯一来源):标题/正文/锚点三件套"
        "(源+行号+sha256)。", {
            "case_id": {"type": "string", "description": "案件 id(必填)"},
        }, ["case_id"]),
    _fn("get_analysis_runs",
        "L3 分析 run 摘要(新→旧):状态/档位/token 用量/预算/锚点与窗口数/"
        "报告要点(note + 综合故事截断)。交流区自身的 chat run 不在其中。", {
            "case_id": {"type": "string", "description": "案件 id(必填)"},
            "limit": {"type": "integer",
                      "description": "返回条数,默认 5,上限 20"},
        }, ["case_id"]),
    _fn("kb_explain",
        "KB 确定性解释器:kind=path|ua|status,value 为待解释值。"
        "命中 covered:true + text;未覆盖 covered:false(不硬解释,宁缺勿滥)。", {
            "kind": {"type": "string", "description": "path|ua|status(必填)"},
            "value": {"type": "string", "description": "待解释的值(必填)"},
        }, ["kind", "value"]),
]

_TOOL_NAMES = {t["function"]["name"] for t in TOOLS}
# 各工具允许的参数键(未知键拒绝,错误喂回 AI 自纠;防 AI 臆造参数被静默忽略)
_TOOL_PARAMS: dict[str, set[str]] = {
    t["function"]["name"]: set(t["function"]["parameters"]["properties"])
    for t in TOOLS
}


# ==================== 公共小件 ====================

def _require_str(p: dict, key: str) -> str:
    v = p.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ToolError(f"{key} 必填且为非空字符串")
    return v.strip()


def _opt_int(p: dict, key: str, default: int, lo: int, hi: int) -> int:
    """整数参数:缺省给 default,超界收敛到 [lo,hi](不报错,如实收敛)。"""
    v = p.get(key)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        raise ToolError(f"{key} 须为整数")
    return max(lo, min(v, hi))


def _check_source_in_case(case_id: str, source_id: str) -> None:
    """源必须属于案件(防跨案串味;query.read_window 无案件闸,这里补)。"""
    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM log_sources WHERE id = ? AND case_id = ?",
            (source_id, case_id)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ToolError(
            f"日志源 {source_id} 不存在或不属于案件 {case_id}(防串味闸)")


def _cap(out: dict, items_key: str = "items") -> dict:
    """体量截尾:超 _RESULT_CAP_CHARS 逐条砍 items 并如实标 truncated。"""
    text = json.dumps(out, ensure_ascii=False, default=str)
    items = out.get(items_key)
    while len(text) > _RESULT_CAP_CHARS and isinstance(items, list) \
            and len(items) > 1:
        items.pop()                              # 截尾不丢 total,锚点可回查
        out["truncated"] = True
        text = json.dumps(out, ensure_ascii=False, default=str)
    return out


# ==================== 五件套实现(全部只读,全经 query 检索层) ====================

def _t_search_logs(p: dict) -> dict:
    case_id = _require_str(p, "case_id")
    limit = _opt_int(p, "limit", 20, 1, LIMIT_MAX)
    try:
        res = query.search(case_id, q=p.get("q"), source_id=p.get("source_id"),
                           ts_from=p.get("ts_from"), ts_to=p.get("ts_to"),
                           limit=limit)
    except ValueError as e:
        raise ToolError(f"时间参数非法: {e}") from None
    return _cap({"ok": True, "tool": "search_logs", "total": res["total"],
                 "items": res["items"],
                 "filters_used": {k: v for k, v in p.items()
                                  if v is not None}})


def _t_field_stats(p: dict) -> dict:
    case_id = _require_str(p, "case_id")
    res = query.stats(case_id, source_id=p.get("source_id"))
    return {"ok": True, "tool": "field_stats", "total": len(res["by_source"]),
            "sources": res["sources"], "by_source": res["by_source"],
            "filters_used": {k: v for k, v in p.items() if v is not None}}


def _t_entity_lookup(p: dict) -> dict:
    case_id = _require_str(p, "case_id")
    value = _require_str(p, "value")
    cross = bool(p.get("cross_source"))
    res = query.entity_lookup(case_id, value, cross_source=cross)
    return _cap({"ok": True, "tool": "entity_lookup",
                 "total": len(res["items"]), "items": res["items"],
                 "cross_source": cross,
                 "note": res.get("note"),
                 "filters_used": {"value": value, "cross_source": cross}})


def _t_time_slice(p: dict) -> dict:
    case_id = _require_str(p, "case_id")
    source_id = _require_str(p, "source_id")
    line_no = p.get("line_no")
    if isinstance(line_no, bool) or not isinstance(line_no, int) or line_no < 1:
        raise ToolError("line_no 须为 ≥1 的整数")
    before = _opt_int(p, "before", 100, 0, TIME_SLICE_SIDE_MAX)
    after = _opt_int(p, "after", 100, 0, TIME_SLICE_SIDE_MAX)
    _check_source_in_case(case_id, source_id)
    win = query.read_window(source_id, max(1, line_no - before),
                            line_no + after)
    return _cap({"ok": True, "tool": "time_slice", "source_id": source_id,
                 "anchor_line_no": line_no, "before": before, "after": after,
                 "total": len(win["lines"]), "lines": win["lines"],
                 "filters_used": {"source_id": source_id, "line_no": line_no}},
                items_key="lines")


def _t_read_window(p: dict) -> dict:
    source_id = _require_str(p, "source_id")
    line_from, line_to = p.get("line_from"), p.get("line_to")
    for name, v in (("line_from", line_from), ("line_to", line_to)):
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ToolError(f"{name} 须为 ≥1 的整数")
    if line_to < line_from:
        raise ToolError("line_to 须 ≥ line_from")
    if line_to - line_from + 1 > READ_WINDOW_MAX:
        raise ToolError(
            f"单次窗口上限 {READ_WINDOW_MAX} 行"
            f"(请求 {line_to - line_from + 1} 行),请缩小区间")
    if p.get("case_id"):
        _check_source_in_case(p["case_id"], source_id)
    win = query.read_window(source_id, line_from, line_to)
    return _cap({"ok": True, "tool": "read_window", "source_id": source_id,
                 "line_from": line_from, "line_to": line_to,
                 "total": len(win["lines"]), "lines": win["lines"],
                 "filters_used": {"source_id": source_id}},
                items_key="lines")


# ==================== 模块状态五件(M5,全部只读) ====================

def _cut(text: object, n: int) -> str | None:
    """长文本截断(报告要点回灌用);None 透传。"""
    if text is None:
        return None
    s = str(text)
    return s if len(s) <= n else s[:n] + "…"


def _t_list_sources(p: dict) -> dict:
    case_id = _require_str(p, "case_id")
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id, name, system, log_type, format_id, tz_declared,"
            " time_range, source_note, sha256, line_count, status, error,"
            " created_at FROM log_sources WHERE case_id = ?"
            " ORDER BY created_at", (case_id,)).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            # 最近一次解析报告(随审计留痕;未解析过 → None 如实)
            d["parse_report"] = ingest.latest_parse_report(conn, d["id"])
            items.append(d)
    finally:
        conn.close()
    return _cap({"ok": True, "tool": "list_sources", "total": len(items),
                 "sources": items}, items_key="sources")


_HIT_STATUSES = {"pending", "accepted", "rejected"}


def _t_list_hits(p: dict) -> dict:
    case_id = _require_str(p, "case_id")
    status = p.get("status")
    if status is None:
        status = "pending"
    if not isinstance(status, str) or status not in _HIT_STATUSES:
        raise ToolError(f"status 须为 {sorted(_HIT_STATUSES)} 之一")
    limit = _opt_int(p, "limit", 20, 1, LIMIT_MAX)
    conn = db.connect()
    try:
        res = rules.list_hits(conn, case_id, status=status, limit=limit)
    finally:
        conn.close()
    return _cap({"ok": True, "tool": "list_hits", "status": status,
                 "total": res["total"], "items": res["items"],
                 "filters_used": {"status": status}})


def _t_list_clues(p: dict) -> dict:
    case_id = _require_str(p, "case_id")
    conn = db.connect()
    try:
        res = rules.list_clues(conn, case_id)
    finally:
        conn.close()
    return _cap({"ok": True, "tool": "list_clues", "total": res["total"],
                 "items": res["items"]})


def _t_get_analysis_runs(p: dict) -> dict:
    case_id = _require_str(p, "case_id")
    limit = _opt_int(p, "limit", 5, 1, 20)
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id, source_id, status, profile, budget, usage_json,"
            " anchors_json, error, created_at, finished_at FROM analysis_runs"
            " WHERE case_id = ? AND source_id IS NOT NULL"
            " ORDER BY created_at DESC LIMIT ?", (case_id, limit)).fetchall()
    finally:
        conn.close()
    items = []
    for r in rows:
        d = dict(r)
        d["usage"] = json.loads(d.pop("usage_json")) if d["usage_json"] else None
        report = json.loads(d.pop("anchors_json")) if d["anchors_json"] else None
        # 报告要点,不全量回灌:锚点/窗口计数 + note + 综合故事截断
        d["report"] = None if report is None else {
            "anchors": len(report.get("anchors") or []),
            "windows": len(report.get("windows") or []),
            "note": report.get("note"),
            "synthesis": _cut(report.get("synthesis"), 500),
            "budget_exceeded": bool(report.get("budget_exceeded")),
        }
        items.append(d)
    return _cap({"ok": True, "tool": "get_analysis_runs",
                 "total": len(items), "items": items})


def _t_kb_explain(p: dict) -> dict:
    kind = _require_str(p, "kind")
    value = _require_str(p, "value")
    try:
        res = kb_explainer.explain(kind, value)
    except kb_explainer.KBError as e:
        raise ToolError(str(e)) from None
    return {"ok": True, "tool": "kb_explain", **res}


_IMPL = {
    "search_logs": _t_search_logs,
    "field_stats": _t_field_stats,
    "entity_lookup": _t_entity_lookup,
    "time_slice": _t_time_slice,
    "read_window": _t_read_window,
    "list_sources": _t_list_sources,
    "list_hits": _t_list_hits,
    "list_clues": _t_list_clues,
    "get_analysis_runs": _t_get_analysis_runs,
    "kb_explain": _t_kb_explain,
}


def run_tool(name: str, params: dict | None) -> dict:
    """工具分发入口:白名单 → 参数校验 → 执行 → 统一结果形状。

    返回必有 ok 字段;任何参数/执行问题都落成 {ok:false,error} 喂回 AI,
    绝不向上抛(循环熔断在 ai.run_agent)。全部工具只读。
    """
    if name not in _TOOL_NAMES:
        return {"ok": False, "tool": name,
                "error": f"未知工具: {name!r}(可用: {sorted(_TOOL_NAMES)})"}
    if params is None:
        return {"ok": False, "tool": name,
                "error": "arguments 不是合法 JSON 对象,请修正后重试"}
    if not isinstance(params, dict):
        return {"ok": False, "tool": name,
                "error": "arguments 须为 JSON 对象"}
    unknown = set(params) - _TOOL_PARAMS[name]
    if unknown:
        return {"ok": False, "tool": name,
                "error": f"未知参数 {sorted(unknown)},本工具只允许:"
                         f" {sorted(_TOOL_PARAMS[name])}"}
    try:
        return _IMPL[name](params)
    except ToolError as e:
        return {"ok": False, "tool": name, "error": str(e)}
    except Exception as e:                         # 零静默:未知错误也如实喂回
        return {"ok": False, "tool": name,
                "error": f"工具内部错误({type(e).__name__}): {e}"}
