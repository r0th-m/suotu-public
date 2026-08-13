"""索图 MCP 服务端(2026-08-13,FUTURE 立项:Streamable HTTP + 八道镣铐)。

形态:MCPServer(mcp 2.0 SDK)挂到主 FastAPI /mcp 前缀;**只读**工具面,
全部是 query.py 单一检索层的薄封装,零新分析逻辑。

八道镣铐落点:
①只读无写口(工具清单即证明);②产出恒候选,线索入库仍在 Web 端人点;
③每个工具调用进审计链(actor=token 属主,action=mcp_call);
④token 限频(滑窗)+ 结果行数硬顶;⑤个人 API token 签发/吊销 +
端点默认关闭(settings.mcp_enabled);⑥每条响应尾部带「原文去 Web 端
核对」指引;⑦initialize instructions 写死裁决在 Web 端由人完成;
⑧README 安全声明划清客户端外发责任(文档侧)。
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone

from . import db, duck, query, rules, viewer

# ---------------------------------------------------------------- 常量与文案

_SERVER_INSTRUCTIONS = (
    "你是索图(SuoTu)日志分析工作台的只读查询接口。纪律:\n"
    "1) 你拿到的一切都是候选证据,不是结论;\n"
    "2) 具体日志条目原文,请引导用户到 Web 端「查看」tab 按 日志源+行号 核对;\n"
    "3) 最终裁决与研判必须由人在 Web 端完成——不要替用户下最终定性;\n"
    "4) 引用数据必须带锚点(日志源名 + 行号);\n"
    "5) 本接口只读:不能上传、不能解析、不能改裁决、不能跑扫描。"
)

_RESPONSE_NOTICE = (
    "\n\n——索图 MCP:以上为候选数据,具体日志原文请到 Web 端「查看」tab "
    "按锚点(日志源+行号)核对;最终裁决与研判须在 Web 端由人完成。"
)

_SEARCH_LIMIT_MAX = 200        # 检索结果行数硬顶(镣铐④)
_VIEW_LINES_MAX = 200          # 查看器行数硬顶
_HITS_LIMIT_MAX = 200
_RATE_PER_MINUTE = 30          # 每 token 每分钟调用上限(滑窗)

_TOKEN_PREFIX = "st_mcp_"


# ---------------------------------------------------------------- token 与开关

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def mcp_enabled(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT value FROM settings WHERE key = 'mcp_enabled'"
                       ).fetchone()
    return bool(row and row["value"] == "1")


def set_mcp_enabled(conn: sqlite3.Connection, enabled: bool, actor: str) -> dict:
    now = _now()
    with conn:
        conn.execute(
            "INSERT INTO settings (key, value, updated_at, actor)"
            " VALUES ('mcp_enabled', ?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=?, updated_at=?, actor=?",
            ("1" if enabled else "0", now, actor,
             "1" if enabled else "0", now, actor))
        db.append_audit(conn, "system", action="mcp_toggle", scope="mcp",
                        actor=actor, detail={"enabled": enabled})
    return {"enabled": enabled, "updated_at": now, "actor": actor}


def create_token(conn: sqlite3.Connection, username: str,
                 label: str | None) -> dict:
    """签发 token:明文只在此返回一次,库里只有哈希。"""
    token = _TOKEN_PREFIX + secrets.token_urlsafe(24)
    tid = secrets.token_hex(8)
    with conn:
        conn.execute(
            "INSERT INTO api_tokens (id, username, label, token_hash,"
            " created_at) VALUES (?,?,?,?,?)",
            (tid, username, label, _hash_token(token), _now()))
        db.append_audit(conn, "system", action="mcp_token_create",
                        scope="mcp", actor=username,
                        detail={"token_id": tid, "label": label})
    return {"id": tid, "token": token, "label": label,
            "note": "明文仅此一次,请立即复制保存"}


def list_tokens(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT id, username, label, created_at, last_used_at, revoked_at"
        " FROM api_tokens ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def revoke_token(conn: sqlite3.Connection, token_id: str, actor: str) -> bool:
    with conn:
        cur = conn.execute(
            "UPDATE api_tokens SET revoked_at = ? WHERE id = ?"
            " AND revoked_at IS NULL", (_now(), token_id))
        if cur.rowcount:
            db.append_audit(conn, "system", action="mcp_token_revoke",
                            scope="mcp", actor=actor,
                            detail={"token_id": token_id})
    return cur.rowcount > 0


def _resolve_token(conn: sqlite3.Connection, token: str) -> str | None:
    """token → 属主用户名;无效/已吊销 → None。"""
    row = conn.execute(
        "SELECT username FROM api_tokens WHERE token_hash = ?"
        " AND revoked_at IS NULL", (_hash_token(token),)).fetchone()
    if row is None:
        return None
    with conn:
        conn.execute("UPDATE api_tokens SET last_used_at = ?"
                     " WHERE token_hash = ?", (_now(), _hash_token(token)))
    return row["username"]


# ---------------------------------------------------------------- 限频(镣铐④)

_RATE_LOCK = threading.Lock()
_RATE: dict[str, list[float]] = {}


def _rate_ok(username: str) -> bool:
    """每用户每分钟 _RATE_PER_MINUTE 次滑窗;超限 False。"""
    now = time.monotonic()
    with _RATE_LOCK:
        hits = _RATE.setdefault(username, [])
        hits[:] = [t for t in hits if now - t < 60.0]
        if len(hits) >= _RATE_PER_MINUTE:
            return False
        hits.append(now)
        return True


def _reset_rate() -> None:
    """测试用:清空限频窗口。"""
    with _RATE_LOCK:
        _RATE.clear()


# ---------------------------------------------------------------- 工具实现

def _audit_call(username: str, tool: str, params: dict, result_rows: int) -> None:
    """镣铐③:每次调用进审计链(参数截断留 digest,不留全文)。"""
    digest = json.dumps(params, ensure_ascii=False, sort_keys=True,
                        default=str)[:300]
    conn = db.connect()
    try:
        with conn:
            db.append_audit(conn, "system", action="mcp_call", scope="mcp",
                            actor=username,
                            detail={"tool": tool, "params": digest,
                                    "rows": result_rows})
    finally:
        conn.close()


def _clamp_limit(limit: int | None, cap: int) -> int:
    if limit is None:
        return min(50, cap)
    return max(1, min(int(limit), cap))


def _tool_case_overview(_params: dict) -> dict:
    conn = db.connect()
    try:
        cases = [dict(r) for r in conn.execute(
            "SELECT c.id, c.name, c.created_at,"
            " (SELECT COUNT(*) FROM log_sources s WHERE s.case_id = c.id)"
            " AS source_count FROM cases c ORDER BY c.created_at DESC")]
        return {"cases": cases}
    finally:
        conn.close()


def _tool_list_sources(p: dict) -> dict:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id, name, system, log_type, format_id, status, line_count,"
            " time_range, evidence_kind FROM log_sources WHERE case_id = ?"
            " ORDER BY created_at", (p["case_id"],)).fetchall()
        return {"sources": [dict(r) for r in rows]}
    finally:
        conn.close()


def _tool_search_events(p: dict) -> dict:
    filters = p.get("field_filters")
    if isinstance(filters, str):
        filters = json.loads(filters)
    return query.search(
        p["case_id"], q=p.get("q"), source_id=p.get("source_id"),
        field_filters=filters, ts_from=p.get("ts_from"), ts_to=p.get("ts_to"),
        limit=_clamp_limit(p.get("limit"), _SEARCH_LIMIT_MAX))


def _tool_entity_lookup(p: dict) -> dict:
    return query.entity_lookup(p["case_id"], p["value"],
                               cross_source=bool(p.get("cross_source")))


def _tool_list_hits(p: dict) -> dict:
    conn = db.connect()
    try:
        return rules.list_hits(
            conn, p["case_id"], status=p.get("status"),
            limit=_clamp_limit(p.get("limit"), _HITS_LIMIT_MAX))
    finally:
        conn.close()


def _tool_get_stats(p: dict) -> dict:
    return query.stats(p["case_id"], source_id=p.get("source_id"))


def _tool_view_lines(p: dict) -> dict:
    conn = db.connect()
    try:
        return viewer.read_lines(
            conn, p["source_id"], offset=max(0, int(p.get("offset", 0))),
            limit=_clamp_limit(p.get("limit"), _VIEW_LINES_MAX))
    finally:
        conn.close()


_TOOLS = {
    "case_overview": _tool_case_overview,
    "list_sources": _tool_list_sources,
    "search_events": _tool_search_events,
    "entity_lookup": _tool_entity_lookup,
    "list_hits": _tool_list_hits,
    "get_stats": _tool_get_stats,
    "view_lines": _tool_view_lines,
}

_TOOL_DESCS = {
    "case_overview": "案件总览:案件清单及各案日志源数量。",
    "list_sources": "案件日志源清单(名称/格式/状态/行数/时间范围/补充证据标记)。",
    "search_events": "检索事件:全文词 q + field_filters(JSON 对象,如 "
                     "{\"src_ip\":\"1.2.3.4\"}) + ts_from/ts_to 时间窗;"
                     "limit 上限 200。",
    "entity_lookup": "实体反查:IP/账户等在某案件(或跨源)的出现位置。",
    "list_hits": "规则/算子命中清单(候选待审区;可按 status 过滤)。",
    "get_stats": "案件统计(事件量/类型分布等聚合面)。",
    "view_lines": "查看日志原文行(带行号;offset/limit,limit 上限 200)。",
}


# ---------------------------------------------------------------- 服务装配

def build_mcp_app():
    """装配 MCPServer(只读工具面)并返回 (可挂载 Starlette app, session_manager)。

    每个工具:限频(镣铐④)→ 执行 → 审计(镣铐③)→ 尾部指引(镣铐⑥)。
    属主用户名由 ASGI 网关层经 contextvars 传入(mcp_context)。
    工具签名全部显式声明(SDK 按签名生成 inputSchema,**kwargs 会破坏协议面)。
    """
    from mcp.server.mcpserver import MCPServer
    from mcp.server.transport_security import TransportSecuritySettings

    srv = MCPServer(name="suotu", instructions=_SERVER_INSTRUCTIONS,
                    version="1.0.0")

    def _run_tool(tool_name: str, func, params: dict) -> str:
        from . import mcp_context
        user = mcp_context.current_user()
        if not _rate_ok(user):
            return (f"调用过频:每分钟上限 {_RATE_PER_MINUTE} 次,稍后再试"
                    + _RESPONSE_NOTICE)
        params = {k: v for k, v in params.items() if v is not None}
        try:
            result = func(params)
        except Exception as e:
            return f"查询失败:{type(e).__name__}: {e}"[:500] + _RESPONSE_NOTICE
        rows = (len(result.get("items", [])) if isinstance(result, dict) else 0)
        _audit_call(user, tool_name, params, rows)
        return json.dumps(result, ensure_ascii=False, default=str) \
            + _RESPONSE_NOTICE

    @srv.tool(name="case_overview", description=_TOOL_DESCS["case_overview"])
    def t_case_overview() -> str:
        return _run_tool("case_overview", _tool_case_overview, {})

    @srv.tool(name="list_sources", description=_TOOL_DESCS["list_sources"])
    def t_list_sources(case_id: str) -> str:
        return _run_tool("list_sources", _tool_list_sources,
                         {"case_id": case_id})

    @srv.tool(name="search_events", description=_TOOL_DESCS["search_events"])
    def t_search_events(case_id: str, q: str | None = None,
                        source_id: str | None = None,
                        field_filters: str | None = None,
                        ts_from: str | None = None, ts_to: str | None = None,
                        limit: int | None = None) -> str:
        return _run_tool("search_events", _tool_search_events,
                         {"case_id": case_id, "q": q, "source_id": source_id,
                          "field_filters": field_filters,
                          "ts_from": ts_from, "ts_to": ts_to, "limit": limit})

    @srv.tool(name="entity_lookup", description=_TOOL_DESCS["entity_lookup"])
    def t_entity_lookup(case_id: str, value: str,
                        cross_source: bool = False) -> str:
        return _run_tool("entity_lookup", _tool_entity_lookup,
                         {"case_id": case_id, "value": value,
                          "cross_source": cross_source})

    @srv.tool(name="list_hits", description=_TOOL_DESCS["list_hits"])
    def t_list_hits(case_id: str, status: str | None = None,
                    limit: int | None = None) -> str:
        return _run_tool("list_hits", _tool_list_hits,
                         {"case_id": case_id, "status": status,
                          "limit": limit})

    @srv.tool(name="get_stats", description=_TOOL_DESCS["get_stats"])
    def t_get_stats(case_id: str, source_id: str | None = None) -> str:
        return _run_tool("get_stats", _tool_get_stats,
                         {"case_id": case_id, "source_id": source_id})

    @srv.tool(name="view_lines", description=_TOOL_DESCS["view_lines"])
    def t_view_lines(source_id: str, offset: int = 0,
                     limit: int | None = None) -> str:
        return _run_tool("view_lines", _tool_view_lines,
                         {"source_id": source_id, "offset": offset,
                          "limit": limit})

    return (srv.streamable_http_app(
                streamable_http_path="/mcp",
                json_response=True,
                stateless_http=True,
                # 内网/本机部署:Host 校验交给部署方(我们已有 token 闸),
                # SDK 的 DNS 重绑定防护默认只放 localhost,会误杀内网 IP
                transport_security=TransportSecuritySettings(
                    enable_dns_rebinding_protection=False)),
            srv.session_manager)


class MCPGateway:
    """/mcp 前缀的 ASGI 包装:开关 → Bearer token → 记属主 → 转发子 app。"""

    def __init__(self, sub_app):
        self._sub = sub_app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._sub(scope, receive, send)
            return
        conn = db.connect()
        try:
            if not mcp_enabled(conn):
                await self._plain(send, 403,
                                  "MCP 端点未启用(设置中开启并签发 token)")
                return
            authz = ""
            for k, v in scope.get("headers", []):
                if k.lower() == b"authorization":
                    authz = v.decode(errors="replace")
            token = authz[7:] if authz.lower().startswith("bearer ") else ""
            user = _resolve_token(conn, token) if token else None
            if user is None:
                await self._plain(send, 401, "未认证或 token 已吊销")
                return
        finally:
            conn.close()
        from . import mcp_context
        token_cm = mcp_context.bind_user(user)
        try:
            await self._sub(scope, receive, send)
        finally:
            mcp_context.unbind(token_cm)

    @staticmethod
    async def _plain(send, status: int, message: str) -> None:
        body = json.dumps({"detail": message}, ensure_ascii=False).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})
