"""MCP 服务端契约测试(2026-08-13;八道镣铐断言级焊死)。

覆盖:默认关闭 403 / 无 token 401 / 吊销即失效 / 工具面只读(白名单断言)/
调用留审计 / 回执带指引声明 / 限频触发 / 协议面(initialize+instructions)。
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import db, mcp_server
from backend.app.main import app

_INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"}}}
_HEADERS = {"Accept": "application/json, text/event-stream"}

# 只读工具白名单(镣铐①:写口出现即红)
_READONLY_TOOLS = {"case_overview", "list_sources", "search_events",
                   "entity_lookup", "list_hits", "get_stats", "view_lines"}


@pytest.fixture()
def mcp_on(conn, monkeypatch):
    """开端点 + 签发 token;返回 (TestClient, 带 Bearer 的 headers)。"""
    mcp_server.set_mcp_enabled(conn, True, "tester")
    tok = mcp_server.create_token(conn, "tester", "pytest")
    monkeypatch.setattr(mcp_server, "_RATE_PER_MINUTE", 1000)  # 默认放开限频
    mcp_server._reset_rate()
    h = dict(_HEADERS)
    h["Authorization"] = f"Bearer {tok['token']}"
    with TestClient(app) as c:
        yield c, h


def test_default_disabled_403(conn):
    with TestClient(app) as c:
        r = c.post("/mcp", json=_INIT, headers=_HEADERS)
    assert r.status_code == 403 and "未启用" in r.json()["detail"]


def test_no_token_401(mcp_on):
    c, _h = mcp_on
    assert c.post("/mcp", json=_INIT, headers=_HEADERS).status_code == 401
    assert c.post("/mcp", json=_INIT,
                  headers={**_HEADERS,
                           "Authorization": "Bearer st_mcp_wrong"}
                  ).status_code == 401


def test_revoke_immediately_401(mcp_on, conn):
    c, h = mcp_on
    assert c.post("/mcp", json=_INIT, headers=h).status_code == 200
    tok_id = conn.execute("SELECT id FROM api_tokens").fetchone()["id"]
    mcp_server.revoke_token(conn, tok_id, "tester")
    assert c.post("/mcp", json=_INIT, headers=h).status_code == 401


def test_token_plaintext_only_once(mcp_on, conn):
    """明文只在创建响应;列表接口只有元信息无 token 字段(镣铐⑤)。"""
    rows = mcp_server.list_tokens(conn)
    assert rows and "token" not in rows[0] and "token_hash" not in rows[0]


def test_initialize_instructions(mcp_on):
    c, h = mcp_on
    r = c.post("/mcp", json=_INIT, headers=h)
    assert r.status_code == 200
    text = r.text
    assert "最终裁决与研判必须由人" in text          # 镣铐⑦:裁决权声明
    assert "只读" in text


def test_tools_whitelist_readonly(mcp_on):
    c, h = mcp_on
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 2,
                             "method": "tools/list", "params": {}}, headers=h)
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert names == _READONLY_TOOLS
    # 写口关键词零容忍
    for banned in ("upload", "parse", "delete", "accept", "revoke", "config"):
        assert not any(banned in n for n in names)


def test_call_audited_and_noticed(mcp_on, conn):
    c, h = mcp_on
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                             "params": {"name": "case_overview",
                                        "arguments": {}}}, headers=h)
    assert r.status_code == 200
    body = r.json()["result"]["content"][0]["text"]
    assert "最终裁决与研判须在 Web 端由人完成" in body   # 镣铐⑥
    rows = conn.execute(
        "SELECT actor, detail_json FROM audit_log WHERE action = 'mcp_call'"
    ).fetchall()
    assert len(rows) == 1 and rows[0]["actor"] == "tester"
    assert "case_overview" in rows[0]["detail_json"]


def test_rate_limit(mcp_on, conn, monkeypatch):
    c, h = mcp_on
    monkeypatch.setattr(mcp_server, "_RATE_PER_MINUTE", 2)
    mcp_server._reset_rate()
    call = {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "case_overview", "arguments": {}}}
    c.post("/mcp", json=call, headers=h)
    c.post("/mcp", json=call, headers=h)
    r = c.post("/mcp", json=call, headers=h)              # 第三次超限
    assert "调用过频" in r.json()["result"]["content"][0]["text"]


def test_admin_endpoints_need_session():
    """管理端点走全局会话闸(与 MCP token 两套体系,互不混用)。"""
    with TestClient(app) as client:
        client.cookies.clear()
        assert client.get("/mcp-admin/status").status_code == 401
        assert client.post("/mcp-admin/tokens", json={}).status_code == 401
