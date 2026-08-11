"""M5 交流区(chat.py)+ 模块可见性契约测试(断言级;全程 mock _call_api,
.env 永不进测试)。

覆盖:
- 会话 CRUD / 消息流转(mock AI)/ 首条消息截 30 字自动命名;
- from_hit 追问注入:命中详情+锚点进 system 上下文;跨案命中 → 防串味拒绝;
- ★模块可见性契约(用户拍板,防「模块数据 AI 不可见」回归):规则扫描的
  hit、L3 的 ai-l3-finding、人 accept 的 clue、解析报告状态,每个模块的
  产物至少一条工具可达路径(经 ai_tools.run_tool 直调断言);
- offline_lite 诚实降级:如实回答「无 AI 档,可用检索/规则代替」,不臆造,
  且不建 chat run(根本没发生调用);
- 熔断在 chat 路径生效:loop_detected(第 3 次相同调用不执行)、
  budget_exceeded(token 预算);
- AI 产物断言级不入库:问答全程 clues/hits 零新增(§1 判断权归人)。
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.app import ai, ai_tools, analysis, chat, db, rules
from backend.app.main import app

from conftest import NGINX_LINES, register_confirm_parse

# 两条必中的攻击行:sqlmap UA → scanner-ua;/../../etc/passwd → path-traversal
ATTACK_TEXT = "\n".join(NGINX_LINES + [
    '1.2.3.4 - - [10/Oct/2000:13:58:00 +0300] "GET /admin HTTP/1.1"'
    ' 200 5 "-" "sqlmap/1.5.2"',
    '5.6.7.8 - - [10/Oct/2000:13:59:00 +0300]'
    ' "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.68.0"',
]) + "\n"


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


def _resp(content="回答", tool_calls=None, total=15):
    return {"content": content, "tool_calls": tool_calls, "model": "m-test",
            "usage": {"prompt_tokens": total - 5, "completion_tokens": 5,
                      "total_tokens": total}}


def _tc(name, args, call_id="c1"):
    return {"id": call_id, "name": name, "arguments": args,
            "arguments_raw": json.dumps(args or {}, ensure_ascii=False),
            "raw": {"id": call_id, "type": "function",
                    "function": {"name": name,
                                 "arguments": json.dumps(args or {})}}}


@pytest.fixture()
def attack_case(client):
    """建案 → 上传攻击样本(5 行 nginx,含 sqlmap UA 与路径穿越)→ 确认 →
    解析 → L1 规则扫描。返回 (case_id, source_id, pending_hits_items)。"""
    case_id = client.post("/cases", json={"name": "交流区测试案"}).json()["id"]
    up = client.post(f"/cases/{case_id}/sources:upload",
                     files={"file": ("access.log", ATTACK_TEXT.encode(),
                                     "text/plain")},
                     data={"system": "web-01"})
    sid = up.json()["sources"][0]["source_id"]
    assert client.post(f"/sources/{sid}/confirm",
                       json={"format_id": "nginx_combined",
                             "tz_declared": "Asia/Shanghai",
                             "log_type": "web"}).status_code == 200
    r = client.post(f"/sources/{sid}/parse")
    assert r.status_code == 200 and r.json()["parsed"] == 5
    client.post(f"/cases/{case_id}/rules:run", json={})
    hits = client.get(f"/cases/{case_id}/hits?status=pending").json()
    rule_ids = {h["rule_id"] for h in hits["items"]}
    assert {"scanner-ua", "path-traversal"} <= rule_ids     # 两条签名必中
    return case_id, sid, hits["items"]


# ---------------------------------------------------------------- 会话 CRUD

def test_session_crud(client, attack_case):
    case_id, _, _ = attack_case
    r = client.post(f"/cases/{case_id}/chat/sessions", json={})
    assert r.status_code == 201
    sid = r.json()["id"]
    assert r.json()["title"] is None                # 未命名,首条消息自动命名
    lst = client.get(f"/cases/{case_id}/chat/sessions").json()
    assert lst["items"][0]["id"] == sid
    assert lst["items"][0]["message_count"] == 0
    msgs = client.get(f"/chat/sessions/{sid}/messages").json()
    assert msgs["items"] == []
    # 显式标题 + 坏案件 + 坏会话 + 不存在的 from_hit
    r2 = client.post(f"/cases/{case_id}/chat/sessions",
                     json={"title": "排查 sqlmap"})
    assert r2.json()["title"] == "排查 sqlmap"
    assert client.post("/cases/不存在/chat/sessions", json={}).status_code == 404
    assert client.get("/chat/sessions/不存在/messages").status_code == 404
    r3 = client.post(f"/cases/{case_id}/chat/sessions",
                     json={"from_hit_id": "不存在"})
    assert r3.status_code == 404


def test_from_hit_cross_case_rejected(client, attack_case):
    case_id, _, hits = attack_case
    other = client.post("/cases", json={"name": "另一案"}).json()["id"]
    r = client.post(f"/cases/{other}/chat/sessions",
                    json={"from_hit_id": hits[0]["id"]})
    assert r3_err(r)                                # 防串味:命中不属本案


def r3_err(r):
    return r.status_code == 400 and "防串味" in r.json()["detail"]


# ---------------------------------------------------------------- 消息流转

def test_message_flow_mock_ai(client, attack_case, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    monkeypatch.setattr(ai, "_call_api", lambda *a, **k: _resp("这是回答"))
    case_id, _, _ = attack_case
    sid = client.post(f"/cases/{case_id}/chat/sessions",
                      json={}).json()["id"]
    r = client.post(f"/chat/sessions/{sid}/messages",
                    json={"content": "这个案件里有什么可疑的?"})
    assert r.status_code == 200
    body = r.json()
    assert body["answer"] == "这是回答"
    assert body["profile"] == "online" and body["label"] == "AI 推测·待核"
    assert body["stop_reason"] == ai.STOP_COMPLETED
    assert body["usage"]["total_tokens"] == 15      # usage 快照随回答落库
    assert body["tool_log"] == []
    assert "suggest_review" in body                 # 转线索只指路 hits accept
    msgs = client.get(f"/chat/sessions/{sid}/messages").json()["items"]
    assert [m["role"] for m in msgs] == ["user", "assistant"]
    assert msgs[1]["tool_log"] == [] and msgs[1]["usage"]["calls"] == 1
    # 首条消息截 30 字自动命名
    sess = client.get(f"/cases/{case_id}/chat/sessions").json()["items"][0]
    assert sess["title"] == "这个案件里有什么可疑的?"
    assert sess["message_count"] == 2
    # 空消息 400
    assert client.post(f"/chat/sessions/{sid}/messages",
                       json={"content": "  "}).status_code == 400


def test_tool_call_roundtrip_via_chat(client, attack_case, ai_env,
                                      monkeypatch):
    """AI 调 list_hits → 工具结果回灌 → 最终回答;tool_log 如实留痕。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, _, _ = attack_case
    seen_payloads = []

    def fake(messages, **k):
        seen_payloads.append(messages)
        if len(seen_payloads) == 1:
            return _resp(None, tool_calls=[
                _tc("list_hits", {"case_id": case_id, "status": "pending"})])
        return _resp("待审区有 sqlmap 扫描命中")

    monkeypatch.setattr(ai, "_call_api", fake)
    sid = client.post(f"/cases/{case_id}/chat/sessions", json={}).json()["id"]
    r = client.post(f"/chat/sessions/{sid}/messages",
                    json={"content": "待审区里有什么?"})
    body = r.json()
    assert body["answer"] == "待审区有 sqlmap 扫描命中"
    assert body["tool_log"][0]["tool"] == "list_hits"
    assert body["tool_log"][0]["result_count"] >= 1
    # 工具结果确实回灌给了 AI(第二轮 messages 里 role=tool)
    second = seen_payloads[1]
    tool_msgs = [m for m in second if m["role"] == "tool"]
    assert tool_msgs and "scanner-ua" in tool_msgs[0]["content"]


def test_from_hit_injected_into_system(client, attack_case, ai_env,
                                       monkeypatch):
    """追问模式:命中详情+锚点注入 system 上下文(主机取证平台 from_analysis 同款)。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, _, hits = attack_case
    captured = []

    def fake(messages, **k):
        captured.append(messages)
        return _resp("追问回答")

    monkeypatch.setattr(ai, "_call_api", fake)
    hit_id = next(h["id"] for h in hits if h["rule_id"] == "scanner-ua")
    sid = client.post(f"/cases/{case_id}/chat/sessions",
                      json={"from_hit_id": hit_id}).json()["id"]
    client.post(f"/chat/sessions/{sid}/messages",
                json={"content": "这条命中展开看看"})
    system = captured[0][0]["content"]
    assert "追问锚点" in system
    assert hit_id in system and "scanner-ua" in system
    assert "sqlmap" in system                      # 命中原文摘要进了上下文
    # 案件概况与待审摘要同样在(无词典门,确定性摘要)
    assert "案件概况" in system and "待审命中" in system
    assert "access.log" in system and "行数=5" in system


# ---------------------------------------------------------------- ★模块可见性契约

def test_module_visibility_contract(client, conn, attack_case, ai_env):
    """契约(断言级):每个模块的产物至少一条工具可达路径。

    规则扫描 hit / L3 ai-l3-finding / 人 accept 的 clue / 解析报告状态 /
    分析 run / KB 解释——全部经 ai_tools.run_tool 直调断言,防「快分析
    产出的数据交流区 AI 读不到」回归(主机取证平台词典门教训)。
    """
    case_id, sid, hits = attack_case

    # L3 产物:真实写入路径(analysis._insert_finding_hit,恒 pending)
    assert analysis._insert_finding_hit(
        conn, case_id, sid, 1, "medium", "契约测试 AI finding",
        {"kind": "ai_finding", "run_id": "run-x", "line_refs": [1]})

    # L3 分析 run:真实发起(offline_lite → 确定性播种,如实标注)
    out = analysis.start_analysis(conn, case_id, sid, background=False)
    run = analysis.get_run(out["run_id"])
    assert run["status"] == "done" and "无 AI" in run["note"]

    # 人 accept:clues 唯一写入路径(accept scanner-ua 那条)
    accept_id = next(h["id"] for h in hits if h["rule_id"] == "scanner-ua")
    client.post(f"/hits/{accept_id}:accept", json={})

    # ① 解析报告状态 + 源清单(list_sources)
    res = ai_tools.run_tool("list_sources", {"case_id": case_id})
    assert res["ok"] and res["total"] == 1
    src = res["sources"][0]
    assert src["status"] == "parsed" and src["line_count"] == 5
    assert src["format_id"] == "nginx_combined"
    assert src["parse_report"]["status"] == "parsed"
    assert src["parse_report"]["events"] == 5

    # ② 规则扫描 hit + ③ L3 ai-l3-finding(list_hits 同一待审区)
    res = ai_tools.run_tool("list_hits", {"case_id": case_id})
    rule_ids = {h["rule_id"] for h in res["items"]}
    assert "path-traversal" in rule_ids             # 规则扫描产物可达
    assert "ai-l3-finding" in rule_ids              # L3 产物可达
    res = ai_tools.run_tool("list_hits",
                            {"case_id": case_id, "status": "accepted"})
    assert res["total"] == 1                        # 已裁决态同样可查
    assert res["items"][0]["rule_id"] == "scanner-ua"
    res = ai_tools.run_tool("list_hits",
                            {"case_id": case_id, "status": "bogus"})
    assert res["ok"] is False                       # 坏状态如实拒绝

    # ④ 人 accept 的 clue(list_clues)
    res = ai_tools.run_tool("list_clues", {"case_id": case_id})
    assert res["ok"] and res["total"] == 1
    clue = res["items"][0]
    assert clue["anchor_source_id"] == sid and clue["anchor_line_no"] >= 1
    assert clue["anchor_sha256"]                    # 锚点三件套齐全

    # ⑤ L3 分析 run 摘要(get_analysis_runs)
    res = ai_tools.run_tool("get_analysis_runs", {"case_id": case_id})
    assert res["ok"] and res["total"] == 1
    item = res["items"][0]
    assert item["status"] == "done" and item["report"]["anchors"] >= 1
    assert "无 AI" in item["report"]["note"]

    # ⑥ KB 解释器(kb_explain):命中与未覆盖两态
    res = ai_tools.run_tool("kb_explain", {"kind": "status", "value": "404"})
    assert res["ok"] and res["covered"] is True and res["text"]
    res = ai_tools.run_tool("kb_explain",
                            {"kind": "path", "value": "/zzz-no-such"})
    assert res["ok"] and res["covered"] is False    # 未覆盖不硬解释
    res = ai_tools.run_tool("kb_explain", {"kind": "bogus", "value": "x"})
    assert res["ok"] is False                       # 坏 kind 如实拒绝


def test_module_tools_readonly_no_audit(conn, case_id, ai_env):
    """模块状态五件全跑一遍:审计零新增(只读,无写路径)。"""
    from conftest import make_source_row
    sid = make_source_row(conn, case_id)
    before = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
    for name, params in [
            ("list_sources", {"case_id": case_id}),
            ("list_hits", {"case_id": case_id}),
            ("list_clues", {"case_id": case_id}),
            ("get_analysis_runs", {"case_id": case_id}),
            ("kb_explain", {"kind": "status", "value": "200"})]:
        res = ai_tools.run_tool(name, params)
        assert res["ok"], f"{name}: {res}"
    after = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
    assert after == before


# ---------------------------------------------------------------- offline_lite 诚实降级

def test_offline_lite_honest_degradation(client, attack_case, ai_env):
    case_id, _, _ = attack_case                     # ai_env:无 key
    sid = client.post(f"/cases/{case_id}/chat/sessions",
                      json={}).json()["id"]
    r = client.post(f"/chat/sessions/{sid}/messages",
                    json={"content": "分析一下"})
    body = r.json()
    assert body["profile"] == "offline_lite"
    assert "无 AI" in body["answer"] and "检索" in body["answer"]
    assert body["usage"] is None and body["tool_log"] == []
    msgs = client.get(f"/chat/sessions/{sid}/messages").json()["items"]
    assert [m["role"] for m in msgs] == ["user", "assistant"]   # 问答照留痕
    # 根本没发生调用:不建 chat run、不写 ai_call 审计
    conn = db.connect()
    try:
        n = conn.execute(
            "SELECT COUNT(*) AS c FROM analysis_runs"
            " WHERE source_id IS NULL").fetchone()["c"]
        assert n == 0
    finally:
        conn.close()


# ---------------------------------------------------------------- 熔断在 chat 路径生效

def test_fuse_loop_detected(client, attack_case, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, _, _ = attack_case
    calls = {"n": 0}

    def fake(messages, **k):                        # 永远重复同一调用 → 循环
        calls["n"] += 1
        return _resp(None, tool_calls=[
            _tc("search_logs", {"case_id": case_id, "q": "sqlmap"})])

    monkeypatch.setattr(ai, "_call_api", fake)
    sid = client.post(f"/cases/{case_id}/chat/sessions", json={}).json()["id"]
    r = client.post(f"/chat/sessions/{sid}/messages",
                    json={"content": "查 sqlmap"})
    body = r.json()
    assert body["stop_reason"] == ai.STOP_LOOP
    assert "熔断停机" in body["answer"] and "循环" in body["answer"]
    assert len(body["tool_log"]) == 2               # 第 3 次相同调用不执行
    # 回答仍落库(留痕),run 收尾 done
    msgs = client.get(f"/chat/sessions/{sid}/messages").json()["items"]
    assert msgs[1]["role"] == "assistant"


def test_fuse_budget_exceeded(client, attack_case, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    ai_env.setenv("AI_TOKEN_BUDGET", "10")          # 一次调用即超
    monkeypatch.setattr(ai, "_call_api", lambda *a, **k: _resp(total=15))
    case_id, _, _ = attack_case
    sid = client.post(f"/cases/{case_id}/chat/sessions", json={}).json()["id"]
    r = client.post(f"/chat/sessions/{sid}/messages",
                    json={"content": "hi"})
    body = r.json()
    assert body["stop_reason"] == ai.STOP_BUDGET
    assert "预算" in body["answer"]


def test_ai_error_honest_degradation(client, attack_case, ai_env, monkeypatch):
    """AI 服务失败:诚实降级回答,不 500,run 标 failed。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")

    def boom(*a, **k):
        raise ai.AIError(ai.KIND_NETWORK, "AI 服务不可达/超时(URLError)")

    monkeypatch.setattr(ai, "_call_api", boom)
    case_id, _, _ = attack_case
    sid = client.post(f"/cases/{case_id}/chat/sessions", json={}).json()["id"]
    r = client.post(f"/chat/sessions/{sid}/messages",
                    json={"content": "hi"})
    assert r.status_code == 200
    assert "AI 调用失败" in r.json()["answer"]
    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT status FROM analysis_runs WHERE source_id IS NULL"
        ).fetchone()
        assert row["status"] == "failed"
    finally:
        conn.close()


# ---------------------------------------------------------------- §1:AI 产物断言级不入库

def test_chat_run_not_in_analysis_list(client, attack_case, ai_env,
                                       monkeypatch):
    """chat run(source_id=NULL)不混入 L3 分析 run 列表(同表不同语义)。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    monkeypatch.setattr(ai, "_call_api", lambda *a, **k: _resp())
    case_id, _, _ = attack_case
    sid = client.post(f"/cases/{case_id}/chat/sessions", json={}).json()["id"]
    client.post(f"/chat/sessions/{sid}/messages", json={"content": "hi"})
    lst = client.get(f"/cases/{case_id}/analysis").json()
    assert lst["total"] == 0                        # 只有 chat run,L3 列表为空
    conn = db.connect()
    try:
        assert conn.execute(
            "SELECT COUNT(*) AS c FROM analysis_runs"
            " WHERE source_id IS NULL").fetchone()["c"] == 1
    finally:
        conn.close()

def test_ai_output_never_stored(client, attack_case, ai_env, monkeypatch):
    """问答全程(mock AI 提及命中 + 调工具):clues/hits 零新增零状态变化。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, _, hits = attack_case

    def fake(messages, **k):
        if not any(m["role"] == "tool" for m in messages):
            return _resp(None, tool_calls=[
                _tc("list_hits", {"case_id": case_id})])
        return _resp(f"建议把命中 {hits[0]['id']} 入库")  # AI「建议」也只是消息

    monkeypatch.setattr(ai, "_call_api", fake)
    conn = db.connect()
    try:
        clues_before = conn.execute(
            "SELECT COUNT(*) AS c FROM clues").fetchone()["c"]
        hits_before = conn.execute(
            "SELECT COUNT(*) AS c FROM hits").fetchone()["c"]
    finally:
        conn.close()
    sid = client.post(f"/cases/{case_id}/chat/sessions", json={}).json()["id"]
    client.post(f"/chat/sessions/{sid}/messages", json={"content": "怎么办"})
    conn = db.connect()
    try:
        assert conn.execute(
            "SELECT COUNT(*) AS c FROM clues").fetchone()["c"] == clues_before
        assert conn.execute(
            "SELECT COUNT(*) AS c FROM hits").fetchone()["c"] == hits_before
        assert conn.execute(                        # 命中状态零变化
            "SELECT COUNT(*) AS c FROM hits WHERE status != 'pending'"
        ).fetchone()["c"] == 0
    finally:
        conn.close()
