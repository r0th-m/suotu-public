"""M3 ai.py 编排层测试(全程 mock _call_api,断言级;.env 永不进测试)。

覆盖:
- 档位:key 在 → online / ai_available;无 key → offline_lite,chat 抛
  AIError(kind=offline) 且不写审计(根本没发生调用);
- chat:usage 累进 run、逐次审计(actor=ai)、token 预算超限 → CircuitStop
  (budget_exceeded),且预算已超时不再次发生 API 调用;
- 熔断四条(各如实标因):轮数上限 round_limit / 调用上限 tool_call_limit /
  预算超限 budget_exceeded / 循环检测 loop_detected(第 3 次相同调用不执行);
- abort:run 置 aborted 后,下一轮前即停,stop_reason=aborted;
- 未知工具名:不执行,错误喂回 AI 自纠,循环不炸。
"""
from __future__ import annotations

import json

import pytest

from backend.app import ai, db

from conftest import make_run_row, make_source_row


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
def run_ctx(conn, case_id):
    """case + source + run 行(chat/run_agent 的落账上下文)。"""
    sid = make_source_row(conn, case_id)
    return case_id, sid


# ---------------------------------------------------------------- 档位

def test_profile_online_and_offline(ai_env):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    assert ai.profile() == "online" and ai.ai_available() is True
    ai_env.delenv("DEEPSEEK_API_KEY")
    assert ai.profile() == "offline_lite" and ai.ai_available() is False
    st = ai.status()
    assert st["available"] is False and "降级" in st["note"]


def test_chat_offline_raises_without_audit(conn, case_id, run_ctx, ai_env):
    _, sid = run_ctx
    run_id = make_run_row(conn, case_id, sid)
    before = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
    with pytest.raises(ai.AIError) as ei:
        ai.chat([{"role": "user", "content": "hi"}], run_id=run_id)
    assert ei.value.kind == ai.KIND_OFFLINE
    after = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
    assert after == before                     # 未发生调用,不写审计


# ---------------------------------------------------------------- chat 记账

def test_chat_accumulates_usage_and_audits(conn, case_id, run_ctx, ai_env,
                                           monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    _, sid = run_ctx
    run_id = make_run_row(conn, case_id, sid, budget=100)
    monkeypatch.setattr(ai, "_call_api",
                        lambda *a, **k: _resp(total=15))
    out = ai.chat([{"role": "user", "content": "hi"}], run_id=run_id)
    assert out["content"] == "回答" and out["model"] == "m-test"
    acc = ai.run_usage(run_id)
    assert acc["total_tokens"] == 15 and acc["calls"] == 1
    rows = conn.execute(
        "SELECT actor, action, scope, detail_json FROM audit_log"
        " WHERE action = 'ai_call'").fetchall()
    assert len(rows) == 1
    assert rows[0]["actor"] == "ai" and rows[0]["scope"] == run_id
    assert json.loads(rows[0]["detail_json"])["ok"] is True


def test_chat_budget_exceeded_stops_and_blocks_next_call(
        conn, case_id, run_ctx, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    _, sid = run_ctx
    run_id = make_run_row(conn, case_id, sid, budget=10)
    calls = {"n": 0}

    def fake(*a, **k):
        calls["n"] += 1
        return _resp(total=15)                 # 一次就超预算

    monkeypatch.setattr(ai, "_call_api", fake)
    with pytest.raises(ai.CircuitStop) as ei:
        ai.chat([{"role": "user", "content": "hi"}], run_id=run_id)
    assert ei.value.reason == ai.STOP_BUDGET
    assert ai.run_usage(run_id)["total_tokens"] == 15   # 已发生调用如实记账
    with pytest.raises(ai.CircuitStop) as ei2:          # 预算已超:不再调用
        ai.chat([{"role": "user", "content": "again"}], run_id=run_id)
    assert ei2.value.reason == ai.STOP_BUDGET
    assert calls["n"] == 1


def test_chat_api_error_audited(conn, case_id, run_ctx, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    _, sid = run_ctx
    run_id = make_run_row(conn, case_id, sid)

    def boom(*a, **k):
        raise ai.AIError(ai.KIND_NETWORK, "AI 服务不可达/超时(URLError)")

    monkeypatch.setattr(ai, "_call_api", boom)
    with pytest.raises(ai.AIError) as ei:
        ai.chat([{"role": "user", "content": "hi"}], run_id=run_id)
    assert ei.value.kind == ai.KIND_NETWORK
    row = conn.execute("SELECT detail_json FROM audit_log"
                       " WHERE action = 'ai_call'").fetchone()
    assert json.loads(row["detail_json"])["error_kind"] == ai.KIND_NETWORK


# ---------------------------------------------------------------- 熔断四条 + abort

@pytest.fixture()
def agent_ctx(conn, case_id, run_ctx, ai_env):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    _, sid = run_ctx
    return case_id, sid


def _agent_responses(monkeypatch, seq):
    """按队列依次返回 _call_api 响应;队空后恒返回纯文本(收敛)。"""
    it = iter(seq)

    def fake(messages, **k):
        return next(it, _resp("最终回答"))
    monkeypatch.setattr(ai, "_call_api", fake)


def test_breaker_round_limit(conn, case_id, agent_ctx, monkeypatch):
    case_id, sid = agent_ctx
    monkeypatch.setenv("AI_MAX_ROUNDS", "2")
    run_id = make_run_row(conn, case_id, sid)
    # 每轮都要工具且参数不同(避开循环检测),轮数上限应先命中
    _agent_responses(monkeypatch, [
        _resp(content=None, tool_calls=[_tc("search_logs", {"case_id": case_id, "q": "a"})]),
        _resp(content=None, tool_calls=[_tc("search_logs", {"case_id": case_id, "q": "b"})]),
        _resp(content=None, tool_calls=[_tc("search_logs", {"case_id": case_id, "q": "c"})]),
    ])
    out = ai.run_agent(run_id, [{"role": "user", "content": "查"}])
    assert out["stop_reason"] == ai.STOP_ROUND_LIMIT
    assert out["rounds"] == 2 and out["content"] is None


def test_breaker_tool_call_limit(conn, case_id, agent_ctx, monkeypatch):
    case_id, sid = agent_ctx
    monkeypatch.setenv("AI_MAX_TOOL_CALLS", "2")
    run_id = make_run_row(conn, case_id, sid)
    _agent_responses(monkeypatch, [
        _resp(content=None, tool_calls=[_tc("search_logs", {"case_id": case_id, "q": "a"})]),
        _resp(content=None, tool_calls=[_tc("search_logs", {"case_id": case_id, "q": "b"})]),
        _resp(content=None, tool_calls=[_tc("search_logs", {"case_id": case_id, "q": "c"})]),
    ])
    out = ai.run_agent(run_id, [{"role": "user", "content": "查"}])
    assert out["stop_reason"] == ai.STOP_TOOL_CALL_LIMIT
    assert out["tool_calls"] == 2


def test_breaker_loop_detected(conn, case_id, agent_ctx, monkeypatch):
    case_id, sid = agent_ctx
    run_id = make_run_row(conn, case_id, sid)
    same = _resp(content=None,
                 tool_calls=[_tc("search_logs", {"case_id": case_id, "q": "x"})])
    _agent_responses(monkeypatch, [same, same, same, same])
    out = ai.run_agent(run_id, [{"role": "user", "content": "查"}])
    assert out["stop_reason"] == ai.STOP_LOOP
    # 相同工具+参数第 3 次判循环即停:只执行了 2 次
    assert out["tool_calls"] == 2
    run = conn.execute("SELECT tool_log_json FROM analysis_runs WHERE id = ?",
                       (run_id,)).fetchone()
    log = json.loads(run["tool_log_json"])
    assert len(log) == 2
    assert log[0]["tool"] == "search_logs"
    assert set(log[0]) == {"tool", "args", "result_count", "truncated"}


def test_breaker_budget_in_agent(conn, case_id, agent_ctx, monkeypatch):
    case_id, sid = agent_ctx
    run_id = make_run_row(conn, case_id, sid, budget=10)
    _agent_responses(monkeypatch, [_resp(total=15)])
    out = ai.run_agent(run_id, [{"role": "user", "content": "查"}])
    assert out["stop_reason"] == ai.STOP_BUDGET


def test_breaker_abort_mid_run(conn, case_id, agent_ctx, monkeypatch):
    case_id, sid = agent_ctx
    run_id = make_run_row(conn, case_id, sid)

    def fake(messages, **k):
        # 第一轮工具执行后把 run 置 aborted(模拟用户中断)
        conn2 = db.connect()
        try:
            with conn2:
                conn2.execute("UPDATE analysis_runs SET status = 'aborted'"
                              " WHERE id = ?", (run_id,))
        finally:
            conn2.close()
        return _resp(content=None,
                     tool_calls=[_tc("search_logs", {"case_id": case_id})])
    monkeypatch.setattr(ai, "_call_api", fake)
    out = ai.run_agent(run_id, [{"role": "user", "content": "查"}])
    assert out["stop_reason"] == ai.STOP_ABORTED
    assert out["rounds"] == 1 and out["tool_calls"] == 1


def test_agent_completed_and_tool_log(conn, case_id, agent_ctx, monkeypatch):
    case_id, sid = agent_ctx
    run_id = make_run_row(conn, case_id, sid)
    _agent_responses(monkeypatch, [
        _resp(content=None, tool_calls=[_tc("field_stats", {"case_id": case_id})]),
        _resp("查完了"),
    ])
    out = ai.run_agent(run_id, [{"role": "user", "content": "查"}])
    assert out["stop_reason"] == ai.STOP_COMPLETED
    assert out["content"] == "查完了" and out["tool_calls"] == 1
    run = conn.execute("SELECT tool_log_json FROM analysis_runs WHERE id = ?",
                       (run_id,)).fetchone()
    log = json.loads(run["tool_log_json"])
    assert log[0]["tool"] == "field_stats" and log[0]["result_count"] >= 0


def test_agent_unknown_tool_not_executed(conn, case_id, agent_ctx,
                                         monkeypatch):
    case_id, sid = agent_ctx
    run_id = make_run_row(conn, case_id, sid)
    _agent_responses(monkeypatch, [
        _resp(content=None, tool_calls=[_tc("drop_table", {"x": 1})]),
        _resp("明白,工具不可用"),
    ])
    out = ai.run_agent(run_id, [{"role": "user", "content": "查"}])
    assert out["stop_reason"] == ai.STOP_COMPLETED   # 错误喂回自纠,循环不炸
    run = conn.execute("SELECT tool_log_json FROM analysis_runs WHERE id = ?",
                       (run_id,)).fetchone()
    log = json.loads(run["tool_log_json"])
    assert log[0]["tool"] == "drop_table" and log[0]["result_count"] == 0
