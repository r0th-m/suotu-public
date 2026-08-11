"""M3 analysis.py L2 播种 + L3 精读测试(全程 mock ai._call_api,断言级)。

覆盖:
- 无锚点不播种:无 pending 命中 → L3 不跑,零 AI 调用,如实 note;
- 全流程:锚点 → 窗口 → 精读 → 综合 → findings 进 hits(恒 pending,
  **clues 零新增** = AI 永不自动入库断言);
- 窗口重叠 ≥10% 合并去重(unit + 集成);
- 坏 JSON 不断链:该窗 ai_error,后续窗口照常,run 不 failed;
- 三重否定:三路齐全 → triple_negative 留痕;窗口有仍站立的确定性命中 →
  AI 的「未见异常」不落档(clean_suppressed);
- offline_lite:③④ 跳过,如实标「无 AI·仅确定性播种」,零 AI 调用;
- abort:运行中置 aborted,下一窗前即停,部分结果如实保留;
- 并发去重:同一源 running 中再发 → 409;API 202/轮询/abort/列表。
"""
from __future__ import annotations

import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app import ai, analysis, db, rules
from backend.app.main import app

from conftest import make_run_row, register_confirm_parse

_AI_RULE = analysis.AI_RULE_ID


def _nginx_text(n: int) -> str:
    """n 行可解析的 nginx combined 正常行。"""
    return "".join(
        f'93.184.216.34 - - [10/Oct/2000:13:{i // 60 % 60:02d}:{i % 60:02d}'
        f' +0300] "GET /p{i} HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
        for i in range(n))


def _hit(conn, case_id, sid, line_no, rule_id="sqli-union-select",
         status="pending"):
    with conn:
        conn.execute(
            "INSERT INTO hits (id, case_id, source_id, line_no, rule_id,"
            " severity, matched_field, matched_value, snippet, status,"
            " created_at) VALUES (?,?,?,?,?,'high','query','x','snip',?,?)",
            (uuid.uuid4().hex, case_id, sid, line_no, rule_id, status,
             "2026-08-05T00:00:00+00:00"))


def _usage(total=15):
    return {"prompt_tokens": total - 5, "completion_tokens": 5,
            "total_tokens": total}


def _resp(content):
    return {"content": content, "tool_calls": None, "model": "m-test",
            "usage": _usage()}


def _finding_json(findings, note="本窗摘要"):
    return json.dumps({"findings": findings, "window_note": note},
                      ensure_ascii=False)


@pytest.fixture()
def seeded(conn, case_id):
    """60 行正常 nginx 入库(窗口测试底料)。"""
    sid, _, report = register_confirm_parse(conn, case_id, _nginx_text(60),
                                            "nginx_combined")
    assert report["parsed"] == 60
    return case_id, sid


def _mock_window(monkeypatch, responder, calls):
    """mock ai._call_api:L3 窗口请求走 responder,综合 pass 回固定故事。"""

    def fake(messages, **kw):
        if messages[0]["content"] == ai.SYSTEM_PROMPT_L3:
            calls["window"] += 1
            return responder(messages, calls["window"])
        calls["synth"] += 1
        return _resp("综合故事:窗口串起来的一段排查叙事")
    monkeypatch.setattr(ai, "_call_api", fake)


# ---------------------------------------------------------------- 无锚点不播种

def test_no_anchor_no_seeding(conn, seeded, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, sid = seeded
    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, lambda m, n: _resp("{}"), calls)
    out = analysis.start_analysis(conn, case_id, sid, background=False)
    run = analysis.get_run(out["run_id"])
    assert run["status"] == "done"
    assert "无锚点不播种" in run["note"]
    assert calls["window"] == 0 and calls["synth"] == 0     # L3 不跑,零 AI
    assert run["usage"] is None                             # 无调用即无记账


# ---------------------------------------------------------------- 全流程(真 L1 + mock L3)

_ATTACK = "\n".join([
    '93.184.216.34 - - [10/Oct/2000:13:55:36 +0300] "GET /search?q=1%27%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    '93.184.216.34 - - [10/Oct/2000:13:55:37 +0300] "GET /.git/config HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    '93.184.216.34 - - [10/Oct/2000:13:55:38 +0300] "GET /ok HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
]) + "\n"


def test_l3_full_flow_and_never_auto_clue(conn, case_id, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    sid, _, _ = register_confirm_parse(conn, case_id, _ATTACK,
                                       "nginx_combined")
    rules.run_rules(conn, case_id, source_id=sid)           # L1 产 pending 锚点
    clues_before = conn.execute(
        "SELECT COUNT(*) AS c FROM clues WHERE case_id = ?",
        (case_id,)).fetchone()["c"]

    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, lambda m, n: _resp(_finding_json([
        {"summary": "疑似 SQL 注入尝试,需人工核实", "suspicion": "high",
         "line_refs": [1]},
        {"summary": "敏感路径访问,疑似侦察", "suspicion": "medium",
         "line_refs": [2]},
    ])), calls)
    out = analysis.start_analysis(conn, case_id, sid,
                                  window_lines=5, background=False)
    run = analysis.get_run(out["run_id"])
    assert run["status"] == "done"
    assert run["report"]["synthesis"] == "综合故事:窗口串起来的一段排查叙事"
    assert calls["window"] == 1 and calls["synth"] == 1    # 1 窗 + 1 综合

    hits = conn.execute(
        "SELECT * FROM hits WHERE case_id = ? AND rule_id = ?",
        (case_id, _AI_RULE)).fetchall()
    assert len(hits) == 2
    for h in hits:
        assert h["status"] == "pending"                    # 恒 pending
        d = json.loads(h["detail_json"])
        assert d["kind"] == "ai_finding" and d["run_id"] == out["run_id"]
        assert d["triple_negative"] is False
        assert d["window"]["from"] <= h["line_no"] <= d["window"]["to"]
    assert {h["severity"] for h in hits} == {"high", "medium"}
    # usage 累进 2 次调用 + 审计留痕
    assert ai.run_usage(out["run_id"])["calls"] == 2
    assert conn.execute("SELECT COUNT(*) AS c FROM audit_log"
                        " WHERE action = 'ai_call'").fetchone()["c"] == 2
    assert conn.execute("SELECT COUNT(*) AS c FROM audit_log"
                        " WHERE action = 'analysis_finish'"
                        ).fetchone()["c"] == 1
    # ★断言级:AI 产物永不自动入库 —— run 完成后 clues 零新增
    clues_after = conn.execute(
        "SELECT COUNT(*) AS c FROM clues WHERE case_id = ?",
        (case_id,)).fetchone()["c"]
    assert clues_after == clues_before == 0


# ---------------------------------------------------------------- 窗口合并

def test_merge_windows_unit():
    # 重叠 ≥10%(11 行窗阈值 1 行)合并;不重叠不合并;钳到行数;锚点去重
    assert analysis.merge_windows([10, 12, 500], 5) == [(5, 17), (495, 505)]
    assert analysis.merge_windows([10, 40], 5) == [(5, 15), (35, 45)]
    assert analysis.merge_windows([3, 3], 5, line_count=8) == [(1, 8)]


def test_window_overlap_merge_integration(conn, seeded, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, sid = seeded
    _hit(conn, case_id, sid, 5)
    _hit(conn, case_id, sid, 8)      # [1,10] 与 [3,13] 重叠 8 行 → 合并
    _hit(conn, case_id, sid, 40)     # [35,45] 独立
    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, lambda m, n: _resp(
        _finding_json([{"summary": f"窗口{n}疑似异常", "suspicion": "low",
                        "line_refs": [5]}])), calls)
    out = analysis.start_analysis(conn, case_id, sid,
                                  window_lines=5, background=False)
    run = analysis.get_run(out["run_id"])
    assert calls["window"] == 2                          # 3 锚点 → 2 窗口
    assert [(w["from"], w["to"]) for w in run["report"]["windows"]] == \
        [(1, 13), (35, 45)]


# ---------------------------------------------------------------- 坏 JSON 不断链

def test_bad_json_window_ai_error_chain_alive(conn, seeded, ai_env,
                                              monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, sid = seeded
    _hit(conn, case_id, sid, 5)
    _hit(conn, case_id, sid, 40)

    def responder(messages, n):
        if n == 1:
            return _resp("这不是 JSON,是 AI 的自由发挥")
        return _resp(_finding_json([{"summary": "第二窗疑似异常",
                                     "suspicion": "low", "line_refs": [40]}]))
    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, responder, calls)
    out = analysis.start_analysis(conn, case_id, sid,
                                  window_lines=5, background=False)
    run = analysis.get_run(out["run_id"])
    assert run["status"] == "done"                       # 坏窗不拖垮 run
    w0, w1 = run["report"]["windows"]
    assert w0["status"] == "ai_error" and "JSON" in w0["ai_error"]
    assert w1["status"] == "done" and w1["findings"] == 1
    hits = conn.execute(
        "SELECT COUNT(*) AS c FROM hits WHERE case_id = ? AND rule_id = ?",
        (case_id, _AI_RULE)).fetchone()["c"]
    assert hits == 1                                     # 只有第二窗的发现


# ---------------------------------------------------------------- 三重否定

def test_triple_negative_recorded(conn, seeded, ai_env, monkeypatch):
    """锚点被人 reject(人审否决,L3 后台跑期间发生)+ AI 未见异常
    → 签名未命中+统计无异常+AI 未见异常 三路齐全,落 triple_negative 留痕。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, sid = seeded
    _hit(conn, case_id, sid, 5)

    def responder(messages, n):
        # 模拟人在分析跑期间否决了该锚点命中(判断权归人)
        conn2 = db.connect()
        try:
            with conn2:
                conn2.execute("UPDATE hits SET status = 'rejected'"
                              " WHERE case_id = ? AND source_id = ?",
                              (case_id, sid))
        finally:
            conn2.close()
        return _resp(_finding_json([], note="本窗未见可疑活动"))
    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, responder, calls)
    out = analysis.start_analysis(conn, case_id, sid,
                                  window_lines=5, background=False)
    run = analysis.get_run(out["run_id"])
    assert run["status"] == "done"
    assert run["report"]["windows"][0].get("triple_negative") is True
    hits = conn.execute(
        "SELECT * FROM hits WHERE case_id = ? AND rule_id = ?",
        (case_id, _AI_RULE)).fetchall()
    assert len(hits) == 1
    assert hits[0]["status"] == "pending" and hits[0]["severity"] == "info"
    d = json.loads(hits[0]["detail_json"])
    assert d["triple_negative"] is True
    assert "三重否定" in hits[0]["snippet"]


def test_clean_verdict_suppressed_when_deterministic_hit_stands(
        conn, seeded, ai_env, monkeypatch):
    """锚点仍 pending(确定性命中站立)+ AI 未见异常 → 不许写「无异常」:
    不落 triple_negative,记 clean_suppressed。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, sid = seeded
    _hit(conn, case_id, sid, 5)
    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, lambda m, n: _resp(
        _finding_json([], note="本窗未见可疑活动")), calls)
    out = analysis.start_analysis(conn, case_id, sid,
                                  window_lines=5, background=False)
    run = analysis.get_run(out["run_id"])
    w0 = run["report"]["windows"][0]
    assert w0.get("clean_suppressed") is True
    assert "suppress_note" in w0
    tn = conn.execute(
        "SELECT COUNT(*) AS c FROM hits WHERE case_id = ? AND rule_id = ?",
        (case_id, _AI_RULE)).fetchone()["c"]
    assert tn == 0                                       # 无「无异常」落档


# ---------------------------------------------------------------- offline_lite 降级

def test_offline_lite_deterministic_seeding_only(conn, seeded, ai_env,
                                                 monkeypatch):
    case_id, sid = seeded                                # ai_env 无 key
    _hit(conn, case_id, sid, 5)
    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, lambda m, n: _resp("{}"), calls)
    out = analysis.start_analysis(conn, case_id, sid,
                                  window_lines=5, background=False)
    run = analysis.get_run(out["run_id"])
    assert run["status"] == "done" and run["profile"] == "offline_lite"
    assert "无 AI·仅确定性播种" in run["note"]
    assert run["report"]["windows"][0]["status"] == "skipped_offline"
    assert calls["window"] == 0 and calls["synth"] == 0  # 零 AI 调用
    assert conn.execute(
        "SELECT COUNT(*) AS c FROM hits WHERE case_id = ? AND rule_id = ?",
        (case_id, _AI_RULE)).fetchone()["c"] == 0        # 无 AI 发现


# ---------------------------------------------------------------- abort / 并发去重

def test_abort_mid_run_stops_before_next_window(conn, seeded, ai_env,
                                                monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, sid = seeded
    for ln in (5, 25, 45):
        _hit(conn, case_id, sid, ln)

    def responder(messages, n):
        conn2 = db.connect()                             # 模拟用户 abort
        try:
            with conn2:
                conn2.execute("UPDATE analysis_runs SET status = 'aborted'"
                              " WHERE status = 'running'")
        finally:
            conn2.close()
        return _resp(_finding_json([{"summary": f"窗{n}疑似异常",
                                     "suspicion": "low", "line_refs": [5]}]))
    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, responder, calls)
    out = analysis.start_analysis(conn, case_id, sid,
                                  window_lines=5, background=False)
    run = analysis.get_run(out["run_id"])
    assert run["status"] == "aborted"
    assert "中断" in (run["error"] or "")
    assert calls["window"] == 1                          # 下一窗前即停
    statuses = [w["status"] for w in run["report"]["windows"]]
    assert statuses[0] == "done" and all(s == "pending" for s in statuses[1:])


def test_concurrent_run_same_source_409(conn, seeded, ai_env):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, sid = seeded
    make_run_row(conn, case_id, sid, status="running")
    with pytest.raises(analysis.AnalysisError) as ei:
        analysis.start_analysis(conn, case_id, sid, background=False)
    assert ei.value.status == 409


def test_start_validates(conn, seeded, ai_env):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    case_id, sid = seeded
    with pytest.raises(analysis.AnalysisError) as ei:
        analysis.start_analysis(conn, case_id, "src-不存在")
    assert ei.value.status == 404
    with pytest.raises(analysis.AnalysisError):
        analysis.start_analysis(conn, case_id, sid, window_lines=0)


# ---------------------------------------------------------------- API

@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


def test_api_run_poll_abort_list(client, conn, case_id, ai_env, monkeypatch):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    sid, _, _ = register_confirm_parse(conn, case_id, _ATTACK,
                                       "nginx_combined")
    rules.run_rules(conn, case_id, source_id=sid)
    calls = {"window": 0, "synth": 0}
    _mock_window(monkeypatch, lambda m, n: _resp(
        _finding_json([{"summary": "疑似注入,需人工核实", "suspicion": "high",
                        "line_refs": [1]}])), calls)

    res = client.post(f"/cases/{case_id}/analysis:run",
                      json={"source_id": sid, "window_lines": 5})
    assert res.status_code == 202
    run_id = res.json()["run_id"]
    deadline = time.time() + 15                           # 后台线程轮询
    while time.time() < deadline:
        body = client.get(f"/analysis/{run_id}").json()
        if body["status"] != "running":
            break
        time.sleep(0.05)
    assert body["status"] == "done", body
    assert body["report"]["anchors"]
    assert body["usage"]["calls"] == 2
    # AI 永不自动入库(API 面断言)
    assert client.get(f"/cases/{case_id}/clues").json()["total"] == 0
    # 列表 + abort 语义
    lst = client.get(f"/cases/{case_id}/analysis").json()
    assert lst["total"] == 1 and lst["items"][0]["id"] == run_id
    assert client.post(f"/analysis/{run_id}:abort").status_code == 409
    assert client.get("/analysis/run-不存在").status_code == 404
    assert client.post(f"/cases/{case_id}/analysis:run",
                       json={"source_id": "src-不存在"}).status_code == 404


def test_api_concurrent_409(client, conn, case_id, ai_env):
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    sid, _, _ = register_confirm_parse(conn, case_id, _ATTACK,
                                       "nginx_combined")
    make_run_row(conn, case_id, sid, status="running")
    res = client.post(f"/cases/{case_id}/analysis:run", json={"source_id": sid})
    assert res.status_code == 409
    # abort 一个 running 的 run → aborted
    row = conn.execute("SELECT id FROM analysis_runs WHERE status = 'running'"
                       ).fetchone()
    res = client.post(f"/analysis/{row['id']}:abort")
    assert res.status_code == 200 and res.json()["status"] == "aborted"


def test_zombie_run_recovered(conn, case_id):
    """僵尸 run 回收:running 卡死(模拟进程退出)→ recover 后 failed 且可重新发起。"""
    from backend.app import analysis
    sid, _, _ = register_confirm_parse(conn, case_id, _nginx_text(20),
                                       "nginx_combined")
    with conn:
        conn.execute(
            "INSERT INTO analysis_runs (id, case_id, source_id, status,"
            " profile, budget, created_at) VALUES ('z1', ?, ?, 'running',"
            " 'online', 1000, 'now')", (case_id, sid))
    assert analysis.recover_zombie_runs() == 1
    row = conn.execute("SELECT status, error FROM analysis_runs"
                       " WHERE id = 'z1'").fetchone()
    assert row["status"] == "failed" and "进程退出" in row["error"]
    # 僵尸清掉后同源可重新发起(不再 409)
    run = analysis.start_analysis(conn, case_id, sid, background=False)
    assert run["status"] in ("running", "done")
    # 再回收一次:无 running → 0
    assert analysis.recover_zombie_runs() == 0


def test_prompt_char_gate(conn, case_id, ai_env, monkeypatch):
    """字符闸:行数闸内但字符超限时按字符截断,prompt_truncated_by='chars'
    如实标注(测试把闸值缩到 10000,等价语义不依赖绝对值)。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    monkeypatch.setattr(analysis, "_PROMPT_MAX_CHARS", 10000)
    # 30 行 × 2000 字符:行数远低于 500,字符超闸
    big_line = '93.184.216.34 - - [10/Oct/2000:13:55:36 +0300] "GET /' + "p" * 1900 + ' HTTP/1.1" 200 10 "-" "Mozilla/5.0"'
    text = "\n".join([big_line] * 30) + "\n"
    sid, _, _ = register_confirm_parse(conn, case_id, text, "nginx_combined")
    # 造一个 pending 锚点
    from backend.app import rules as _rules
    with conn:
        conn.execute(
            "INSERT INTO hits (id, case_id, source_id, line_no, rule_id,"
            " severity, matched_field, matched_value, snippet, status,"
            " created_at) VALUES ('h1', ?, ?, 15, 'sqli-union-select',"
            " 'high', 'query', 'x', 's', 'pending', 'now')", (case_id, sid))
    seen = {}

    def fake(messages, **kw):
        if messages[0]["content"] == ai.SYSTEM_PROMPT_L3:
            seen["user"] = messages[1]["content"]
            return _resp('{"findings": [], "window_note": "w"}')
        return _resp("综合故事")

    monkeypatch.setattr(ai, "_call_api", fake)
    out = analysis.start_analysis(conn, case_id, sid, background=False)
    run = analysis.get_run(out["run_id"])
    w = (run.get("report") or {}).get("windows", [{}])[0]
    assert w.get("prompt_truncated") is True
    assert w.get("prompt_truncated_by") == "chars"
    # 实际喂出的行数远小于 30(约 24000/2010 ≈ 12 行)
    assert "仅展示前" in seen["user"]


def test_budget_zero_unlimited(conn, case_id, ai_env, monkeypatch):
    """budget=0 = 不限(用户显式选择):超默认预算也不停;循环检测不受影响。"""
    ai_env.setenv("DEEPSEEK_API_KEY", "k-test")
    sid, _, _ = register_confirm_parse(conn, case_id, _ATTACK, "nginx_combined")
    with conn:
        conn.execute(
            "INSERT INTO hits (id, case_id, source_id, line_no, rule_id,"
            " severity, matched_field, matched_value, snippet, status,"
            " created_at) VALUES ('h9', ?, ?, 1, 'sqli-union-select',"
            " 'high', 'query', 'x', 's', 'pending', 'now')", (case_id, sid))
    monkeypatch.setattr(ai, "_call_api",
                        lambda messages, **kw: _resp('{"findings": [], "window_note": "w"}')
                        if messages[0]["content"] == ai.SYSTEM_PROMPT_L3
                        else _resp("综合"))
    out = analysis.start_analysis(conn, case_id, sid, background=False, budget=0)
    run = analysis.get_run(out["run_id"])
    assert run["status"] == "done"
    assert run["budget"] == 0
    assert not (run.get("report") or {}).get("budget_exceeded")
    # budget 校验:负数/非整数拒绝
    import pytest as _pt
    with _pt.raises(analysis.AnalysisError):
        analysis.start_analysis(conn, case_id, sid, background=False, budget=-1)
