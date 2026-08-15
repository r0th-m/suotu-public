"""记录区(案件日志流)测试(合成纪律)。

覆盖:
- 人工笔记 CRUD:新增(201+审计 note_add)/删除(物理删+审计 note_delete);
  正文空/超 4000 字 → 422;
- 锚点校验:hit/scan_round/analysis_run/line 四类引用不存在 → 422 如实;
- 删除权限:他人笔记 → 403(auth 无角色,仅本人可删);
- journal 合成流:扫描轮次/AI 分析/笔记三类合流按时间倒序;自动条目内容
  正确(跑一轮真实扫描 + 构造 analysis_run 行);无摘要/错误如实展示;
  空案件空流;分页 limit/offset。
"""
from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient

from backend.app import auth, ingest, journal, rules
from backend.app.main import app

ATTACK = ('93.184.216.34 - - [10/Oct/2000:13:55:36 +0000] "GET'
          ' /search?q=1%27%20UNION%20SELECT%20password%20FROM%20users'
          ' HTTP/1.1" 200 10 "-" "Mozilla/5.0"')
NORMAL = ('93.184.216.34 - - [10/Oct/2000:13:55:46 +0000]'
          ' "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"')
TEXT = ATTACK + "\n" + NORMAL + "\n"


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


def _parse(conn, case_id, text=TEXT, name="access.log"):
    reg = ingest.register_upload(conn, case_id, name, io.BytesIO(text.encode()))
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, "nginx_combined",
                          tz_declared="UTC", log_type="web")
    assert ingest.parse_source(conn, sid)["status"] == "parsed"
    return sid


def _audits(conn, case_id, action):
    return conn.execute(
        "SELECT * FROM audit_log WHERE case_id = ? AND action = ?",
        (case_id, action)).fetchall()


def _make_run(conn, case_id, source_id, *, status="done",
              created="2026-08-10T00:00:00+00:00", report=None, error=None):
    """直接落一行 analysis_runs(自动条目合成的台账输入)。"""
    with conn:
        conn.execute(
            "INSERT INTO analysis_runs (id, case_id, source_id, status,"
            " profile, anchors_json, budget, error, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            ("run-j-1", case_id, source_id, status, "online",
             json.dumps(report, ensure_ascii=False) if report else None,
             1000, error, created))
    return "run-j-1"


# ==================== 笔记 CRUD + 审计 ====================

def test_note_add_list_delete(client, conn, case_id):
    r = client.post(f"/cases/{case_id}/notes", json={"body": "  第一条笔记  "})
    assert r.status_code == 201
    note = r.json()
    assert note["body"] == "第一条笔记"                    # 去首尾空白
    assert note["author"] == "tester" and note["anchor_kind"] is None
    assert len(_audits(conn, case_id, "note_add")) == 1    # 审计留痕
    # 删除:物理删 + 审计
    r = client.delete(f"/notes/{note['id']}")
    assert r.status_code == 200 and r.json()["deleted"] is True
    assert len(_audits(conn, case_id, "note_delete")) == 1
    assert client.delete(f"/notes/{note['id']}").status_code == 404


def test_note_body_validation(client, case_id):
    assert client.post(f"/cases/{case_id}/notes",
                       json={"body": "   "}).status_code == 422
    assert client.post(
        f"/cases/{case_id}/notes",
        json={"body": "x" * 4001}).status_code == 422
    assert client.post(
        f"/cases/{case_id}/notes",
        json={"body": "ok", "anchor_kind": "hit"}).status_code == 422  # 缺 ref


def test_note_anchor_422_when_missing(client, conn, case_id):
    sid = _parse(conn, case_id)
    for kind, ref in (("hit", "no-such-hit"),
                      ("scan_round", "99"),
                      ("analysis_run", "no-such-run"),
                      ("line", "bad-format"),
                      ("line", "no-such-source:1"),
                      ("line", f"{sid}:9999")):
        r = client.post(f"/cases/{case_id}/notes",
                        json={"body": "锚点测试", "anchor_kind": kind,
                              "anchor_ref": ref})
        assert r.status_code == 422, (kind, ref)
    # 合法锚点正样本:行号锚点指向真实行
    r = client.post(f"/cases/{case_id}/notes",
                    json={"body": "合法行锚点", "anchor_kind": "line",
                          "anchor_ref": f"{sid}:1"})
    assert r.status_code == 201
    assert r.json()["anchor_ref"] == f"{sid}:1"


def test_note_delete_only_author(client, conn, case_id):
    r = client.post(f"/cases/{case_id}/notes", json={"body": "作者的笔记"})
    note_id = r.json()["id"]
    # 另一用户:建号 + 换会话 Cookie
    auth.create_user("other", "Other#2026pass")
    other_token = auth.create_session("other")
    client.cookies.set(auth.COOKIE_NAME, other_token)
    r = client.delete(f"/notes/{note_id}")
    assert r.status_code == 403                            # 他人不可删
    # 换回本人可删
    client.cookies.set(auth.COOKIE_NAME, auth.create_session("tester"))
    assert client.delete(f"/notes/{note_id}").status_code == 200


# ==================== journal 合成流 ====================

def test_journal_synthesis_order_and_content(client, conn, case_id):
    sid = _parse(conn, case_id)
    # AI 台账(老时间戳,带 findings 报告)
    _make_run(conn, case_id, sid, report={
        "anchors": [1],
        "windows": [{"from": 1, "to": 2, "anchors": [1], "findings": 2,
                     "status": "done"}]})
    rules.run_rules(conn, case_id, rule_ids=["sqli-union-select"])  # 第 1 轮
    client.post(f"/cases/{case_id}/notes", json={"body": "记录一下"})
    body = client.get(f"/cases/{case_id}/journal").json()
    assert body["total"] == 3
    kinds = [e["kind"] for e in body["items"]]
    assert kinds == ["note", "scan", "ai"]               # 时间倒序(笔记最新)
    # 扫描自动条目内容
    scan = body["items"][1]
    assert scan["title"] == "第 1 轮扫描"
    assert "扫描 2 行" in scan["body"] and "新增候选 1" in scan["body"]
    assert scan["anchor"] == {"kind": "scan_round", "ref": "1"}
    assert scan["meta"]["rule_ids"] == ["sqli-union-select"]
    # AI 自动条目内容(状态 + findings 计数)
    ai = body["items"][2]
    assert ai["kind"] == "ai" and "状态 done" in ai["body"]
    assert "findings 2" in ai["body"]
    assert ai["anchor"] == {"kind": "analysis_run", "ref": "run-j-1"}


def test_journal_ai_entry_without_report(conn, case_id):
    sid = _parse(conn, case_id)
    _make_run(conn, case_id, sid, status="failed", error="ai 调用失败")
    flow = journal.journal(conn, case_id)
    assert flow["total"] == 1
    assert "错误:ai 调用失败" in flow["items"][0]["body"]  # 如实展示错误
    # 无报告无错误 → 如实「无摘要」
    with conn:
        conn.execute("UPDATE analysis_runs SET error = NULL WHERE id = 'run-j-1'")
    flow = journal.journal(conn, case_id)
    assert "无摘要" in flow["items"][0]["body"]


def test_journal_empty_case(conn, case_id):
    flow = journal.journal(conn, case_id)
    assert flow["total"] == 0 and flow["items"] == []      # 空案件如实空流


def test_journal_pagination(conn, case_id):
    _parse(conn, case_id)
    rules.run_rules(conn, case_id)                          # 1 条自动
    for i in range(3):
        journal.add_note(conn, case_id, f"笔记{i}")
    page1 = journal.journal(conn, case_id, limit=2, offset=0)
    page2 = journal.journal(conn, case_id, limit=2, offset=2)
    assert page1["total"] == 4
    assert len(page1["items"]) == 2 and len(page2["items"]) == 2
    ids1 = [(e["kind"], e["ts"]) for e in page1["items"]]
    ids2 = [(e["kind"], e["ts"]) for e in page2["items"]]
    assert not set(ids1) & set(ids2)                        # 翻页不重复
    all_ts = [e["ts"] for e in page1["items"] + page2["items"]]
    assert all_ts == sorted(all_ts, reverse=True)           # 全局时间倒序


def test_journal_case_not_found(client):
    assert client.get("/cases/no-such/journal").status_code == 404
    assert client.post("/cases/no-such/notes",
                       json={"body": "x"}).status_code == 404
