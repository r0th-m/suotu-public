"""入库三段式契约:register(金库+建议)→ confirm(人确认)→ parse(报告零静默)。

另覆盖:zip 多文件展开、0 行命中 → failed、状态机违规、审计哈希链。
"""
from __future__ import annotations

import io

import pytest

from backend.app import db, duck, ingest, query

from conftest import (IIS_TEXT, NGINX_TEXT, RAW_TEXT, ZERO_HIT_TEXT,
                      make_zip, register_confirm_parse)


def test_three_stage_pipeline(conn, case_id):
    reg = ingest.register_upload(conn, case_id, "access.log",
                                 io.BytesIO(NGINX_TEXT.encode()),
                                 system="web-01", source_note="运维导出")
    sid = reg["sources"][0]["source_id"]
    # ① 登记:状态 registered,指纹给建议(不确认)
    assert reg["sources"][0]["status"] == "registered"
    fp = reg["sources"][0]["fingerprint"]
    assert fp["suggestions"][0]["format_id"] == "nginx_combined"
    row = conn.execute("SELECT * FROM log_sources WHERE id = ?", (sid,)).fetchone()
    assert row["status"] == "registered" and row["format_id"] is None
    assert row["system"] == "web-01" and row["source_note"] == "运维导出"

    # ② 人确认
    c = ingest.confirm_source(conn, sid, "nginx_combined",
                              tz_declared="Asia/Shanghai", log_type="web")
    assert c["status"] == "confirmed"

    # ③ 解析:报告总/成/坏齐全,行数与时间范围回写
    rep = ingest.parse_source(conn, sid)
    assert rep["status"] == "parsed"
    assert rep["total_lines"] == 3 and rep["parsed"] == 3 and rep["bad_lines"] == 0
    assert rep["events"] == 3 and rep["entities"] >= 3   # 3 个 src_ip + alice
    row = conn.execute("SELECT * FROM log_sources WHERE id = ?", (sid,)).fetchone()
    assert row["status"] == "parsed" and row["line_count"] == 3
    assert row["time_range"] is not None               # 有声明时区 → ts_utc 非空


def test_parse_report_shows_bad_lines(conn, case_id):
    """坏行如实进解析报告(零静默),状态仍 parsed。"""
    text = NGINX_TEXT + "garbage line that matches nothing\n"
    sid, _, rep = register_confirm_parse(conn, case_id, text, "nginx_combined")
    assert rep["parsed"] == 3 and rep["bad_lines"] == 1
    assert rep["bad_samples"] and rep["bad_samples"][0].startswith("L4")
    # 报告随审计留痕,GET 源信息可取回
    stored = ingest.latest_parse_report(conn, sid)
    assert stored["bad_lines"] == 1


def test_zero_hit_marks_failed(conn, case_id):
    """非空文件 0 行命中 → failed + error,不猜不硬塞。"""
    reg = ingest.register_upload(conn, case_id, "alien.log",
                                 io.BytesIO(ZERO_HIT_TEXT.encode()))
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, "nginx_combined")
    rep = ingest.parse_source(conn, sid)
    assert rep["status"] == "failed" and "0 行命中" in rep["error"]
    row = conn.execute("SELECT status, error FROM log_sources WHERE id = ?",
                       (sid,)).fetchone()
    assert row["status"] == "failed" and row["error"]


def test_parse_requires_confirm(conn, case_id):
    """状态机:registered 直接 parse → 明确报错(三段式不可跳步)。"""
    reg = ingest.register_upload(conn, case_id, "a.log",
                                 io.BytesIO(NGINX_TEXT.encode()))
    sid = reg["sources"][0]["source_id"]
    with pytest.raises(ingest.IngestError, match="confirm"):
        ingest.parse_source(conn, sid)


def test_confirm_unknown_format_rejected(conn, case_id):
    reg = ingest.register_upload(conn, case_id, "a.log",
                                 io.BytesIO(NGINX_TEXT.encode()))
    sid = reg["sources"][0]["source_id"]
    with pytest.raises(ingest.IngestError, match="未知格式"):
        ingest.confirm_source(conn, sid, "made_up_format")


def test_reparse_idempotent(conn, case_id):
    """重解析幂等:派生行先清后插,不翻倍。"""
    sid, _, _ = register_confirm_parse(conn, case_id, NGINX_TEXT, "nginx_combined")
    rep2 = ingest.parse_source(conn, sid)
    assert rep2["events"] == 3
    n = duck.get_conn().execute(
        "SELECT COUNT(*) FROM log_events WHERE source_id = ?", (sid,)).fetchone()[0]
    assert n == 3


def test_zip_upload_multi_files(conn, case_id):
    """zip 单层逐文件展开成多个 source;嵌套 zip 跳过并如实记录。"""
    blob = make_zip({
        "nginx/access.log": NGINX_TEXT,
        "iis/u_ex.log": IIS_TEXT,
        "misc/raw.txt": RAW_TEXT,
        "nested.zip": make_zip({"inner.log": NGINX_TEXT}),
    })
    reg = ingest.register_upload(conn, case_id, "bundle.zip", io.BytesIO(blob))
    assert reg["kind"] == "zip"
    assert len(reg["sources"]) == 3
    assert len(reg["skipped"]) == 1 and "嵌套" in reg["skipped"][0]
    names = {s["name"] for s in reg["sources"]}
    assert names == {"access.log", "u_ex.log", "raw.txt"}
    # 每个成员独立走三段式
    by_name = {s["name"]: s for s in reg["sources"]}
    sid = by_name["u_ex.log"]["source_id"]
    ingest.confirm_source(conn, sid, "iis_w3c")
    rep = ingest.parse_source(conn, sid)
    assert rep["parsed"] == 2 and rep["skipped_lines"] == 4


def test_audit_chain_intact(conn, case_id):
    """三段式每步写审计,哈希链可校验。"""
    register_confirm_parse(conn, case_id, NGINX_TEXT, "nginx_combined")
    ok, msg = db.verify_audit(conn)
    assert ok, msg
    actions = [r["action"] for r in conn.execute(
        "SELECT action FROM audit_log ORDER BY id")]
    assert actions == ["source_register", "source_confirm", "source_parse"]
    assert all(r["actor"] == "system" for r in conn.execute(
        "SELECT actor FROM audit_log"))               # M4:无会话内部调用恒 system


def test_audit_chain_detects_tamper(conn, case_id):
    register_confirm_parse(conn, case_id, NGINX_TEXT, "nginx_combined")
    with conn:
        conn.execute("UPDATE audit_log SET action = 'x' WHERE id = 1")
    ok, msg = db.verify_audit(conn)
    assert not ok


# ---------------------------------------------------------------- 补充证据

def test_supplementary_evidence_flag(conn, case_id):
    """补充证据(2026-08-09,实战案例工作方式):打标入库、审计留痕、
    同管线可解析可检索;缺省仍是 log。"""
    # 缺省:普通日志源
    reg_log = ingest.register_upload(conn, case_id, "access.log",
                                     io.BytesIO(NGINX_TEXT.encode()))
    assert reg_log["sources"][0]["evidence_kind"] == "log"
    # 打标:补充证据(单文件 + zip 成员都继承)
    reg_sup = ingest.register_upload(
        conn, case_id, "runlog.txt", io.BytesIO(RAW_TEXT.encode()),
        source_note="奇虎 agent 日志,运维 08-09 导出",
        evidence_kind="supplementary")
    sup = reg_sup["sources"][0]
    assert sup["evidence_kind"] == "supplementary"
    blob = make_zip({"runlog.txt": RAW_TEXT, "notes.txt": RAW_TEXT})
    reg_zip = ingest.register_upload(conn, case_id, "evi.zip",
                                     io.BytesIO(blob),
                                     evidence_kind="supplementary")
    assert all(s["evidence_kind"] == "supplementary"
               for s in reg_zip["sources"])
    # 库里落标 + 审计 detail 留痕
    row = conn.execute("SELECT evidence_kind FROM log_sources WHERE id = ?",
                       (sup["source_id"],)).fetchone()
    assert row["evidence_kind"] == "supplementary"
    audit = conn.execute(
        "SELECT detail_json FROM audit_log WHERE action = 'source_register'"
        " ORDER BY id").fetchall()
    import json as _json
    kinds = [_json.loads(a["detail_json"]).get("evidence_kind") for a in audit]
    assert kinds[:2] == ["log", "supplementary"]
    # 补充证据同管线:确认 raw → 解析 → 检索层可查
    ingest.confirm_source(conn, sup["source_id"], "raw")
    rep = ingest.parse_source(conn, sup["source_id"])
    assert rep["status"] == "parsed"
    from backend.app import query
    hits = query.search(case_id, q="oddsvc")
    assert hits["items"], "补充证据内容应能被检索层搜到"


def test_supplementary_evidence_kind_rejected(conn, case_id):
    """非法 evidence_kind 明确报错,不静默落库。"""
    with pytest.raises(ingest.IngestError):
        ingest.register_upload(conn, case_id, "x.log",
                               io.BytesIO(NGINX_TEXT.encode()),
                               evidence_kind="whatever")
