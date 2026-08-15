"""记录区(案件日志流,2026-08-15):扫描轮次/AI 分析/人工笔记的统一
案件级记录流。

纪律:
- 自动条目**读取时合成**,不复制进新表(防双写不一致):扫描轮次读
  scan_runs 台账,AI 分析读 analysis_runs 台账,有什么展示什么,
  没有的字段如实「无摘要/未回填」;
- 人工笔记落 case_notes 表(工作记录不是证据,删除为物理删;
  证据链在金库/审计链);auth.py 无角色概念 → 删除仅本人(actor=author);
- 笔记增删写审计哈希链,actor 锚真人;
- 锚点只做引用校验(对象不存在 → 422 如实),跳转语义在前端。
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from . import db, query

ANCHOR_KINDS = {"hit", "scan_round", "analysis_run", "line"}
NOTE_BODY_MAX = 4000


class JournalError(Exception):
    """记录区业务校验失败,message 直给调用方,status 为 HTTP 语义。"""
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------ 人工笔记

def _check_case(conn: sqlite3.Connection, case_id: str) -> None:
    if conn.execute("SELECT 1 FROM cases WHERE id = ?",
                    (case_id,)).fetchone() is None:
        raise JournalError(f"案件不存在: {case_id}", status=404)


def _check_anchor(conn: sqlite3.Connection, case_id: str,
                  anchor_kind: str, anchor_ref: str) -> None:
    """锚点引用校验:对象不存在 → 422 如实(不硬挂悬空引用)。"""
    if anchor_kind == "hit":
        if conn.execute("SELECT 1 FROM hits WHERE id = ? AND case_id = ?",
                        (anchor_ref, case_id)).fetchone() is None:
            raise JournalError(f"锚点候选命中不存在: {anchor_ref}", status=422)
    elif anchor_kind == "scan_round":
        if not anchor_ref.isdigit() or conn.execute(
                "SELECT 1 FROM scan_runs WHERE case_id = ? AND round_no = ?",
                (case_id, int(anchor_ref))).fetchone() is None:
            raise JournalError(f"锚点扫描轮次不存在: {anchor_ref}", status=422)
    elif anchor_kind == "analysis_run":
        if conn.execute(
                "SELECT 1 FROM analysis_runs WHERE id = ? AND case_id = ?",
                (anchor_ref, case_id)).fetchone() is None:
            raise JournalError(f"锚点分析 run 不存在: {anchor_ref}", status=422)
    elif anchor_kind == "line":
        # 坐标形态 "source_id:line_no";源须属本案,行经检索层如实验证
        parts = anchor_ref.rsplit(":", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            raise JournalError(
                f"行号锚点坐标须为 source_id:line_no,收到: {anchor_ref!r}",
                status=422)
        source_id, line_no = parts[0], int(parts[1])
        if conn.execute("SELECT 1 FROM log_sources WHERE id = ? AND case_id = ?",
                        (source_id, case_id)).fetchone() is None:
            raise JournalError(f"锚点日志源不存在或不属于本案件: {source_id}",
                               status=422)
        if not query.read_window(source_id, line_no, line_no)["lines"]:
            raise JournalError(
                f"锚点行不存在: 源 {source_id} 第 {line_no} 行", status=422)


def add_note(conn: sqlite3.Connection, case_id: str, body: str,
             anchor_kind: str | None = None, anchor_ref: str | None = None,
             actor: str = "system") -> dict:
    """新增人工笔记:正文非空 ≤4000 字;锚点先校验引用存在(422 如实);
    写审计(note_add,actor 真人)。"""
    _check_case(conn, case_id)
    text = (body or "").strip()
    if not text:
        raise JournalError("笔记正文不能为空", status=422)
    if len(text) > NOTE_BODY_MAX:
        raise JournalError(f"笔记正文超上限({NOTE_BODY_MAX} 字)", status=422)
    if anchor_kind is not None:
        if anchor_kind not in ANCHOR_KINDS:
            raise JournalError(
                f"anchor_kind 须为 {sorted(ANCHOR_KINDS)} 之一", status=422)
        if not anchor_ref or not anchor_ref.strip():
            raise JournalError("有锚点类型时 anchor_ref 必填", status=422)
        _check_anchor(conn, case_id, anchor_kind, anchor_ref.strip())
        anchor_ref = anchor_ref.strip()
    note_id = uuid.uuid4().hex
    with conn:
        conn.execute(
            "INSERT INTO case_notes (id, case_id, body, anchor_kind,"
            " anchor_ref, author, created_at) VALUES (?,?,?,?,?,?,?)",
            (note_id, case_id, text, anchor_kind, anchor_ref, actor, _now()))
        db.append_audit(conn, case_id, action="note_add", scope=note_id,
                        actor=actor,
                        detail={"anchor_kind": anchor_kind,
                                "anchor_ref": anchor_ref,
                                "body_len": len(text)})
    return get_note(conn, note_id)


def get_note(conn: sqlite3.Connection, note_id: str) -> dict:
    row = conn.execute("SELECT * FROM case_notes WHERE id = ?",
                       (note_id,)).fetchone()
    if row is None:
        raise JournalError(f"笔记不存在: {note_id}", status=404)
    return dict(row)


def delete_note(conn: sqlite3.Connection, note_id: str,
                actor: str = "system") -> dict:
    """删除笔记:物理删(工作记录非证据);auth 无角色 → 仅本人可删,
    他人 → 403 如实;留审计(note_delete)。"""
    note = get_note(conn, note_id)
    if note["author"] != actor:
        raise JournalError("只有笔记作者本人可删除该笔记", status=403)
    with conn:
        conn.execute("DELETE FROM case_notes WHERE id = ?", (note_id,))
        db.append_audit(conn, note["case_id"], action="note_delete",
                        scope=note_id, actor=actor,
                        detail={"author": note["author"],
                                "body_len": len(note["body"])})
    return {"id": note_id, "deleted": True}


# ------------------------------------------------------------------ 合成记录流

def _scan_entry(r: sqlite3.Row) -> dict:
    """扫描轮次台账 → 自动条目(摘要有什么展示什么,未回填如实)。"""
    summary = json.loads(r["summary_json"]) if r["summary_json"] else None
    rule_ids = json.loads(r["rule_ids_json"]) if r["rule_ids_json"] else None
    n_rules = len(rule_ids) if rule_ids else None
    head = f"第 {r['round_no']} 轮扫描"
    if summary is None:
        body = "摘要未回填(扫描可能中断,如实)"      # 零静默
    else:
        parts = [
            f"跑了 {n_rules} 条规则" if n_rules is not None else "全量规则",
            f"扫描 {summary.get('scanned', 0)} 行",
            f"新增候选 {summary.get('hits_new', 0)}",
        ]
        if summary.get("truncated"):
            parts.append(f"截断 {summary['truncated']}")
        body = " | ".join(parts)
    return {
        "kind": "scan", "ts": r["created_at"], "author": r["actor"],
        "title": head, "body": body,
        "anchor": {"kind": "scan_round", "ref": str(r["round_no"])},
        "meta": {"round_no": r["round_no"], "rule_ids": rule_ids,
                 "summary": summary},
    }


def _ai_entry(r: sqlite3.Row) -> dict:
    """AI 分析台账 → 自动条目(取状态+findings 计数;没有就如实「无摘要」)。"""
    report = json.loads(r["anchors_json"]) if r["anchors_json"] else None
    windows = (report or {}).get("windows") or []
    findings = sum(w.get("findings") or 0 for w in windows)
    anchors = len((report or {}).get("anchors") or [])
    if r["error"]:
        body = f"状态 {r['status']} · 错误:{r['error']}"
    elif report is None:
        body = f"状态 {r['status']} · 无摘要"          # 如实
    else:
        body = (f"状态 {r['status']} · 锚点 {anchors} · 窗口 {len(windows)}"
                f" · findings {findings}(候选,推测·待核)")
    return {
        "kind": "ai", "ts": r["created_at"], "author": None,
        "title": "AI 分析", "body": body,
        "anchor": {"kind": "analysis_run", "ref": r["id"]},
        "meta": {"run_id": r["id"], "status": r["status"],
                 "source_id": r["source_id"], "profile": r["profile"]},
    }


def _note_entry(r: sqlite3.Row) -> dict:
    return {
        "kind": "note", "ts": r["created_at"], "author": r["author"],
        "title": "人工笔记", "body": r["body"],
        "anchor": {"kind": r["anchor_kind"], "ref": r["anchor_ref"]}
        if r["anchor_kind"] else None,
        "meta": {"note_id": r["id"]},
    }


def journal(conn: sqlite3.Connection, case_id: str, *,
            limit: int = 50, offset: int = 0) -> dict:
    """合成记录流:扫描轮次 + AI 分析 + 人工笔记,按时间倒序合并分页。

    台账为空 → 如实空流(不编造条目);同刻条目按 笔记>扫描>AI 确定性
    次序(同 ts 稳定序,避免翻页漂移)。
    """
    _check_case(conn, case_id)
    entries = [
        _scan_entry(r) for r in conn.execute(
            "SELECT * FROM scan_runs WHERE case_id = ?", (case_id,))
    ] + [
        _ai_entry(r) for r in conn.execute(
            "SELECT * FROM analysis_runs WHERE case_id = ?", (case_id,))
    ] + [
        _note_entry(r) for r in conn.execute(
            "SELECT * FROM case_notes WHERE case_id = ?", (case_id,))
    ]
    # 时间倒序;同刻按来源类确定性次序(note > scan > ai),翻页不漂移
    rank = {"note": 0, "scan": 1, "ai": 2}
    entries.sort(key=lambda e: (e["ts"], -rank[e["kind"]]), reverse=True)
    return {"total": len(entries), "limit": limit, "offset": offset,
            "items": entries[offset:offset + limit]}
