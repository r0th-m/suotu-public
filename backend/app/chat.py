"""交流区(M5,人机对话,SUOTU_DESIGN §1/§4.6/§6.1)。

纪律:
- **不做词典抽词截流**(主机取证平台教训:快分析能查到、交流区 AI 查不到,根因是
  词典门后的数据 AI 结构性不可见)——system 上下文只放案件概况(源清单
  +各源行数/状态)与 pending hits Top10 摘要两块确定性摘要,其余一切数据
  由 AI 自己调工具拿(数据面五件套 + 模块状态五件,全经 §4.6 单一检索层
  与模块只读视图;契约测试焊死「每个模块的产物至少一条工具可达路径」);
- from_hit_id 追问模式:建会话时指定命中,该命中详情+锚点注入 system
  上下文(主机取证平台 from_analysis 交接棒同款思想);
- 熔断复用 ai.run_agent 现有四条(轮数/调用/预算/循环)+ abort:每轮问答
  建一条 analysis_runs 台账行(source_id=NULL=案件作用域),usage 累进/
  预算闸/工具台账全走 ai.py 既有机制;usage/tool_log 快照随 AI 回答落
  chat_messages(run 行仍是权威留痕);
- AI 产物不落任何业务表(§1 判断权归人):回答只是消息,断言级测试焊死
  「问答后 clues/hits 零新增」;AI 回答提及某 hit,人也只能去待审区走
  既有 hits accept 路径;
- offline_lite 诚实降级:如实回答「无 AI 档,可用检索/规则代替」,不臆造;
  人消息照留痕。
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from . import ai, db

# 交流区 system 提示纪律:先查再答/锚点齐全/不确定说需人工核实/无入库路径
SYSTEM_PROMPT_CHAT = (
    "你是应急日志分析工作台「索图」的交流区助手,协助分析师研判案件日志。\n"
    "纪律(必须严格遵守):\n"
    "1. 先查再答:你可以调用工具读取本案件的全部数据——日志检索/字段统计/"
    "实体反查/时间窗/原文段(数据面),以及源清单/待审命中/已入库线索/"
    "分析 run/KB 解释(各模块状态)。工具没给的信息就说「未查到」,绝不臆造。\n"
    "2. 你的所有推断都属「AI 推测·待核」:推断用「疑似/需人工核实」措辞,"
    "引用日志必须带锚点(源 id + 行号)。\n"
    "3. 你没有任何入库路径:认为某条命中值得入库时,只能提示人去待审区"
    "人工 accept,不得宣称已入库。"
)

_HISTORY_MAX = 10          # 带入上下文的最近问答轮数
_PENDING_HITS_TOP = 10     # system 上下文待审命中摘要条数
_TITLE_LEN = 30            # 首条消息自动命名截断长度

# 熔断停机原因 → 给人看的如实说明(附加在回答末尾)
_STOP_NOTES = {
    ai.STOP_ROUND_LIMIT: "工具调度轮数达上限,本轮提前收尾",
    ai.STOP_TOOL_CALL_LIMIT: "工具调用次数达上限,本轮提前收尾",
    ai.STOP_BUDGET: "token 预算耗尽,本轮提前收尾",
    ai.STOP_LOOP: "检测到重复工具调用(循环),已主动停机防烧钱",
    ai.STOP_ABORTED: "用户中断",
}

# 「转线索」提示位:只指路,入库只能人走既有 hits accept 路径(§1)
SUGGEST_REVIEW = {
    "prompt": "回答为 AI 推测·待核;若提及的命中值得入库,请到待审区人工"
              " accept(clues 唯一写入路径)",
    "action": "POST /hits/{hit_id}:accept",
}

_OFFLINE_ANSWER = (
    "当前档位无 AI(offline_lite,未配置 API key):交流区 AI 助手不可用,"
    "你的问题已留痕。\n"
    "确定性功能不受 AI 档影响,可改用:日志检索(/search)、规则扫描"
    "(rules:run)、字段统计(/stats)、即席聚合(/aggregate)、KB 解释"
    "(/kb/explain)——以上全部为确定性结果,非 AI 推测。"
)


class ChatError(Exception):
    """交流区业务校验失败,status + message 直给路由层。"""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cut(text: object, n: int = 200) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= n else s[:n] + "…"


def _get_session(conn: sqlite3.Connection, session_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM chat_sessions WHERE id = ?",
                       (session_id,)).fetchone()
    if row is None:
        raise ChatError(f"会话不存在: {session_id}", status=404)
    return row


# ==================== 会话 CRUD ====================

def create_session(conn: sqlite3.Connection, case_id: str, *,
                   title: str | None = None,
                   from_hit_id: str | None = None,
                   actor: str = "system") -> dict:
    """建会话;from_hit_id=追问模式(命中必须存在且属本案,防串味)。"""
    if conn.execute("SELECT 1 FROM cases WHERE id = ?",
                    (case_id,)).fetchone() is None:
        raise ChatError(f"案件不存在: {case_id}", status=404)
    if from_hit_id is not None:
        hit = conn.execute("SELECT case_id FROM hits WHERE id = ?",
                           (from_hit_id,)).fetchone()
        if hit is None:
            raise ChatError(f"命中不存在: {from_hit_id}", status=404)
        if hit["case_id"] != case_id:
            raise ChatError(f"命中 {from_hit_id} 不属于本案件(防串味)")
    if title is not None:
        title = title.strip() or None
    sid = uuid.uuid4().hex
    now = _now()
    with conn:
        conn.execute(
            "INSERT INTO chat_sessions (id, case_id, title, from_hit_id,"
            " created_at) VALUES (?,?,?,?,?)",
            (sid, case_id, title, from_hit_id, now))
        db.append_audit(conn, case_id, action="chat_session_create",
                        scope=sid, actor=actor,
                        detail={"from_hit_id": from_hit_id})
    return {"id": sid, "case_id": case_id, "title": title,
            "from_hit_id": from_hit_id, "created_at": now}


def list_sessions(conn: sqlite3.Connection, case_id: str) -> dict:
    """会话列表(新→旧,带消息数)。"""
    rows = conn.execute(
        "SELECT s.*, (SELECT COUNT(*) FROM chat_messages m"
        " WHERE m.session_id = s.id) AS message_count"
        " FROM chat_sessions s WHERE s.case_id = ?"
        " ORDER BY s.created_at DESC, s.id", (case_id,)).fetchall()
    return {"items": [dict(r) for r in rows]}


def get_messages(conn: sqlite3.Connection, session_id: str) -> dict:
    """会话消息(旧→新);tool_log/usage 出库即解析(快照,权威在 run 行)。"""
    _get_session(conn, session_id)
    rows = conn.execute(
        "SELECT * FROM chat_messages WHERE session_id = ?"
        " ORDER BY ts, rowid", (session_id,)).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["tool_log"] = json.loads(d.pop("tool_log_json")) \
            if d.get("tool_log_json") else None
        d["usage"] = json.loads(d.pop("usage_json")) \
            if d.get("usage_json") else None
        items.append(d)
    return {"session_id": session_id, "items": items}


def _store_message(conn: sqlite3.Connection, session_id: str, role: str,
                   content: str, tool_log: list | None = None,
                   usage: dict | None = None) -> dict:
    """落一条消息(留痕,非业务入库)。"""
    mid = uuid.uuid4().hex
    ts = _now()
    with conn:
        conn.execute(
            "INSERT INTO chat_messages (id, session_id, role, content,"
            " tool_log_json, usage_json, ts) VALUES (?,?,?,?,?,?,?)",
            (mid, session_id, role, content,
             json.dumps(tool_log, ensure_ascii=False)
             if tool_log is not None else None,
             json.dumps(usage, ensure_ascii=False)
             if usage is not None else None, ts))
    return {"id": mid, "session_id": session_id, "role": role,
            "content": content, "ts": ts}


# ==================== system 上下文组装(确定性摘要,无词典门) ====================

def _case_overview(conn: sqlite3.Connection, case_id: str) -> str:
    """案件概况:案件名 + 源清单(各源 行数/状态/格式/时间范围)。"""
    case = conn.execute("SELECT name FROM cases WHERE id = ?",
                        (case_id,)).fetchone()
    sources = conn.execute(
        "SELECT id, name, log_type, format_id, status, line_count,"
        " time_range FROM log_sources WHERE case_id = ?"
        " ORDER BY created_at", (case_id,)).fetchall()
    lines = [f"案件:{case['name'] if case else '?'} (id={case_id})"]
    if not sources:
        lines.append("日志源:(无——尚未登记任何日志源,如实)")
    else:
        lines.append("日志源清单:")
        for s in sources:
            lines.append(
                f"  · {s['name']} id={s['id']} 类型={s['log_type']}"
                f" 格式={s['format_id']} 状态={s['status']}"
                f" 行数={s['line_count']} 时间范围={s['time_range']}")
    return "\n".join(lines)


def _pending_hits_digest(conn: sqlite3.Connection, case_id: str,
                         top: int = _PENDING_HITS_TOP) -> str:
    """pending 命中 Top 摘要(规则/统计/AI 精读产物全在待审区,一视同仁)。"""
    rows = conn.execute(
        "SELECT id, rule_id, severity, source_id, line_no, snippet"
        " FROM hits WHERE case_id = ? AND status = 'pending'"
        " ORDER BY created_at, id LIMIT ?", (case_id, top)).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) AS c FROM hits WHERE case_id = ?"
        " AND status = 'pending'", (case_id,)).fetchone()["c"]
    if not rows:
        return "待审命中:0 条(待审区为空,如实)"
    lines = [f"待审命中 Top{len(rows)}(共 {total} 条,均未入库、人未审核,"
             "完整清单用 list_hits 工具查):"]
    for h in rows:
        lines.append(f"  · [{h['severity']}] {h['rule_id']}"
                     f" 源={h['source_id']} 行={h['line_no']}"
                     f" hit_id={h['id']} 摘要={_cut(h['snippet'], 120)}")
    return "\n".join(lines)


def _hit_followup(conn: sqlite3.Connection, hit_id: str) -> str:
    """追问注入:该命中的完整详情 + 锚点(建会话时 from_hit_id 指定)。"""
    hit = conn.execute("SELECT * FROM hits WHERE id = ?",
                       (hit_id,)).fetchone()
    if hit is None:                       # 命中被删(理论不应发生):如实标注
        return f"【追问锚点】命中 {hit_id} 已不存在(如实)。"
    detail = json.loads(hit["detail_json"]) if hit["detail_json"] else None
    lines = [
        "【追问锚点:本会话围绕以下命中展开】",
        f"  hit_id={hit['id']} 规则={hit['rule_id']}"
        f" severity={hit['severity']} 状态={hit['status']}",
        f"  锚点:源={hit['source_id']} 行={hit['line_no']}"
        f" ts_utc={hit['ts_utc']}",
        f"  命中:{hit['matched_field']} 含「{hit['matched_value']}」",
        f"  原文摘要:{_cut(hit['snippet'], 300)}",
    ]
    if detail is not None:
        lines.append(f"  结构化细节:{_cut(json.dumps(detail, ensure_ascii=False), 500)}")
    lines.append("  (上下文用 read_window/time_slice 工具按锚点行号取原文段)")
    return "\n".join(lines)


def _build_system(conn: sqlite3.Connection, sess: sqlite3.Row) -> str:
    """system 上下文 = 提示纪律 + 案件概况 + pending hits 摘要 + 追问注入。"""
    parts = [SYSTEM_PROMPT_CHAT,
             "\n【案件概况】\n" + _case_overview(conn, sess["case_id"]),
             "\n【" + _pending_hits_digest(conn, sess["case_id"]) + "】"]
    if sess["from_hit_id"]:
        parts.append("\n" + _hit_followup(conn, sess["from_hit_id"]))
    return "\n".join(parts)


# ==================== 发消息(人消息落库 → run_agent → AI 回答落库) ====================

def _create_chat_run(conn: sqlite3.Connection, case_id: str) -> str:
    """本轮问答的 AI run 台账行(source_id=NULL=案件作用域;熔断四条挂它)。"""
    run_id = uuid.uuid4().hex
    with conn:
        conn.execute(
            "INSERT INTO analysis_runs (id, case_id, source_id, status,"
            " profile, budget, created_at) VALUES (?,?,NULL,'running',?,?,?)",
            (run_id, case_id, ai.profile(), ai.token_budget(), _now()))
    return run_id


def _finish_chat_run(conn: sqlite3.Connection, run_id: str, status: str,
                     error: str | None = None) -> tuple[dict | None, list]:
    """收尾 chat run(done/failed 如实),返回 (usage 快照, tool_log 快照)。"""
    with conn:
        conn.execute(
            "UPDATE analysis_runs SET status = ?, error = ?, finished_at = ?"
            " WHERE id = ? AND status = 'running'",
            (status, error, _now(), run_id))
    row = conn.execute(
        "SELECT usage_json, tool_log_json FROM analysis_runs WHERE id = ?",
        (run_id,)).fetchone()
    usage = json.loads(row["usage_json"]) if row["usage_json"] else None
    tool_log = json.loads(row["tool_log_json"]) if row["tool_log_json"] else []
    return usage, tool_log


def post_message(conn: sqlite3.Connection, session_id: str, content: str,
                 actor: str = "system") -> dict:
    """人消息落库 → AI 回答(或诚实降级)→ 回答落库(含 tool_log/usage 快照)。

    AI 产物不落任何业务表:回答只是消息;转线索只有人走 hits accept(§1)。
    """
    sess = _get_session(conn, session_id)
    question = (content or "").strip()
    if not question:
        raise ChatError("content 必填且为非空字符串")
    case_id = sess["case_id"]

    # 历史(落库前取,不含本条):最近 N 轮,旧→新
    history = [{"role": r["role"], "content": r["content"]} for r in
               conn.execute(
                   "SELECT role, content FROM chat_messages"
                   " WHERE session_id = ? ORDER BY ts DESC, rowid DESC"
                   " LIMIT ?", (session_id, _HISTORY_MAX)).fetchall()][::-1]

    user_msg = _store_message(conn, session_id, "user", question)
    if sess["title"] is None:             # 首条消息截 30 字自动命名
        with conn:
            conn.execute("UPDATE chat_sessions SET title = ? WHERE id = ?",
                         (question[:_TITLE_LEN], session_id))

    # ---- offline_lite:诚实降级,不臆造(人不空等,功能指路) ----
    if not ai.ai_available():
        asst_msg = _store_message(conn, session_id, "assistant",
                                  _OFFLINE_ANSWER)
        return {"session_id": session_id, "case_id": case_id,
                "profile": ai.profile(), "label": "无 AI 档·诚实降级",
                "answer": _OFFLINE_ANSWER, "stop_reason": None,
                "usage": None, "tool_log": [],
                "user_message": user_msg, "assistant_message": asst_msg,
                "suggest_review": SUGGEST_REVIEW}

    # ---- online:run_agent(熔断四条 + abort 全复用 ai.py 既有机制) ----
    run_id = _create_chat_run(conn, case_id)
    messages = ([{"role": "system", "content": _build_system(conn, sess)}]
                + history
                + [{"role": "user", "content": question}])
    stop_reason = None
    try:
        result = ai.run_agent(run_id, messages)
        stop_reason = result["stop_reason"]
        answer = result["content"]
        if stop_reason != ai.STOP_COMPLETED:
            note = _STOP_NOTES.get(stop_reason, stop_reason)
            answer = (answer + "\n\n" if answer else "") + \
                f"[熔断停机:{note};已发生的工具调用见 tool_log,如实保留]"
        if not answer:
            answer = (f"AI 未产出最终回答(停机原因:{stop_reason} 如实);"
                      "已发生的工具调用见 tool_log。")
        usage, tool_log = _finish_chat_run(conn, run_id, "done")
    except ai.AIError as e:               # 服务级失败:诚实降级,不 500
        answer = (f"AI 调用失败(kind={e.kind}):{e}。本轮未产出回答;"
                  "确定性功能(检索/规则/统计/聚合)不受影响。")
        usage, tool_log = _finish_chat_run(conn, run_id, "failed", str(e))
    asst_msg = _store_message(conn, session_id, "assistant", answer,
                              tool_log=tool_log, usage=usage)
    return {"session_id": session_id, "case_id": case_id,
            "profile": ai.profile(), "label": "AI 推测·待核",
            "answer": answer, "stop_reason": stop_reason,
            "usage": usage, "tool_log": tool_log,
            "user_message": user_msg, "assistant_message": asst_msg,
            "suggest_review": SUGGEST_REVIEW}
