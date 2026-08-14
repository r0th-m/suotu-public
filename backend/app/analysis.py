"""L2 锚点播种 + L3 AI 精读(M3,SUOTU_DESIGN §6 四层漏斗 map-reduce)。

流程(每一环都留痕,断链即如实):
① 锚点:取该源 pending 命中(排除本模块自己的 ai-l3-finding,防自我播种);
   无锚点 → 如实「无锚点不播种」,L3 不跑,run 记 done 零 AI 调用;
② 窗口:每锚点 ±N 行(默认 200),重叠 ≥10% 合并去重,钳到 [1, 行数];
③ 精读:每窗一轮 AI(system 纪律:结论锚行号/不确定说需人工核实/只输出
   JSON);坏 JSON → 该窗如实 ai_error 不断链,后续窗口照常;
④ 综合:全部 window_note → 一段故事(同纪律);AI 出错如实记,不影响已落
   的发现;
⑤ findings → hits 待审区:rule_id="ai-l3-finding",severity=suspicion,
   detail_json={kind:"ai_finding", run_id, window, line_refs},
   **status 恒 pending,永不自动入库**(§1 判断权归人,断言级测试焊死:
   run 完成后 clues 表零新增);
⑥ 三重否定(§6 L4):AI 未见异常(无 high/medium/low finding)的窗口,
   只有当窗口内 签名未命中+统计无异常(pending/accepted 口径,rejected 是
   人已否决不再算数)才落 triple_negative 留痕;窗口有仍站立的确定性命中
   时,AI 的「干净」结论一律不落档(clean_suppressed 如实记录)——
   该窗不许写「无异常」。

档位:offline_lite(无 key)→ ③④ 跳过,报告如实标「无 AI·仅确定性播种」。
运行形态:后台线程 + GET 轮询 + abort(每窗前检查,熔断联动);同一源
running 中再发 → 409。token 预算见 ai.py(超限即停,部分结果如实保留)。

诚实边界:AI 精读只看窗口内行,窗口外上下文不可见;finding 锚点行号由 AI
给出,钳到窗口内,窗口外行号如实丢弃计数;同一窗口重跑,AI 输出不同则
命中按 (source,line,rule) 去重,不保证逐条幂等。
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from . import ai, db, query, rules

AI_RULE_ID = "ai-l3-finding"
_DEFAULT_WINDOW = 200          # L2 播种默认 ±N 行
_OVERLAP_RATIO = 0.10          # 窗口重叠 ≥10% 合并去重(§6 L2)
_PROMPT_MAX_LINES = 500        # 单窗喂给 AI 的行数上限(超了截断并如实标)
# 字符闸定位(2026-08-05 用户指正后校准):deepseek-chat 上下文 64K token,
# 扣掉 8192 输出余量,输入预算 ~50K token;日志 ~3.2 字符/token → 160k 字符。
# 闸的目的是「防超上下文 + 防注意力稀释」,不是省 token——46k token 的窗
# 装得下就不该切;多行合并块的巨窗(SmartBI 实测 46k+/窗)才拦。
_PROMPT_MAX_CHARS = 160000
_FINDING_SEVERITIES = {"high", "medium", "low", "info"}
_ANOMALY_SEVERITIES = {"high", "medium", "low"}   # AI「见到异常」的口径

# 后台线程台账(测试 join 用;进程内运行态,不入库)
_THREADS: dict[str, threading.Thread] = {}


class AnalysisError(Exception):
    """分析运行的业务校验失败,message 直给调用方。"""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ==================== L2 播种:锚点 → 窗口(重叠合并) ====================

def merge_windows(anchors: list[int], n: int,
                  line_count: int | None = None) -> list[tuple[int, int]]:
    """锚点 ±N 行 → 窗口清单;重叠 ≥10% 窗口长的相邻窗口合并去重,
    钳到 [1, line_count](line_count 未知则不钳上界)。"""
    size = 2 * n + 1
    threshold = max(1, int(size * _OVERLAP_RATIO))
    wins: list[list[int]] = []
    for a in sorted(set(anchors)):
        lo, hi = max(1, a - n), a + n
        if wins and lo <= wins[-1][1] and (wins[-1][1] - lo + 1) >= threshold:
            wins[-1][1] = max(wins[-1][1], hi)     # 重叠 ≥10%:合并
        else:
            wins.append([lo, hi])
    if line_count:
        for w in wins:
            w[1] = min(w[1], line_count)
    return [(w[0], w[1]) for w in wins]


def _pending_anchors(conn: sqlite3.Connection, case_id: str,
                     source_id: str) -> list[int]:
    """该源 pending 命中行号(排除 AI 自己的 finding,防自我播种)。"""
    return [r["line_no"] for r in conn.execute(
        "SELECT DISTINCT line_no FROM hits"
        " WHERE case_id = ? AND source_id = ? AND status = 'pending'"
        " AND rule_id != ? ORDER BY line_no",
        (case_id, source_id, AI_RULE_ID))]


# ==================== L3 精读:窗口 → findings(坏 JSON 不断链) ====================

def _parse_ai_json(content: str | None) -> dict | None:
    """AI 输出 → JSON 对象;容忍 ```json 围栏与前后杂音,解析不了 → None。"""
    if not content:
        return None
    text = content.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if m:
        text = m.group(1)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            obj = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
    return obj if isinstance(obj, dict) else None


def _validate_findings(obj: dict) -> tuple[list[dict], int]:
    """findings 逐项校验:坏项跳过并计数(零静默);line_refs 归一成 int 列表。"""
    raw = obj.get("findings")
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        return [], 1
    out: list[dict] = []
    skipped = 0
    for f in raw:
        if not isinstance(f, dict) or \
                not isinstance(f.get("summary"), str) or not f["summary"].strip() or \
                f.get("suspicion") not in _FINDING_SEVERITIES:
            skipped += 1
            continue
        refs = f.get("line_refs") or []
        if not isinstance(refs, list):
            refs = []
        refs = [r for r in refs
                if isinstance(r, int) and not isinstance(r, bool)]
        out.append({"summary": f["summary"].strip(),
                    "suspicion": f["suspicion"], "line_refs": refs})
    return out, skipped


def _pick_line(conn: sqlite3.Connection, source_id: str, refs: list[int],
               win: tuple[int, int], fallback: int) -> int:
    """finding 锚点行号:窗口内首个未被 (源,行,rule) 占用的 line_ref;
    都被占/越窗 → fallback(窗口锚点行)再避让。"""
    used = {r["line_no"] for r in conn.execute(
        "SELECT line_no FROM hits WHERE source_id = ? AND rule_id = ?",
        (source_id, AI_RULE_ID))}
    in_win = [r for r in refs if win[0] <= r <= win[1]]
    for r in in_win + [fallback]:
        if r not in used:
            return r
    return fallback                                   # 兜底:INSERT OR IGNORE 幂等


def _insert_finding_hit(conn: sqlite3.Connection, case_id: str, source_id: str,
                        line_no: int, severity: str, summary: str,
                        detail: dict) -> bool:
    """finding → hits 待审区(status 恒 pending;UNIQUE 去重幂等)。
    返回是否实际新增。"""
    cur = conn.execute(
        "INSERT OR IGNORE INTO hits (id, case_id, source_id, line_no, rule_id,"
        " severity, matched_field, matched_value, snippet, ts_utc, status,"
        " created_at, detail_json) VALUES (?,?,?,?,?,?,?,?,?,NULL,'pending',?,?)",
        (uuid.uuid4().hex, case_id, source_id, line_no, AI_RULE_ID, severity,
         "ai_finding", severity, summary[:300], _now(),
         json.dumps(detail, ensure_ascii=False)))
    return cur.rowcount > 0


def _window_deterministic_state(conn: sqlite3.Connection, case_id: str,
                                source_id: str, win: tuple[int, int],
                                sig_ids: set[str],
                                stat_ids: set[str]) -> tuple[bool, bool]:
    """窗口内仍站立(pending/accepted)的确定性命中:(有签名命中, 有统计异常)。

    rejected 是人已否决,不再算数(三重否定才可能成立——判断权归人);
    AI 自己的 finding 不算(防自我引用)。
    """
    rows = conn.execute(
        "SELECT DISTINCT rule_id FROM hits"
        " WHERE case_id = ? AND source_id = ? AND line_no BETWEEN ? AND ?"
        " AND status IN ('pending','accepted') AND rule_id != ?",
        (case_id, source_id, win[0], win[1], AI_RULE_ID)).fetchall()
    ids = {r["rule_id"] for r in rows}
    return bool(ids & sig_ids), bool(ids & stat_ids)


# ==================== 运行:后台线程 + 状态轮询 + abort ====================

def start_analysis(conn: sqlite3.Connection, case_id: str, source_id: str,
                   window_lines: int = _DEFAULT_WINDOW,
                   background: bool = True, actor: str = "system",
                   budget: int | None = None) -> dict:
    """发起 L2+L3 分析 run;同一源 running 中再发 → 409。

    background=False 供测试同步执行(生产 API 一律后台)。
    budget:本次 run 的 token 预算快照;None=环境缺省,0=不限
    (用户显式选择;循环检测与用户中断两条保险不受影响)。
    """
    if conn.execute("SELECT 1 FROM cases WHERE id = ?",
                    (case_id,)).fetchone() is None:
        raise AnalysisError(f"案件不存在: {case_id}", status=404)
    src = conn.execute("SELECT id, line_count FROM log_sources WHERE id = ?",
                       (source_id,)).fetchone()
    if src is None or conn.execute(
            "SELECT 1 FROM log_sources WHERE id = ? AND case_id = ?",
            (source_id, case_id)).fetchone() is None:
        raise AnalysisError(f"日志源不存在或不属于本案件: {source_id}",
                            status=404)
    if not isinstance(window_lines, int) or isinstance(window_lines, bool) \
            or not 1 <= window_lines <= 2000:
        raise AnalysisError("window_lines 须为 1..2000 的整数")
    if budget is not None and (not isinstance(budget, int)
                               or isinstance(budget, bool) or budget < 0):
        raise AnalysisError("budget 须为 ≥0 的整数(0=不限)")
    if conn.execute(
            "SELECT 1 FROM analysis_runs WHERE source_id = ?"
            " AND status = 'running'", (source_id,)).fetchone():
        raise AnalysisError("该日志源已有 running 中的分析 run,先去重等待"
                            "或 abort 后再发起", status=409)
    run_id = uuid.uuid4().hex
    effective_budget = budget if budget is not None else ai.token_budget()
    with conn:
        conn.execute(
            "INSERT INTO analysis_runs (id, case_id, source_id, status,"
            " profile, anchors_json, budget, usage_json, tool_log_json,"
            " created_at) VALUES (?,?,?,'running',?,?,?,?,?,?)",
            (run_id, case_id, source_id, ai.profile(), None,
             effective_budget, None, None, _now()))
        db.append_audit(conn, case_id, action="analysis_run", scope=run_id,
                        actor=actor,
                        detail={"source_id": source_id,
                                "window_lines": window_lines,
                                "profile": ai.profile()})
    if background:
        t = threading.Thread(target=_execute, args=(run_id, window_lines),
                             daemon=True)
        _THREADS[run_id] = t
        t.start()
    else:
        _execute(run_id, window_lines)
    return {"run_id": run_id, "status": "running"}


def abort_run(conn: sqlite3.Connection, run_id: str,
              actor: str = "system") -> dict:
    """用户中断:running → aborted(执行线程每窗前检查,熔断联动)。"""
    row = conn.execute("SELECT status, case_id FROM analysis_runs"
                       " WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise AnalysisError(f"分析 run 不存在: {run_id}", status=404)
    if row["status"] != "running":
        raise AnalysisError(f"run 已是 {row['status']} 状态,不能中断",
                            status=409)
    with conn:
        conn.execute("UPDATE analysis_runs SET status = 'aborted'"
                     " WHERE id = ?", (run_id,))
        db.append_audit(conn, row["case_id"], action="analysis_abort",
                        scope=run_id, actor=actor)
    return {"run_id": run_id, "status": "aborted"}


def get_run(run_id: str) -> dict:
    """run 状态视图(轮询用):JSON 列解析 + 派生说明(无锚点/降级如实)。"""
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?",
                           (run_id,)).fetchone()
        if row is None:
            raise AnalysisError(f"分析 run 不存在: {run_id}", status=404)
        out = dict(row)
    finally:
        conn.close()
    report = json.loads(out["anchors_json"]) if out["anchors_json"] else None
    out["report"] = report
    out["usage"] = json.loads(out["usage_json"]) if out["usage_json"] else None
    out["tool_log"] = json.loads(out["tool_log_json"]) \
        if out["tool_log_json"] else []
    for k in ("anchors_json", "usage_json", "tool_log_json"):
        out.pop(k, None)
    # 派生如实说明(报告里没有结构化 note 时按状态补)
    if report is None and out["status"] == "running":
        out["note"] = "运行中"
    elif report and report.get("note"):
        out["note"] = report["note"]
    else:
        out["note"] = None
    return out


def list_runs(case_id: str) -> dict:
    """案件的 L3 分析 run 列表(新→旧)。

    M5 起 analysis_runs 复用为交流区 chat run 台账(source_id=NULL);
    本列表只出 L3 分析 run(source_id 非空),chat run 不混入。
    """
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id, case_id, source_id, status, profile, budget, error,"
            " created_at, finished_at FROM analysis_runs WHERE case_id = ?"
            " AND source_id IS NOT NULL"
            " ORDER BY created_at DESC", (case_id,)).fetchall()
        return {"total": len(rows), "items": [dict(r) for r in rows]}
    finally:
        conn.close()


def recover_zombie_runs() -> int:
    """启动时清理僵尸 run:status='running' 但执行线程已随上个进程死亡
    (daemon 线程被进程退出强杀,run 永远卡 running 且 409 挡住新 run
    ——2026-08-05 实测)。一律标 failed(原因如实),返回清理数;
    全部 case 扫一遍(分析 run 是进程内产物,重启即不可恢复)。"""
    conn = db.connect()
    try:
        with conn:
            cur = conn.execute(
                "UPDATE analysis_runs SET status = 'failed',"
                " error = '进程退出/重启,执行线程死亡,run 中断(可重新发起)',"
                " finished_at = ? WHERE status = 'running'", (_now(),))
            n = cur.rowcount
            if n:
                rows = conn.execute(
                    "SELECT DISTINCT case_id FROM analysis_runs"
                    " WHERE status = 'failed'"
                    " AND error LIKE '进程退出/重启%'").fetchall()
                for r in rows:
                    db.append_audit(
                        conn, r["case_id"], action="analysis_zombie_recover",
                        detail={"recovered": n})
        return n
    finally:
        conn.close()


# ==================== 执行体(②③④⑤⑥ 全链路) ====================

def _finish(conn: sqlite3.Connection, run_id: str, status: str,
            report: dict, error: str | None) -> None:
    """收尾:报告落 run + 审计;abort 场景保留 aborted 状态不被盖回。"""
    with conn:
        if status == "aborted":
            conn.execute(
                "UPDATE analysis_runs SET anchors_json = ?, error = ?,"
                " finished_at = ? WHERE id = ? AND status = 'aborted'",
                (json.dumps(report, ensure_ascii=False), error, _now(),
                 run_id))
        else:
            conn.execute(
                "UPDATE analysis_runs SET status = ?, anchors_json = ?,"
                " error = ?, finished_at = ? WHERE id = ?",
                (status, json.dumps(report, ensure_ascii=False), error,
                 _now(), run_id))
        run = conn.execute("SELECT case_id FROM analysis_runs WHERE id = ?",
                           (run_id,)).fetchone()
        db.append_audit(conn, run["case_id"], action="analysis_finish",
                        scope=run_id, actor="ai",
                        detail={"status": status, "error": error,
                                "windows": len(report.get("windows") or []),
                                "anchors": len(report.get("anchors") or [])})


def _execute(run_id: str, window_lines: int) -> None:
    """run 执行体(后台线程或测试同步);任何异常 → failed 如实,不炸线程。"""
    conn = db.connect()
    try:
        run = conn.execute("SELECT * FROM analysis_runs WHERE id = ?",
                           (run_id,)).fetchone()
        case_id, source_id = run["case_id"], run["source_id"]
        profile = run["profile"]
        report: dict = {"anchors": [], "window_lines": window_lines,
                        "windows": [], "synthesis": None,
                        "synthesis_error": None, "note": None,
                        "budget_exceeded": False}

        # ---- ① 锚点(L1 产物;无锚点不播种,L3 不跑,如实) ----
        anchors = _pending_anchors(conn, case_id, source_id)
        report["anchors"] = anchors
        if not anchors:
            report["note"] = ("无锚点不播种:该源无 pending 命中,"
                              "L2 切片与 L3 精读未执行")
            _finish(conn, run_id, "done", report, None)
            return

        # ---- ② 窗口(重叠 ≥10% 合并,钳到行数) ----
        src = conn.execute("SELECT line_count FROM log_sources WHERE id = ?",
                           (source_id,)).fetchone()
        windows = merge_windows(anchors, window_lines, src["line_count"])
        anchor_set = sorted(anchors)
        for w_from, w_to in windows:
            report["windows"].append({
                "from": w_from, "to": w_to,
                "anchors": [a for a in anchor_set if w_from <= a <= w_to],
                "status": "pending", "findings": 0})

        # 关联强度排序(2026-08-14,SAG 式 PageRank):窗口按锚点强度降序,
        # 强关联先吃 token;无实体联动数据时自然回退行号序。
        _scores = query.entity_linkage_scores(case_id, source_id)
        if _scores:
            for w in report["windows"]:
                w["linkage_score"] = round(max(
                    (_scores.get((source_id, a), 0.0) for a in w["anchors"]),
                    default=0.0), 6)
            report["windows"].sort(key=lambda w: -w["linkage_score"])

        # 确定性命中分类(三重否定口径):签名规则 id 集 / 统计+跨源 id 集
        sig_ids = {r["id"] for r in rules.load_rules()}
        stat_ids = {r["id"] for r in rules.load_stat_rules()}
        stat_ids.add(rules.CROSS_SOURCE_RULE["id"])

        # ---- offline_lite:③④ 跳过,如实标「无 AI·仅确定性播种」 ----
        if profile != "online":
            for w in report["windows"]:
                w["status"] = "skipped_offline"
            report["note"] = ("无 AI·仅确定性播种(offline_lite):"
                              "L3 精读与综合 pass 未执行;窗口与锚点已留档,"
                              "配置 AI 后可重跑")
            _finish(conn, run_id, "done", report, None)
            return

        # ---- ③ 每窗一轮 AI 精读(map) ----
        ai_failed: str | None = None
        for w in report["windows"]:
            if ai.is_aborted(run_id):          # abort 联动,每窗前检查
                _finish(conn, run_id, "aborted", report,
                        "用户中断,已完成窗口如实保留")
                return
            win = (w["from"], w["to"])
            data = query.read_window(source_id, win[0], win[1])
            lines = data["lines"]
            # 双闸截断:行数闸 + 字符闸(多行合并块让行数闸失效,实测)
            shown = lines[:_PROMPT_MAX_LINES]
            total_chars = 0
            cut_at = len(shown)
            for i, l in enumerate(shown):
                total_chars += len(l["raw"]) + 10
                if total_chars > _PROMPT_MAX_CHARS:
                    cut_at = i
                    break
            shown = shown[:cut_at]
            w["prompt_truncated"] = (len(lines) > len(shown))
            if w["prompt_truncated"]:
                w["prompt_truncated_by"] = (
                    "chars" if len(shown) < min(len(lines), _PROMPT_MAX_LINES)
                    else "lines")
            user = (f"日志源 {source_id} 第 {win[0]}~{win[1]} 行"
                    f"(共 {len(lines)} 行"
                    + (f",仅展示前 {len(shown)} 行"
                       f"(行数/字符双闸,约 {total_chars} 字符)"
                       if w["prompt_truncated"] else "") + "):\n"
                    + "\n".join(f"L{l['line_no']}: {l['raw']}"
                                for l in shown))
            try:
                result = ai.chat(
                    [{"role": "system", "content": ai.SYSTEM_PROMPT_L3},
                     {"role": "user", "content": user}],
                    run_id=run_id)
            except ai.CircuitStop as e:        # token 预算超限:即停,如实标
                report["budget_exceeded"] = True
                w["status"] = "ai_error"
                w["ai_error"] = str(e)
                report["note"] = (f"token 预算耗尽(budget_exceeded),"
                                  f"第 {win[0]}~{win[1]} 行窗口起停止,"
                                  "已完成窗口如实保留")
                break
            except ai.AIError as e:            # 服务级失败:留痕并止损
                ai_failed = f"AI 调用失败(kind={e.kind}): {e}"
                w["status"] = "ai_error"
                w["ai_error"] = ai_failed
                break
            obj = _parse_ai_json(result["content"])
            if obj is None:                    # 坏 JSON:该窗 ai_error,不断链
                w["status"] = "ai_error"
                w["ai_error"] = ("AI 输出非合法 JSON,本窗如实记 ai_error;"
                                 "原始输出已按纪律不入库")
                continue
            findings, skipped = _validate_findings(obj)
            w["window_note"] = obj.get("window_note") \
                if isinstance(obj.get("window_note"), str) else None
            if skipped:
                w["skipped_findings"] = skipped   # 坏项跳过计数,零静默
            # ⑤ findings → hits 待审区(恒 pending,永不自动入库)
            for f in findings:
                line_no = _pick_line(conn, source_id, f["line_refs"], win,
                                     w["anchors"][0])
                out_of_win = len([r for r in f["line_refs"]
                                  if not (win[0] <= r <= win[1])])
                detail = {"kind": "ai_finding", "run_id": run_id,
                          "window": {"from": win[0], "to": win[1]},
                          "line_refs": f["line_refs"],
                          "out_of_window_refs": out_of_win or None,
                          "triple_negative": False}
                if _insert_finding_hit(conn, case_id, source_id, line_no,
                                       f["suspicion"], f["summary"], detail):
                    w["findings"] += 1
            conn.commit()
            # ⑥ 三重否定:AI 未见异常 → 三路齐全才落留痕,否则不许写「无异常」
            if not any(f["suspicion"] in _ANOMALY_SEVERITIES
                       for f in findings):
                has_sig, has_stat = _window_deterministic_state(
                    conn, case_id, source_id, win, sig_ids, stat_ids)
                if not has_sig and not has_stat:
                    anchor = w["anchors"][0]
                    _insert_finding_hit(
                        conn, case_id, source_id, anchor, "info",
                        "三重否定留痕:本窗口签名未命中 + 统计无异常 + "
                        "AI 未见异常(锚点行号为该窗播种锚点)",
                        {"kind": "ai_finding", "run_id": run_id,
                         "window": {"from": win[0], "to": win[1]},
                         "line_refs": [anchor], "triple_negative": True})
                    w["triple_negative"] = True
                    conn.commit()
                else:
                    w["clean_suppressed"] = True   # 有确定性命中,不落「干净」
                    w["suppress_note"] = (
                        "窗口内仍有站立的确定性命中(签名/统计),AI 的"
                        "「未见异常」结论不予落档(三重否定纪律)")
            w["status"] = "done"

        # ---- ④ 综合 pass(全部 window_note → 一段故事,同纪律) ----
        notes = [f"窗口 L{w['from']}~L{w['to']}: {w['window_note']}"
                 for w in report["windows"]
                 if w.get("status") == "done" and w.get("window_note")]
        if notes and not report["budget_exceeded"] and ai_failed is None \
                and not ai.is_aborted(run_id):
            try:
                synth = ai.chat(
                    [{"role": "system", "content": ai.SYSTEM_PROMPT_SYNTH},
                     {"role": "user", "content": "\n".join(notes)}],
                    run_id=run_id)
                report["synthesis"] = synth["content"]
            except ai.CircuitStop as e:
                report["budget_exceeded"] = True
                report["synthesis_error"] = str(e)
            except ai.AIError as e:
                report["synthesis_error"] = f"kind={e.kind}: {e}"
        elif not notes and not report["budget_exceeded"] and ai_failed is None:
            report["synthesis_error"] = ("无可综合的 window_note"
                                         "(全部窗口 ai_error 或无摘要),"
                                         "综合 pass 如实跳过")

        if ai_failed is not None:
            _finish(conn, run_id, "failed", report,
                    ai_failed + ";已完成窗口如实保留")
        elif ai.is_aborted(run_id):
            _finish(conn, run_id, "aborted", report,
                    "用户中断,已完成窗口如实保留")
        else:
            if report["note"] is None:
                done_n = sum(1 for w in report["windows"]
                             if w["status"] == "done")
                err_n = sum(1 for w in report["windows"]
                            if w["status"] == "ai_error")
                report["note"] = (f"L3 精读完成:{done_n} 窗成功"
                                  + (f",{err_n} 窗 ai_error(如实)" if err_n
                                     else ""))
            _finish(conn, run_id, "done", report, None)
    except Exception as e:                            # 零静默:未知异常 → failed
        try:
            _finish(conn, run_id, "failed",
                    {"anchors": [], "windows": [], "note": None},
                    f"run 内部错误({type(e).__name__}): {e}")
        except Exception:
            pass
    finally:
        conn.close()
        _THREADS.pop(run_id, None)
