import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api.js";

// AI 分析区(M3):L2 播种 + L3 精读的发起、运行监控、报告与历史,外加 KB 解释小工具。
// 文案纪律(§1/§6):AI 产物=候选(推测·待核),一律进待审区,判断权归人;
// AI 可关——offline_lite 时诚实降级为「仅确定性播种」,界面如实标明。
export default function AiPane({ caseDetail, aiStatus, onGotoReview, onFindingsChanged, aiInit, onAiInitConsumed }) {
  const sources = caseDetail.sources || [];
  const parsedSources = sources.filter((s) => s.status === "parsed");
  const nameOf = (id) => sources.find((s) => s.id === id)?.name || id;
  const offline = !aiStatus || aiStatus.profile !== "online";

  const [sourceId, setSourceId] = useState("");
  const [budget, setBudget] = useState("");   // 空=缺省 50 万;0=不限
  const [busy, setBusy] = useState(false);
  const [runError, setRunError] = useState(null);
  const [run, setRun] = useState(null); // 当前查看的 run(轮询对象)
  const [runs, setRuns] = useState(null); // 历史列表
  const pollRef = useRef(null);

  const loadRuns = useCallback(async () => {
    try {
      const r = await api.listAnalysis(caseDetail.id);
      setRuns(r.items || []);
    } catch {
      /* 历史列表失败不打断主流程 */
    }
  }, [caseDetail.id]);

  // 换案件:清空当前 run/选项,重拉历史
  useEffect(() => {
    setRun(null);
    setSourceId("");
    setRunError(null);
    loadRuns();
  }, [loadRuns]);

  // 轮询:当前 run running 时每 2.5s 拉一次;转终态后刷历史与待审计数
  useEffect(() => {
    if (!run || run.status !== "running") {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }
    pollRef.current = setInterval(async () => {
      try {
        const r = await api.getAnalysis(run.id);
        setRun(r);
        if (r.status !== "running") {
          loadRuns();
          onFindingsChanged?.(); // findings 恒 pending 进待审区,刷新徽标
        }
      } catch {
        /* 单次轮询失败等下一拍 */
      }
    }, 2500);
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [run, loadRuns, onFindingsChanged]);

  async function startRun() {
    if (!sourceId) return;
    setBusy(true);
    setRunError(null);
    try {
      const b = budget.trim() === "" ? null : Number(budget);
      if (b !== null && (!Number.isInteger(b) || b < 0)) {
        setRunError("预算须为 ≥0 的整数(0 = 不限)");
        return;
      }
      const r = await api.runAnalysis(caseDetail.id, sourceId, b);
      setRun(await api.getAnalysis(r.run_id));
      loadRuns();
    } catch (err) {
      // 409:同源已有 running,如实提示(后端 detail 原文)
      setRunError(err.status === 409 ? `该源已有分析在跑:${err.message}` : err.message);
    } finally {
      setBusy(false);
    }
  }

  async function abortRun() {
    if (!run) return;
    try {
      await api.abortAnalysis(run.id);
      setRun(await api.getAnalysis(run.id));
      loadRuns();
    } catch (err) {
      setRunError(err.message);
    }
  }

  async function openRun(id) {
    setRunError(null);
    try {
      setRun(await api.getAnalysis(id));
    } catch (err) {
      setRunError(err.message);
    }
  }

  // 记录区锚点跳入:打开指定 run(失败如实报错,不静默)
  useEffect(() => {
    if (!aiInit) return;
    openRun(aiInit.runId);
    onAiInitConsumed?.();
  }, [aiInit]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="pane">
      <div className="advice-note">
        AI 产物 = 候选:findings 一律以 pending 进「待审区」(推测·待核),
        人点入库才算线索——判断权归人。AI 可关:未配置时诚实降级为仅确定性播种,
        L1 规则/统计扫描不受影响。
      </div>

      {/* ── 运行区 ── */}
      <div className="section">
        <div className="section-title">发起分析(L2 播种 + L3 精读)</div>
        <div className="form-row">
          <label>
            日志源
            <select value={sourceId} onChange={(e) => setSourceId(e.target.value)}>
              <option value="">选择已解析源…</option>
              {parsedSources.map((s) => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
          </label>
          <label>
            token 预算
            <input
              style={{ width: 110 }}
              value={budget}
              onChange={(e) => setBudget(e.target.value)}
              placeholder="500000"
            />
          </label>
          <button className="primary" onClick={startRun} disabled={busy || !sourceId}>
            {busy ? "发起中…" : "播种并精读(L2+L3)"}
          </button>
          {budget.trim() === "0" && (
            <span className="form-note">
              不限预算:循环检测与手动中断仍生效;token 消耗照实记账
            </span>
          )}
          {offline && (
            <span className="form-note">
              当前 AI 未配置:将只出确定性播种(L3 精读与综合 pass不执行)
            </span>
          )}
          {parsedSources.length === 0 && (
            <span className="muted">本案件暂无已解析(parsed)的日志源。</span>
          )}
        </div>
        {runError && <div className="form-error" style={{ marginTop: 6 }}>{runError}</div>}
      </div>

      {/* ── 运行卡 + 报告区 ── */}
      {run && (
        <RunCard run={run} caseId={caseDetail.id} nameOf={nameOf}
                 onAbort={abortRun} onGotoReview={onGotoReview} />
      )}

      {/* ── 历史 runs ── */}
      <div className="section">
        <div className="section-title">历史分析 runs</div>
        {!runs && <div className="muted">加载中…</div>}
        {runs && runs.length === 0 && <div className="muted">本案件尚无分析记录。</div>}
        {runs && runs.length > 0 && (
          <table className="kv-table rules-table">
            <thead>
              <tr>
                <th style={{ width: 150 }}>发起时间</th>
                <th>日志源</th>
                <th style={{ width: 90 }}>状态</th>
                <th style={{ width: 100 }}>档位</th>
                <th style={{ width: 90 }}>预算</th>
                <th>说明</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.created_at || "—"}</td>
                  <td>
                    <button className="link-btn" onClick={() => openRun(r.id)} title={`查看 run ${r.id}`}>
                      {nameOf(r.source_id)}
                    </button>
                  </td>
                  <td><StatusBadge status={r.status} /></td>
                  <td className="mono">{PROFILE_LABEL[r.profile] || r.profile}</td>
                  <td className="mono">{r.budget ?? "—"}</td>
                  <td className="note-cell" title={r.error || ""}>{r.error || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ── KB 解释小工具 ── */}
      <KbExplain />
    </div>
  );
}

const PROFILE_LABEL = { online: "online", offline_lite: "offline(降级)" };

// run 状态 → 徽标(转圈/绿/灰/红)
function StatusBadge({ status }) {
  if (status === "running")
    return (
      <span className="badge badge-info">
        <span className="spinner" /> 运行中
      </span>
    );
  if (status === "done") return <span className="badge badge-ok">完成</span>;
  if (status === "aborted") return <span className="badge badge-muted">已中断</span>;
  if (status === "failed") return <span className="badge badge-danger">失败</span>;
  return <span className="badge badge-muted">{status}</span>;
}

// 停止原因如实文案(后端目前经 report.note/budget_exceeded 表达;
// stop_reason 字段预留,出现即翻中文)
const STOP_REASON_LABEL = {
  round_limit: "达到轮次上限(round_limit)",
  tool_call_limit: "达到工具调用上限(tool_call_limit)",
  budget_exceeded: "token 预算耗尽(budget_exceeded)",
  loop_detected: "检测到循环调用(loop_detected)",
};

function RunCard({ run, caseId, nameOf, onAbort, onGotoReview }) {
  const report = run.report || null;
  const usage = run.usage || null;
  const windows = report?.windows || [];
  const anchors = report?.anchors || [];
  const findings = windows.reduce((n, w) => n + (w.findings || 0), 0);
  const tripleNeg = windows.filter((w) => w.triple_negative).length;
  const budget = run.budget || null;
  const total = usage?.total_tokens ?? 0;
  const pct = budget ? Math.min(100, Math.round((total / budget) * 100)) : 0;

  return (
    <>
      <div className="section">
        <div className="section-title">
          当前 run · <span className="mono muted">{run.id}</span>
        </div>
        <div className="form-row" style={{ marginBottom: 6 }}>
          <StatusBadge status={run.status} />
          <span className="muted">源:{nameOf(run.source_id)}</span>
          <span className="muted">档位:{PROFILE_LABEL[run.profile] || run.profile}</span>
          {run.status === "running" && (
            <button onClick={onAbort}>中断</button>
          )}
        </div>

        {usage && (
          <div className="form-row" style={{ marginBottom: 6 }}>
            <span className="mono muted">
              tokens: prompt {usage.prompt_tokens ?? 0} · completion{" "}
              {usage.completion_tokens ?? 0} · total {usage.total_tokens ?? 0}
              {usage.calls != null && ` · 调用 ${usage.calls} 次`}
            </span>
          </div>
        )}
        {budget != null && (
          <div className="form-row" style={{ marginBottom: 6 }}>
            <span className="muted">预算</span>
            <span className={`budget-bar${pct >= 80 ? " hot" : ""}`}>
              <i style={{ width: `${pct}%` }} />
            </span>
            <span className="mono muted">
              {total} / {budget}({pct}%)
            </span>
          </div>
        )}

        {/* 停止/异常如实区:不藏不粉饰 */}
        {run.stop_reason && (
          <div className="form-note">
            停止原因:{STOP_REASON_LABEL[run.stop_reason] || run.stop_reason}
          </div>
        )}
        {report?.budget_exceeded && (
          <div className="form-note">token 预算耗尽(budget_exceeded),已完成窗口如实保留。</div>
        )}
        {run.error && <div className="form-error">{run.error}</div>}
        {(run.note || report?.note) && (
          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
            {run.note || report.note}
          </div>
        )}
      </div>

      {report && (
        <div className="section">
          <div className="section-title">分析报告</div>
          {/* 漏斗:锚点 → 窗口 → findings → 三重否定 */}
          <div className="report-grid">
            <div className="report-cell">
              <span className="report-num">{anchors.length}</span>
              <span className="report-label">锚点(pending 命中)</span>
            </div>
            <div className="report-cell">
              <span className="report-num">{windows.length}</span>
              <span className="report-label">播种窗口</span>
            </div>
            <div className="report-cell">
              <span className="report-num">{findings}</span>
              <span className="report-label">AI findings(候选)</span>
            </div>
            <div className="report-cell">
              <span className="report-num">{tripleNeg}</span>
              <span className="report-label">三重否定留痕</span>
            </div>
          </div>

          {findings > 0 && (
            <div className="form-note" style={{ margin: "4px 0 8px" }}>
              {findings} 条 AI findings 已进待审区——AI 推测·待核,判断权归人。
              <button className="link-btn" onClick={onGotoReview}>前往待审区裁决 →</button>
            </div>
          )}

          {/* notes 逐条如实列出(含「无锚点不播种」「无 AI·仅确定性播种」等) */}
          <div className="report-seg">
            <div className="report-seg-title">说明(notes,逐条如实)</div>
            <ul className="note-list">
              {(run.note || report.note) && <li>{run.note || report.note}</li>}
              {windows.map((w, i) => (
                <WindowNotes key={i} w={w} />
              ))}
              {report.synthesis_error && <li>综合 pass:{report.synthesis_error}</li>}
            </ul>
          </div>

          {/* 锚点按扫描轮次分组(仅展示层标注,播种逻辑不变):
              用户能看出每条锚点是第几轮哪批规则跑出来的 */}
          {anchors.length > 0 && (
            <AnchorRounds caseId={caseId} sourceId={run.source_id}
                          anchors={anchors} />
          )}

          {report.synthesis && (
            <div className="report-seg">
              <div className="report-seg-title">综合 pass(AI 起草·推测待核,非结论)</div>
              <div className="synthesis-box">{report.synthesis}</div>
            </div>
          )}

          {/* 窗口明细 */}
          {windows.length > 0 && (
            <div className="report-seg">
              <div className="report-seg-title">窗口明细({windows.length})</div>
              <table className="kv-table rules-table">
                <thead>
                  <tr>
                    <th style={{ width: 120 }}>窗口</th>
                    <th style={{ width: 70 }}>锚点</th>
                    <th style={{ width: 110 }}>状态</th>
                    <th style={{ width: 70 }}>findings</th>
                    <th>摘要</th>
                  </tr>
                </thead>
                <tbody>
                  {windows.map((w, i) => (
                    <tr key={i}>
                      <td className="mono">L{w.from}~L{w.to}</td>
                      <td className="mono">{(w.anchors || []).length}</td>
                      <td><WindowStatus w={w} /></td>
                      <td className="mono">{w.findings || 0}</td>
                      <td className="note-cell" title={w.window_note || w.ai_error || ""}>
                        {w.window_note || w.ai_error || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </>
  );
}

// 锚点按扫描轮次分组(展示层):锚点=pending 命中的行号,轮次从待审区
// hits 的 round_no 反查(老数据 NULL=「历史」;查不到=如实标「未登记」)
function AnchorRounds({ caseId, sourceId, anchors }) {
  const [roundOf, setRoundOf] = useState(null); // "source_id:line_no" → round_no

  useEffect(() => {
    let cancelled = false;
    api
      .listHits(caseId, { limit: 1000 })
      .then((r) => {
        if (cancelled) return;
        const m = {};
        for (const h of r.items || []) {
          m[`${h.source_id}:${h.line_no}`] = h.round_no;
        }
        setRoundOf(m);
      })
      .catch(() => !cancelled && setRoundOf({}));
    return () => {
      cancelled = true;
    };
  }, [caseId]);

  if (!roundOf) return null;
  const groups = {}; // 轮次标签 → 行号列表
  for (const line of anchors) {
    const rn = roundOf[`${sourceId}:${line}`];
    const label = rn != null ? `R${rn}` : rn === null ? "历史" : "未登记";
    (groups[label] = groups[label] || []).push(line);
  }
  // 轮次号升序,「历史」「未登记」排尾(确定性)
  const order = (a, b) => {
    const ra = /^R(\d+)$/.exec(a);
    const rb = /^R(\d+)$/.exec(b);
    if (ra && rb) return Number(ra[1]) - Number(rb[1]);
    if (ra) return -1;
    if (rb) return 1;
    return a === "历史" ? -1 : 1;
  };
  return (
    <div className="report-seg">
      <div className="report-seg-title">锚点按扫描轮次分组({anchors.length})</div>
      {Object.keys(groups).sort(order).map((label) => (
        <div key={label} style={{ marginBottom: 2, fontSize: 12 }}>
          <span className="badge badge-muted">{label}</span>{" "}
          <span className="mono muted">
            {groups[label].map((l) => `L${l}`).join(" ")}
          </span>
        </div>
      ))}
      <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
        轮次 = 该命中由第几轮规则扫描产出;「历史」= 轮次台账上线前的老数据。
      </div>
    </div>
  );
}

// 每窗的如实说明:摘要 / 截断提示 / 跳过坏项 / 三重否定抑制 / ai_error
function WindowNotes({ w }) {  const items = [];
  const range = `L${w.from}~L${w.to}`;
  if (w.prompt_truncated) items.push(`窗口 ${range}:行数超提示上限,仅展示前段交 AI(截断如实)`);
  if (w.skipped_findings) items.push(`窗口 ${range}:${w.skipped_findings} 条坏 findings 被跳过(零静默)`);
  if (w.clean_suppressed && w.suppress_note) items.push(`窗口 ${range}:${w.suppress_note}`);
  if (w.ai_error) items.push(`窗口 ${range}:${w.ai_error}`);
  return items.map((t, i) => <li key={i}>{t}</li>);
}

function WindowStatus({ w }) {
  if (w.status === "done")
    return (
      <span className="badge badge-ok">
        完成{w.triple_negative ? "·三重否定" : ""}
      </span>
    );
  if (w.status === "ai_error") return <span className="badge badge-danger">ai_error</span>;
  if (w.status === "skipped_offline")
    return <span className="badge badge-muted">无 AI 跳过</span>;
  return <span className="badge badge-muted">{w.status || "pending"}</span>;
}

// KB 解释小工具:确定性解释 path/ua/status;未覆盖如实交 AI/人研判。
const KB_KINDS = [
  { id: "path", name: "路径 path" },
  { id: "ua", name: "User-Agent" },
  { id: "status", name: "状态码 status" },
];

function KbExplain() {
  const [kind, setKind] = useState("path");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function query() {
    if (!value.trim()) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.kbExplain(kind, value.trim()));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="section">
      <div className="section-title">KB 解释器(确定性,非 AI)</div>
      <div className="form-row">
        <label>
          类型
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            {KB_KINDS.map((k) => (
              <option key={k.id} value={k.id}>{k.name}</option>
            ))}
          </select>
        </label>
        <input
          style={{ minWidth: 260 }}
          value={value}
          placeholder="如 /wp-login.php、sqlmap/1.7、404"
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && query()}
        />
        <button className="primary" onClick={query} disabled={busy || !value.trim()}>
          {busy ? "查询中…" : "解释"}
        </button>
      </div>
      {error && <div className="form-error" style={{ marginTop: 6 }}>{error}</div>}
      {result && (
        <div style={{ marginTop: 8 }}>
          {result.covered ? (
            <div className="advice-note" style={{ marginBottom: 0 }}>
              <span className="badge badge-ok">KB 已覆盖</span>{" "}
              <span className="mono">{result.value}</span>:{result.text}
            </div>
          ) : (
            <div className="form-note">
              KB 未覆盖 <span className="mono">{result.value}</span>
              ——不硬解释,该值交 AI/人研判。
            </div>
          )}
        </div>
      )}
    </div>
  );
}
