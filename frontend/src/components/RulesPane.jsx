import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { sevBadge } from "../util.js";

// 规则与扫描区:规则清单(只读)+ 手动触发扫描。
// 文案纪律(§1/§8):扫描产物是「候选命中」,一律进待审区,永不自动落线索。
// M2:规则分「签名规则」与「统计规则(键值比对算子族)」两组;
// 扫描报告按 signature / stats / cross_source 三段如实呈现,skipped 不藏。
export default function RulesPane({ caseDetail, onScanned }) {
  const sources = caseDetail.sources || [];
  const nameOf = (id) => sources.find((s) => s.id === id)?.name || id;
  const [rules, setRules] = useState(null);       // 签名规则
  const [statRules, setStatRules] = useState(null); // 统计规则 + 跨源联动内置条目
  const [loadError, setLoadError] = useState(null);
  const [sourceId, setSourceId] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);
  const [scanError, setScanError] = useState(null);

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      const r = await api.listRules(caseDetail.id);
      setRules(r.items || []);
      setStatRules(r.stats || []); // M2 新增键;老后端无此键时落空数组
    } catch (err) {
      setLoadError(err.message);
    }
  }, [caseDetail.id]);

  useEffect(() => {
    setReport(null);
    setSourceId("");
    load();
  }, [load]);

  async function run() {
    setBusy(true);
    setScanError(null);
    try {
      const r = await api.runRules(caseDetail.id, sourceId || undefined);
      setReport(r);
      onScanned?.(); // 新候选进待审区,刷新 App 的待审计数徽标
    } catch (err) {
      setScanError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="pane">
      <div className="advice-note">
        命中 ≠ 结论:规则扫描的产物一律是候选,全部进「待审区」,人点入库才算线索(判断权归人)。
      </div>

      <div className="form-row" style={{ marginBottom: 10 }}>
        <label>
          扫描范围
          <select value={sourceId} onChange={(e) => setSourceId(e.target.value)}>
            <option value="">全案件</option>
            {sources.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </label>
        <button className="primary" onClick={run} disabled={busy || !rules}>
          {busy ? "扫描中…" : "运行扫描"}
        </button>
        {rules && (
          <span className="muted">
            签名 {rules.length} 条 · 统计 {(statRules || []).length} 条
          </span>
        )}
      </div>
      {scanError && <div className="form-error" style={{ marginBottom: 8 }}>{scanError}</div>}

      {report && <ScanReport report={report} nameOf={nameOf} />}

      {loadError && <div className="form-error">{loadError}</div>}
      {!rules && !loadError && <div className="muted">加载规则中…</div>}
      {rules && rules.length === 0 && <div className="muted">本案件暂无可用签名规则。</div>}
      {rules && rules.length > 0 && (
        <div className="section">
          <div className="section-title">签名规则({rules.length})</div>
          <table className="kv-table rules-table">
            <thead>
              <tr>
                <th style={{ width: 170 }}>规则 id</th>
                <th>标题</th>
                <th style={{ width: 80 }}>级别</th>
                <th style={{ width: 110 }}>目标</th>
                <th>匹配条件</th>
                <th style={{ width: 160 }}>备注</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td>{r.id}</td>
                  <td>{r.title}</td>
                  <td>
                    <span className={`badge ${sevBadge(r.severity)}`}>{r.severity}</span>
                  </td>
                  <td>{r.target}</td>
                  <td title={JSON.stringify(r.match)}>{matchSummary(r.match)}</td>
                  <td className="note-cell" title={r.note || ""}>
                    {r.note ? r.note : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {statRules && statRules.length > 0 && (
        <div className="section">
          <div className="section-title">
            统计规则(键值比对算子族,{statRules.length})
          </div>
          <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>
            统计命中是聚合产物:line_no 为组内代表行;概率性弱信号一律进待审区交人复核,机器不定论。
          </div>
          <table className="kv-table rules-table">
            <thead>
              <tr>
                <th style={{ width: 170 }}>规则 id</th>
                <th>标题</th>
                <th style={{ width: 80 }}>级别</th>
                <th style={{ width: 130 }}>算子</th>
                <th>参数</th>
                <th style={{ width: 160 }}>备注</th>
              </tr>
            </thead>
            <tbody>
              {statRules.map((r) => (
                <tr key={r.id}>
                  <td>{r.id}</td>
                  <td>{r.title}</td>
                  <td>
                    <span className={`badge ${sevBadge(r.severity)}`}>{r.severity}</span>
                  </td>
                  <td>
                    <span className="badge op-badge" title={r.operator}>
                      {OPERATOR_LABEL[r.operator] || r.operator || "—"}
                    </span>
                  </td>
                  <td className="note-cell" title={statFullTitle(r)}>
                    {statParamSummary(r)}
                  </td>
                  <td className="note-cell" title={r.note || ""}>
                    {r.note ? r.note : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// 算子 → 中文名(M2 统计算子族 + 跨源联动内置)
const OPERATOR_LABEL = {
  same_key_divergence: "同键异值分化",
  cross_key_same_value: "异键同值聚簇",
  rate_spike: "同键变率突刺",
  cross_source_entity: "跨源实体",
};

// 统计规则参数摘要的展示顺序(与 backend rules/stats/*.yaml 的参数全集一致)
const STAT_PARAM_KEYS = [
  "key_fields", "diverge_field", "metric", "min_group_events", "diverge_ratio",
  "value_field", "min_keys", "max_value_freq", "exclude_kb",
  "bucket_seconds", "zscore", "min_bucket_count",
];

// 参数摘要:key_fields=[a,b]; diverge_field=method; …(无参数的内置条目 → —)
function statParamSummary(rule) {
  const parts = STAT_PARAM_KEYS.filter((k) => rule[k] !== undefined).map((k) =>
    Array.isArray(rule[k]) ? `${k}=[${rule[k].join(",")}]` : `${k}=${rule[k]}`
  );
  return parts.length ? parts.join("; ") : "—";
}

// 悬停全文:完整参数 JSON + note(参数单元格截断时不丢信息)
function statFullTitle(rule) {
  const params = {};
  for (const k of STAT_PARAM_KEYS) if (rule[k] !== undefined) params[k] = rule[k];
  const head = Object.keys(params).length ? JSON.stringify(params) : "(无参数,内置联动步骤)";
  return rule.note ? `${head}\n备注:${rule.note}` : head;
}

// match 字段条件摘要:{field: v} / {field: [v1, v2]}(list 即 OR)→ "field: v1 | v2"
function matchSummary(match) {
  if (!match || typeof match !== "object") return "—";
  const parts = Object.entries(match).map(([k, v]) =>
    Array.isArray(v) ? `${k}: ${v.join(" | ")}` : `${k}: ${v}`
  );
  return parts.length ? parts.join("; ") : "—";
}

function ScanReport({ report, nameOf }) {
  // 老后端(纯 M1)无分段键:签名段回落到顶层字段,统计/跨源段不渲染
  const sig = report.signature || {
    scanned: report.scanned,
    hits_new: report.hits_new,
    per_rule: report.per_rule || [],
  };
  const stats = report.stats || null;
  const cs = report.cross_source || null;
  return (
    <div className="section">
      <div className="section-title">扫描报告</div>
      <div className="report-grid">
        <div className="report-cell">
          <span className="report-num">{report.scanned}</span>
          <span className="report-label">扫描行数</span>
        </div>
        <div className="report-cell">
          <span className="report-num">{report.hits_new}</span>
          <span className="report-label">新增候选</span>
        </div>
        <div className="report-cell">
          <span className="report-num">{report.hits_total}</span>
          <span className="report-label">候选总数</span>
        </div>
      </div>
      {report.hits_new > 0 && (
        <div className="form-note" style={{ margin: "4px 0 8px" }}>
          {report.hits_new} 条新候选已进待审区,等待人工裁决——机器不定论。
        </div>
      )}

      <ReportSegment
        title={`① 签名规则段(逐事件匹配,扫描 ${sig.scanned} 行,新增 ${sig.hits_new})`}
        perRule={sig.per_rule}
      />
      {stats && (
        <div className="report-seg">
          <div className="report-seg-title">
            ② 统计规则段(聚合算子,新增 {stats.hits_new})
          </div>
          <RuleHitBadges perRule={stats.per_rule} />
          {(stats.skipped || []).length > 0 && (
            <div className="skipped-list">
              <span className="muted">
                跳过 {stats.skipped.length} 项(如实列出,不硬算):
              </span>
              {stats.skipped.map((s, i) => (
                <div key={i} className="mono" style={{ fontSize: 12 }}>
                  {s.rule_id} · {nameOf(s.source_id)}:{s.reason}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {cs && (
        <div className="report-seg">
          <div className="report-seg-title">
            ③ 跨源联动段(global 实体 ≥2 源,新增 {cs.hits_new})
          </div>
          {(cs.entities || []).length === 0 ? (
            <span className="muted">本次无跨源联动实体。</span>
          ) : (
            <div>
              {(cs.entities || []).map((e) => (
                <span key={e} className="badge badge-bolt rule-hit-badge" title="跨源联动实体(同值未必同人,交人复核)">
                  ⚡ {e}
                </span>
              ))}
              <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
                跨源结论已打 ⚡ 标并写明涉及源;同值未必同人,交人复核(§7 防串味)。
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ReportSegment({ title, perRule }) {
  return (
    <div className="report-seg">
      <div className="report-seg-title">{title}</div>
      <RuleHitBadges perRule={perRule} />
    </div>
  );
}

// 规则命中分布徽标:非零直列,零命中折叠(签名/统计段共用)
function RuleHitBadges({ perRule }) {
  const list = perRule || [];
  const nonzero = list.filter((p) => p.hits > 0);
  const zero = list.filter((p) => p.hits === 0);
  return (
    <div style={{ marginTop: 2 }}>
      {nonzero.length === 0 && <span className="muted">本段无规则命中。</span>}
      {nonzero.map((p) => (
        <span key={p.rule_id} className="badge badge-warn rule-hit-badge" title={`${p.rule_id} 命中 ${p.hits} 条`}>
          {p.rule_id} × {p.hits}
        </span>
      ))}
      {zero.length > 0 && (
        <details className="norm-detail" style={{ display: "inline-block", marginLeft: 8 }}>
          <summary>0 命中规则({zero.length})</summary>
          <div className="mono muted" style={{ marginTop: 4 }}>
            {zero.map((p) => p.rule_id).join("、")}
          </div>
        </details>
      )}
    </div>
  );
}
