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
  const [customRules, setCustomRules] = useState(null); // 自定义规则(含状态)
  const [loadError, setLoadError] = useState(null);
  const [sourceId, setSourceId] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);
  const [scanError, setScanError] = useState(null);
  // 规则勾选(仅当次生效,不持久化):excluded 为「取消勾选」的 id 集合,
  // 默认空 = 全选;draft/review 自定义规则不可跑,不进可选空间
  const [excluded, setExcluded] = useState(new Set());

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      const r = await api.listRules(caseDetail.id);
      setRules(r.items || []);
      setStatRules(r.stats || []); // M2 新增键;老后端无此键时落空数组
      setCustomRules(r.custom || []); // 自定义规则(含 draft/review/enable 状态)
    } catch (err) {
      setLoadError(err.message);
    }
  }, [caseDetail.id]);

  useEffect(() => {
    setReport(null);
    setSourceId("");
    setExcluded(new Set());          // 换案件/重载规则:勾选复位为全选
    load();
  }, [load]);

  // 可跑规则 id 空间(签名 + 统计/跨源内置 + enable 自定义)
  const runnableIds = [
    ...(rules || []).map((r) => r.id),
    ...(statRules || []).map((r) => r.id),
    ...(customRules || []).filter((c) => c.status === "enable").map((c) => c.id),
  ];

  async function run() {
    setBusy(true);
    setScanError(null);
    try {
      // 全选 → 不传 rule_ids(全量,旧行为);子集 → 传选中清单
      const selected = runnableIds.filter((id) => !excluded.has(id));
      if (selected.length === 0) {
        setScanError("至少勾选一条规则(或点「全选」跑全量)。");
        return;
      }
      const ruleIds =
        excluded.size === 0 && rules ? undefined : selected;
      const r = await api.runRules(caseDetail.id, sourceId || undefined, ruleIds);
      setReport(r);
      onScanned?.(); // 新候选进待审区,刷新 App 的待审计数徽标
    } catch (err) {
      setScanError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function toggle(id) {
    setExcluded((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
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
      {rules && (
        <details className="norm-detail" style={{ marginBottom: 8 }}>
          <summary>
            规则勾选:已选 {runnableIds.filter((id) => !excluded.has(id)).length}
            /{runnableIds.length}(仅当次生效,不持久化;默认全选=全量)
          </summary>
          <div style={{ marginTop: 4 }}>
            <button onClick={() => setExcluded(new Set())}>全选</button>{" "}
            <button onClick={() => setExcluded(new Set(runnableIds))}>全不选</button>
          </div>
          <RuleCheckGroup title="签名规则" rules={rules}
                          excluded={excluded} onToggle={toggle} />
          <RuleCheckGroup title="统计规则(含跨源联动内置)" rules={statRules || []}
                          excluded={excluded} onToggle={toggle} />
          <RuleCheckGroup
            title="自定义规则(draft/review 不可跑,置灰)"
            rules={(customRules || []).map((c) => ({
              ...c, disabled: c.status !== "enable",
            }))}
            excluded={excluded} onToggle={toggle} />
        </details>
      )}
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
      {customRules && (
        <CustomRulesSection rules={customRules} onChanged={load} />
      )}
    </div>
  );
}

// 算子 → 中文名(M2 统计算子族 + 链式/周期 + 跨源联动内置)
const OPERATOR_LABEL = {
  same_key_divergence: "同键异值分化",
  cross_key_same_value: "异键同值聚簇",
  rate_spike: "同键变率突刺",
  size_outlier: "尺寸离群",
  sequence: "链式 motif",
  periodicity: "周期信标",
  cross_source_entity: "跨源实体",
};

// 统计规则参数摘要的展示顺序(与 backend rules/stats/*.yaml 的参数全集一致)
const STAT_PARAM_KEYS = [
  "key_fields", "diverge_field", "metric", "min_group_events", "diverge_ratio",
  "value_field", "min_keys", "max_value_freq", "exclude_kb",
  "bucket_seconds", "zscore", "min_bucket_count",
  "deviate_ratio", "max_outliers",
  "steps", "window_seconds", "min_first_step_count",
  "min_events", "max_cv", "min_span_seconds", "max_hits",
];

// 参数摘要:key_fields=[a,b]; diverge_field=method; …(无参数的内置条目 → —)
function statParamSummary(rule) {
  const parts = STAT_PARAM_KEYS.filter((k) => rule[k] !== undefined).map((k) =>
    typeof rule[k] === "object"
      ? `${k}=${JSON.stringify(rule[k])}`           // steps 这类结构参数
      : `${k}=${rule[k]}`
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

// 自定义规则治理小节:清单(含状态徽标)+ 新建/编辑(yaml 文本框)+
// 状态切换 + 删除。纪律与 formatdesc 一致:创建恒 draft,只有 enable 进扫描;
// 内置规则永只读(撞内置 id 后端 409 如实)。
const RULE_STATUS_LABEL = { draft: "草稿", review: "待审", enable: "启用", broken: "损坏" };

const CUSTOM_RULE_TEMPLATE = `# 自定义签名规则样例(统计规则改用 operator + 参数,见内置 stats 规则)
id: my-custom-rule          # 小写连字符;不可与内置规则同名
title: 我的规则
severity: low               # info|low|medium|high
target: any                 # web|middleware|audit|any
match:                      # 字段条件 AND,字段内子串列表 OR
  ua: ["some-token"]
# max_hits: 100            # 可选:每案命中预算帽(默认签名 500/统计 50)
`;

function CustomRulesSection({ rules, onChanged }) {
  const [editing, setEditing] = useState(null);   // {id|null, yaml}
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      if (editing.id) {
        await api.updateCustomRule(editing.id, { yamlText: editing.yaml });
      } else {
        await api.createCustomRule(editing.yaml);
      }
      setEditing(null);
      onChanged?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function edit(rule) {
    setError(null);
    try {
      const d = await api.getCustomRule(rule.id);
      setEditing({ id: rule.id, yaml: d.yaml_text });
    } catch (err) {
      setError(err.message);
    }
  }

  async function setStatus(rule, status) {
    setError(null);
    try {
      await api.updateCustomRule(rule.id, { status });
      onChanged?.();
    } catch (err) {
      setError(err.message);
    }
  }

  async function remove(rule) {
    if (!window.confirm(`删除自定义规则 ${rule.id}?(只许删自定义,内置规则只读)`)) return;
    setError(null);
    try {
      await api.deleteCustomRule(rule.id);
      onChanged?.();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="section">
      <div className="section-title">自定义规则({rules.length})</div>
      <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>
        新建即草稿(draft),只有「启用」状态进扫描;命中一律进待审区,人裁决才算线索。
      </div>
      {error && <div className="form-error" style={{ marginBottom: 8 }}>{error}</div>}
      {rules.length > 0 && (
        <table className="kv-table rules-table">
          <thead>
            <tr>
              <th style={{ width: 170 }}>规则 id</th>
              <th>标题</th>
              <th style={{ width: 70 }}>类型</th>
              <th style={{ width: 80 }}>级别</th>
              <th style={{ width: 120 }}>状态</th>
              <th style={{ width: 120 }}>操作</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id}>
                <td>{r.id}</td>
                <td title={r.error || r.note || ""}>{r.title || r.error || "—"}</td>
                <td>{r.kind === "stat" ? "统计" : r.kind === "signature" ? "签名" : "—"}</td>
                <td>
                  {r.severity
                    ? <span className={`badge ${sevBadge(r.severity)}`}>{r.severity}</span>
                    : "—"}
                </td>
                <td>
                  <select
                    value={r.status}
                    disabled={r.status === "broken"}
                    onChange={(e) => setStatus(r, e.target.value)}
                    title="只有「启用」进扫描;草稿/待审如实标注不进扫描"
                  >
                    {["draft", "review", "enable"].map((s) => (
                      <option key={s} value={s}>{RULE_STATUS_LABEL[s]}({s})</option>
                    ))}
                    {r.status === "broken" && <option value="broken">损坏</option>}
                  </select>
                </td>
                <td>
                  <button onClick={() => edit(r)} disabled={r.status === "broken"}>编辑</button>{" "}
                  <button onClick={() => remove(r)}>删除</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {!editing && (
        <button style={{ marginTop: 6 }}
                onClick={() => setEditing({ id: null, yaml: CUSTOM_RULE_TEMPLATE })}>
          新建自定义规则
        </button>
      )}
      {editing && (
        <div style={{ marginTop: 6 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>
            {editing.id ? `编辑 ${editing.id}(内容保存时重过 schema 校验;状态不变)` :
              "新建(保存即草稿 draft,人审转「启用」后才进扫描)"}
          </div>
          <textarea
            className="mono"
            style={{ width: "100%", minHeight: 180 }}
            value={editing.yaml}
            onChange={(e) => setEditing({ ...editing, yaml: e.target.value })}
          />
          <div style={{ marginTop: 4 }}>
            <button className="primary" onClick={save} disabled={busy}>
              {busy ? "保存中…" : "保存"}
            </button>{" "}
            <button onClick={() => setEditing(null)} disabled={busy}>取消</button>
          </div>
        </div>
      )}
    </div>
  );
}

// match 字段条件摘要:{field: v} / {field: [v1, v2]}(list 即 OR)→ "field: v1 | v2"
function matchSummary(match) {
  if (!match || typeof match !== "object") return "—";
  const parts = Object.entries(match).map(([k, v]) =>
    Array.isArray(v) ? `${k}: ${v.join(" | ")}` : `${k}: ${v}`
  );
  return parts.length ? parts.join("; ") : "—";
}

// 规则勾选分组(扫描勾选区用;disabled=不可跑的 draft/review 自定义规则)
function RuleCheckGroup({ title, rules, excluded, onToggle }) {
  if (!rules || rules.length === 0) return null;
  return (
    <div style={{ marginTop: 6 }}>
      <div className="muted" style={{ fontSize: 12 }}>{title}({rules.length})</div>
      <div>
        {rules.map((r) => (
          <label key={r.id} className="mono"
                 style={{ display: "inline-block", marginRight: 14, fontSize: 12 }}
                 title={r.disabled ? `状态 ${r.status},转 enable 后才可跑` : r.title || r.id}>
            <input
              type="checkbox"
              checked={!r.disabled && !excluded.has(r.id)}
              disabled={!!r.disabled}
              onChange={() => onToggle(r.id)}
            />{" "}
            {r.id}
          </label>
        ))}
      </div>
    </div>
  );
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
      <div className="section-title">
        扫描报告{report.round_no != null && `(第 ${report.round_no} 轮)`}
      </div>
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
      {list.filter((p) => p.truncated > 0).map((p) => (
        <span key={`${p.rule_id}-trunc`} className="badge badge-bolt rule-hit-badge"
              title={`${p.rule_id} 超每案命中预算帽,已截断,溢出 ${p.truncated} 条未入库(如实标注)`}>
          {p.rule_id} 已截断 +{p.truncated}
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
