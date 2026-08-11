import { useEffect, useState } from "react";
import { api, FORMATS, LOG_TYPES, STATUS_LABEL } from "../api.js";
import { parseTimeRange, shortSha } from "../util.js";
import SealSection from "./SealSection.jsx";

// 日志源区:上传向导(登记 → 指纹建议 → 人确认 → 解析)+ 源列表 + 封存导出。
export default function SourcesPane({ caseDetail, colorOf, onChanged }) {
  return (
    <div className="pane">
      <div className="pane-header">
        <h2>
          日志源 <span className="muted">登记 → 指纹建议 → 人确认 → 解析(入库三段式)</span>
        </h2>
      </div>
      <SealSection caseId={caseDetail.id} />
      <UploadWizard caseId={caseDetail.id} onChanged={onChanged} />
      <SourceList caseDetail={caseDetail} colorOf={colorOf} onChanged={onChanged} />
    </div>
  );
}

/* ---------------------------------------------------------------- 上传向导 */

function UploadWizard({ caseId, onChanged }) {
  const [file, setFile] = useState(null);
  const [system, setSystem] = useState("");
  const [note, setNote] = useState("");
  const [supplementary, setSupplementary] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null); // upload 响应(含指纹建议)

  async function submit(e) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await api.uploadSource(caseId, file, {
        system: system || undefined,
        sourceNote: note || undefined,
        evidenceKind: supplementary ? "supplementary" : undefined,
      });
      setResult(r);
      onChanged(); // 源已登记,刷新列表
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="section">
      <div className="section-title">上传日志文件(txt / log / zip)</div>
      <form className="inline-form" onSubmit={submit}>
        <div className="form-row">
          <input
            type="file"
            accept=".txt,.log,.zip"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
        </div>
        <div className="form-row">
          <label>
            系统名
            <input
              placeholder="如:官网 nginx(可选)"
              value={system}
              onChange={(e) => setSystem(e.target.value)}
            />
          </label>
          <label style={{ flex: 1 }}>
            来源说明
            <input
              style={{ width: "100%" }}
              placeholder="谁提供/从哪台设备导出/什么时间范围(可选,留痕用)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </label>
        </div>
        <div className="form-row">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={supplementary}
              onChange={(e) => setSupplementary(e.target.checked)}
            />
            补充证据
          </label>
          <button className="primary" type="submit" disabled={busy || !file}>
            {busy ? "上传中…" : "上传并探测格式"}
          </button>
          <span className="muted">
            {supplementary
              ? "补充证据:人随时补的材料(agent 日志/目录导出/会话录屏等),打标留痕、同管线可检索"
              : "源名取自文件名;zip 将单层展开为多个日志源"}
          </span>
        </div>
        {error && <div className="form-error">{error}</div>}
      </form>

      {result && (
        <div style={{ marginTop: 10 }}>
          {result.kind === "zip" && (
            <div className="muted" style={{ marginBottom: 6 }}>
              压缩包 {result.zip}:登记 {result.sources.length} 个日志源
              {result.skipped.length > 0 && (
                <span className="form-note">;跳过 {result.skipped.join("、")}</span>
              )}
            </div>
          )}
          {result.sources.map((s) => (
            <FingerprintBlock key={s.source_id} source={s} onConfirmed={onChanged} />
          ))}
        </div>
      )}
    </div>
  );
}

// 单个新登记源的指纹建议 + 确认表单(建议只是建议,确认权在人)。
function FingerprintBlock({ source, onConfirmed }) {
  const fp = source.fingerprint || {};
  const suggestions = fp.suggestions || [];
  const [done, setDone] = useState(false);

  return (
    <div className="section" style={{ background: "var(--panel-2)" }}>
      <div className="section-title">
        <span className="mono">{source.name}</span>{" "}
        <span className="badge badge-muted">已登记</span>{" "}
        <span className="muted mono">sha256 {shortSha(source.sha256)}</span>
      </div>
      <div className="advice-note">
        以下为格式指纹探测<strong>建议</strong>,仅供参考;解析配置必须由人确认后才生效,
        系统不会自动选择格式(设计 §4)。
      </div>
      {fp.verdict === "unknown" && (
        <div className="form-note" style={{ marginBottom: 6 }}>
          探测未能识别该格式(最高置信度低于阈值 {fp.threshold})。
          建议从格式清单手选,或使用 {fp.recommended_fallback === "raw" ? "raw T0 原文兜底" : "兜底格式"}。
        </div>
      )}
      {suggestions.length === 0 && fp.verdict !== "unknown" && (
        <div className="muted" style={{ marginBottom: 6 }}>无任何候选格式命中。</div>
      )}
      {suggestions.map((sg) => (
        <div className="suggestion" key={sg.format_id}>
          <div className="suggestion-head">
            <b className="mono">{sg.format_id}</b>
            <span className="muted">{sg.name}</span>
            <span>
              置信度 {(sg.confidence * 100).toFixed(1)}%
            </span>
            <span className="confidence-bar">
              <i style={{ width: `${Math.round(sg.confidence * 100)}%` }} />
            </span>
            {sg.header_hit && <span className="badge badge-info">头行命中</span>}
          </div>
          {sg.sample_preview?.length > 0 && (
            <table className="preview-table">
              <thead>
                <tr><th>行号</th><th>ts_raw</th><th>抽样解析预览(归一字段)</th></tr>
              </thead>
              <tbody>
                {sg.sample_preview.map((p) => (
                  <tr key={p.line_no}>
                    <td>{p.line_no}</td>
                    <td>{p.ts_raw ?? "—"}</td>
                    <td>{JSON.stringify(p.norm)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      ))}
      {done ? (
        <div className="form-ok">已确认,请在下方源列表中执行解析。</div>
      ) : (
        <ConfirmForm
          sourceId={source.source_id}
          suggestions={suggestions}
          onDone={() => {
            setDone(true);
            onConfirmed();
          }}
        />
      )}
    </div>
  );
}

/* ---------------------------------------------------------------- 确认表单 */

export function ConfirmForm({ sourceId, suggestions = [], current, onDone }) {
  const suggestedIds = new Set(suggestions.map((s) => s.format_id));
  const rest = FORMATS.filter((f) => !suggestedIds.has(f.id));
  const [formatId, setFormatId] = useState(
    current?.format_id || suggestions[0]?.format_id || "raw"
  );
  const [tz, setTz] = useState(current?.tz_declared || "");
  const [logType, setLogType] = useState(current?.log_type || "unknown");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  // M4:自定义描述文件(仅 enable 状态可选;draft/review 提交 → 后端 422「未启用」如实)
  const [descs, setDescs] = useState([]);

  useEffect(() => {
    api
      .listFormatDescs()
      .then((r) => setDescs((r.items || []).filter((d) => d.status === "enable")))
      .catch(() => {}); // 清单拉取失败不挡确认表单,仅缺 desc 组
  }, []);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.confirmSource(sourceId, {
        formatId,
        tzDeclared: tz.trim() || null,
        logType,
      });
      onDone();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="inline-form" onSubmit={submit}>
      <div className="form-row">
        <label>
          格式
          <select value={formatId} onChange={(e) => setFormatId(e.target.value)}>
            {suggestions.length > 0 && (
              <optgroup label="指纹建议(置顶)">
                {suggestions.map((s) => (
                  <option key={s.format_id} value={s.format_id}>
                    {s.format_id}(置信度 {(s.confidence * 100).toFixed(1)}%)
                  </option>
                ))}
              </optgroup>
            )}
            <optgroup label="全部格式">
              {rest.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.id} — {f.name}
                </option>
              ))}
            </optgroup>
            {descs.length > 0 && (
              <optgroup label="自定义格式(desc:*,已启用)">
                {descs.map((d) => (
                  <option key={d.format_id} value={d.format_id}>
                    {d.format_id} — {d.title || d.name}
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </label>
        <label>
          声明时区
          <input
            placeholder="IANA 名,如 Asia/Shanghai"
            value={tz}
            onChange={(e) => setTz(e.target.value)}
          />
        </label>
        <label>
          日志类型
          <select value={logType} onChange={(e) => setLogType(e.target.value)}>
            {LOG_TYPES.map((t) => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="muted">
        时区留空 = 不做时间归一,ts_utc 为空并如实标注「时区未知」,不硬纠。
      </div>
      {error && <div className="form-error">{error}</div>}
      <div className="form-row">
        <button className="primary" type="submit" disabled={busy}>
          {busy ? "确认中…" : "确认解析配置"}
        </button>
      </div>
    </form>
  );
}

/* ---------------------------------------------------------------- 源列表 */

function statusBadge(status) {
  const cls = {
    registered: "badge-muted",
    confirmed: "badge-info",
    parsed: "badge-ok",
    failed: "badge-danger",
  }[status] || "badge-muted";
  return <span className={`badge ${cls}`}>{STATUS_LABEL[status] || status}</span>;
}

function SourceList({ caseDetail, colorOf, onChanged }) {
  const sources = caseDetail.sources || [];
  if (sources.length === 0) {
    return <div className="muted">本案件还没有日志源,请从上方上传。</div>;
  }
  return (
    <div>
      {sources.map((s) => (
        <SourceCard key={s.id} source={s} color={colorOf(s.id)} onChanged={onChanged} />
      ))}
    </div>
  );
}

function SourceCard({ source, color, onChanged }) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [report, setReport] = useState(null); // 解析报告(来自 parse 响应或源详情)
  const [reportOpen, setReportOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const tr = parseTimeRange(source.time_range);

  async function doParse() {
    setBusy(true);
    setError(null);
    try {
      const r = await api.parseSource(source.id);
      setReport(r);
      setReportOpen(true);
      onChanged();
    } catch (err) {
      // 422:解析失败,message 即失败原因原文;同步刷新拿到 failed 状态
      setError(err.message);
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  async function toggleReport() {
    if (reportOpen) {
      setReportOpen(false);
      return;
    }
    if (!report) {
      try {
        const detail = await api.getSource(source.id);
        setReport(detail.parse_report || null);
      } catch (err) {
        setError(err.message);
        return;
      }
    }
    setReportOpen(true);
  }

  return (
    <div className="source-card">
      <div className="source-head">
        <span className="src-dot" style={{ background: color }} />
        <span className="source-name">{source.name}</span>
        {statusBadge(source.status)}
        {source.evidence_kind === "supplementary" && (
          <span className="badge badge-info">补充证据</span>
        )}
        {source.log_type && <span className="badge badge-muted">{source.log_type}</span>}
        {source.format_id && <span className="mono muted">{source.format_id}</span>}
      </div>
      <div className="source-meta">
        <span>系统 <b>{source.system || "—"}</b></span>
        <span>行数 <b>{source.line_count ?? "未知(未解析)"}</b></span>
        <span>
          时间范围{" "}
          <b className="mono">
            {tr ? `${tr.from} ~ ${tr.to}` : "未知(未解析或无时区)"}
          </b>
        </span>
        <span>
          sha256 <b className="mono sha" title={source.sha256}>{shortSha(source.sha256)}</b>
        </span>
        {source.tz_declared
          ? <span>时区 <b>{source.tz_declared}</b></span>
          : <span className="muted">时区未声明</span>}
      </div>
      {source.source_note && (
        <div className="source-note-text">来源说明:{source.source_note}</div>
      )}
      {source.status === "failed" && source.error && (
        <div className="error-text">解析失败:{source.error}</div>
      )}
      {error && <div className="form-error" style={{ marginTop: 6 }}>{error}</div>}

      <div className="source-actions">
        {(source.status === "registered" || source.status === "failed") && (
          <button onClick={() => setConfirmOpen((v) => !v)}>
            {confirmOpen ? "收起确认表单" : source.status === "failed" ? "重新确认格式" : "确认格式"}
          </button>
        )}
        {(source.status === "confirmed" || source.status === "failed" || source.status === "parsed") && (
          <button className="primary" onClick={doParse} disabled={busy}>
            {busy ? "解析中…" : source.status === "parsed" ? "重新解析" : "开始解析"}
          </button>
        )}
        {source.status === "parsed" && (
          <button onClick={toggleReport}>
            {reportOpen ? "收起解析报告" : "解析报告"}
          </button>
        )}
      </div>

      {confirmOpen && (
        <ConfirmForm
          sourceId={source.id}
          current={source}
          onDone={() => {
            setConfirmOpen(false);
            onChanged();
          }}
        />
      )}
      {reportOpen && <ParseReportView report={report} />}
    </div>
  );
}

/* ---------------------------------------------------------------- 解析报告 */

function ParseReportView({ report }) {
  if (!report) {
    return <div className="muted" style={{ marginTop: 8 }}>尚无解析报告留痕。</div>;
  }
  const bad = report.bad_lines || 0;
  return (
    <div style={{ marginTop: 8 }}>
      <div className="report-grid">
        <Cell n={report.total_lines ?? "—"} label="总行数" />
        <Cell n={report.parsed ?? "—"} label="解析成功" ok />
        <Cell n={bad} label="坏行" warn={bad > 0} />
        <Cell n={report.skipped_lines ?? "—"} label="跳过(注释/空行)" />
        {report.events !== undefined && <Cell n={report.events} label="入库事件" />}
        {report.entities !== undefined && <Cell n={report.entities} label="抽取实体" />}
      </div>
      {bad > 0 && (
        <div className="bad-box">
          存在 {bad} 行坏行(无法按所选格式解析),已逐行计入报告,零静默。
          请人工核对坏行样本并决定是否调整格式或时区——本系统不下结论。
          {report.bad_samples?.length > 0 && (
            <div className="mono" style={{ marginTop: 4 }}>
              {report.bad_samples.map((s, i) => (
                <div key={i}>{s}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Cell({ n, label, ok, warn }) {
  const color = warn ? "var(--warn-fg)" : ok ? "var(--ok-fg)" : "var(--text)";
  return (
    <div className="report-cell">
      <span className="report-num" style={{ color }}>{n}</span>
      <span className="report-label">{label}</span>
    </div>
  );
}
