import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

// M4 格式治理(§4):描述文件清单(状态机人审流转)+ 导入(恒 draft)
// + AI 起草(草稿不落盘,人审编辑后导入;AI 草稿≠可用格式)。
const STATUS_BADGE = {
  draft: { cls: "badge-muted", label: "draft 草稿" },
  review: { cls: "badge-warn", label: "review 人审中" },
  enable: { cls: "badge-ok", label: "enable 已启用" },
  broken: { cls: "badge-danger", label: "broken 损坏" },
};

export default function FormatDescPane({ caseDetail }) {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const r = await api.listFormatDescs();
      setItems(r.items || []);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function onImported(msg) {
    setNotice(msg || "已存为 draft,人审启用后才可用于解析。");
    refresh();
  }

  return (
    <div className="pane">
      <div className="pane-header">
        <h2>
          格式治理{" "}
          <span className="muted">
            描述文件清单 · 导入恒 draft · 人审 enable 后才可用于解析(§4)
          </span>
        </h2>
      </div>
      {error && <div className="form-error">{error}</div>}
      {notice && (
        <div className="form-ok" style={{ marginBottom: 8 }} onClick={() => setNotice(null)}>
          {notice}
        </div>
      )}
      <DescList items={items} onChanged={refresh} />
      <ImportSection onImported={onImported} />
      <AiDraftSection sources={caseDetail.sources || []} onImported={onImported} />
    </div>
  );
}

/* ------------------------------------------------------------- 描述文件清单 */

function DescList({ items, onChanged }) {
  const [busy, setBusy] = useState(null); // 正在操作的 name
  const [error, setError] = useState(null);

  async function doTransition(name, to) {
    setBusy(name);
    setError(null);
    try {
      await api.transitionFormatDesc(name, to);
      onChanged();
    } catch (err) {
      setError(err.message); // 409 非法流转,原文如实
    } finally {
      setBusy(null);
    }
  }

  async function doDelete(name) {
    if (!window.confirm(`确认删除描述文件 ${name}?(仅 draft 可删,删除留痕)`)) return;
    setBusy(name);
    setError(null);
    try {
      await api.deleteFormatDesc(name);
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  async function doExport(name) {
    setBusy(name);
    setError(null);
    try {
      const text = await api.exportFormatDesc(name);
      const url = URL.createObjectURL(new Blob([text], { type: "text/yaml" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `${name}.yaml`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="section">
      <div className="section-title">描述文件清单</div>
      {error && <div className="form-error">{error}</div>}
      {items === null ? (
        <div className="muted">加载中…</div>
      ) : items.length === 0 ? (
        <div className="muted">暂无描述文件,可从下方导入或让 AI 起草。</div>
      ) : (
        <table className="kv-table">
          <thead>
            <tr>
              <th>name</th>
              <th>title</th>
              <th>kind</th>
              <th>状态</th>
              <th>note</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {items.map((d) => {
              const badge = STATUS_BADGE[d.status] || STATUS_BADGE.broken;
              return (
                <tr key={d.name}>
                  <td className="mono">{d.name}</td>
                  <td>{d.title || "—"}</td>
                  <td className="mono">{d.kind || "—"}</td>
                  <td>
                    <span className={`badge ${badge.cls}`}>{badge.label}</span>
                  </td>
                  <td className="note-cell" title={d.note || d.error || ""}>
                    {d.error ? <span className="form-error">{d.error}</span> : d.note || "—"}
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    {d.status === "draft" && (
                      <>
                        <button
                          disabled={busy === d.name}
                          onClick={() => doTransition(d.name, "review")}
                        >
                          提交人审
                        </button>{" "}
                        <button disabled={busy === d.name} onClick={() => doDelete(d.name)}>
                          删除
                        </button>{" "}
                      </>
                    )}
                    {d.status === "review" && (
                      <button
                        className="primary"
                        disabled={busy === d.name}
                        onClick={() => doTransition(d.name, "enable")}
                      >
                        启用
                      </button>
                    )}
                    {d.status === "enable" && (
                      <button
                        disabled={busy === d.name}
                        onClick={() => doTransition(d.name, "draft")}
                      >
                        停用(回 draft)
                      </button>
                    )}
                    {d.status !== "broken" && (
                      <>
                        {" "}
                        <button
                          className="link-btn"
                          disabled={busy === d.name}
                          onClick={() => doExport(d.name)}
                        >
                          导出
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <div className="muted" style={{ marginTop: 6 }}>
        状态机只许向前:draft → review → enable;enable 可停用回 draft(留痕)。仅 draft 可删。
      </div>
    </div>
  );
}

/* ------------------------------------------------- YAML 编辑器(校验 + 导入) */

// 导入区与 AI 起草区共用的编辑/校验/导入块。
function YamlEditor({ yaml, setYaml, onImported }) {
  const [sampleText, setSampleText] = useState("");
  const [validating, setValidating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [valResult, setValResult] = useState(null);
  const [error, setError] = useState(null);
  const [okMsg, setOkMsg] = useState(null);

  const sampleLines = sampleText.split("\n").filter((l) => l.trim());

  async function doValidate() {
    setValidating(true);
    setError(null);
    setOkMsg(null);
    try {
      setValResult(await api.validateFormatDesc(yaml, sampleLines));
    } catch (err) {
      setError(err.message);
    } finally {
      setValidating(false);
    }
  }

  async function doImport() {
    setImporting(true);
    setError(null);
    setOkMsg(null);
    try {
      await api.importFormatDesc(yaml);
      setOkMsg("已存为 draft,人审启用后才可用于解析。");
      onImported("已存为 draft,人审启用后才可用于解析。");
    } catch (err) {
      setError(err.message); // 409 撞名 / 400 schema 不合,原文如实
    } finally {
      setImporting(false);
    }
  }

  return (
    <div>
      <textarea
        className="yaml-box"
        spellCheck={false}
        placeholder={"name: my_format\ntitle: 我的格式\nkind: line_regex\n..."}
        value={yaml}
        onChange={(e) => {
          setYaml(e.target.value);
          setValResult(null);
          setOkMsg(null);
        }}
      />
      <details style={{ margin: "6px 0" }}>
        <summary className="muted">抽样试解析(可选,粘贴若干行样本)</summary>
        <textarea
          className="yaml-box"
          style={{ minHeight: 70, marginTop: 4 }}
          spellCheck={false}
          placeholder="粘贴日志样本行,校验时复用真实引擎跑前 3 行预览"
          value={sampleText}
          onChange={(e) => setSampleText(e.target.value)}
        />
      </details>
      <div className="form-row">
        <button onClick={doValidate} disabled={validating || !yaml.trim()}>
          {validating ? "校验中…" : "校验并预览"}
        </button>
        <button className="primary" onClick={doImport} disabled={importing || !yaml.trim()}>
          {importing ? "导入中…" : "导入(恒 draft)"}
        </button>
        <span className="muted">导入不启用:人审流转至 enable 后才可用于解析。</span>
      </div>
      {error && <div className="form-error" style={{ marginTop: 6 }}>{error}</div>}
      {okMsg && <div className="form-ok" style={{ marginTop: 6 }}>{okMsg}</div>}
      {valResult && <ValidateResult result={valResult} />}
    </div>
  );
}

function ValidateResult({ result }) {
  if (!result.ok) {
    return (
      <div className="bad-box" style={{ marginTop: 8 }}>
        校验未通过:
        {(result.errors || []).map((e, i) => (
          <div key={i} className="mono" style={{ marginTop: 4 }}>{e}</div>
        ))}
      </div>
    );
  }
  const p = result.preview;
  return (
    <div style={{ marginTop: 8 }}>
      <div className="form-ok">
        校验通过:name={result.spec?.name} · kind={result.spec?.kind} · 字段{" "}
        {(result.spec?.fields || []).join(", ") || "—"}
      </div>
      {p && (
        <div style={{ marginTop: 6 }}>
          <div className="muted">
            抽样试解析:共 {p.total_lines} 行 · 解析成功 {p.parsed} · 坏行 {p.bad_lines} ·
            跳过 {p.skipped_lines}
            {p.warning && <span className="form-note">;{p.warning}</span>}
          </div>
          {p.events?.length > 0 && (
            <table className="preview-table">
              <thead>
                <tr><th>行号</th><th>ts_raw</th><th>抽样解析预览(归一字段)</th></tr>
              </thead>
              <tbody>
                {p.events.slice(0, 3).map((ev) => (
                  <tr key={ev.line_no}>
                    <td>{ev.line_no}</td>
                    <td>{ev.ts_raw ?? "—"}</td>
                    <td>{JSON.stringify(ev.norm)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {p.bad_samples?.length > 0 && (
            <div className="bad-box">
              坏行样本(如实):
              {p.bad_samples.map((s, i) => (
                <div key={i} className="mono">{s}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------- 手动导入区 */

function ImportSection({ onImported }) {
  const [yaml, setYaml] = useState("");
  return (
    <div className="section">
      <div className="section-title">导入描述文件(YAML)</div>
      <YamlEditor yaml={yaml} setYaml={setYaml} onImported={onImported} />
    </div>
  );
}

/* ------------------------------------------------------------- AI 起草区 */

function AiDraftSection({ sources, onImported }) {
  const [sourceId, setSourceId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [meta, setMeta] = useState(null); // {model, sampled_lines, source_id}
  const [yaml, setYaml] = useState("");

  async function run() {
    if (!sourceId) return;
    setBusy(true);
    setError(null);
    setMeta(null);
    try {
      const r = await api.draftFormat(sourceId);
      setYaml(r.draft_yaml || "");
      setMeta(r);
    } catch (err) {
      // 503 无 AI 档 / 502 AI 输出坏 / 409 金库哈希不符,原文如实
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="section">
      <div className="section-title">AI 起草格式(§4.4)</div>
      {sources.length === 0 ? (
        <div className="muted">本案件暂无日志源;先在「日志源」tab 上传登记。</div>
      ) : (
        <div className="form-row">
          <label>
            已登记源
            <select value={sourceId} onChange={(e) => setSourceId(e.target.value)}>
              <option value="">请选择…</option>
              {sources.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}({s.status})
                </option>
              ))}
            </select>
          </label>
          <button className="primary" onClick={run} disabled={busy || !sourceId}>
            {busy ? "AI 起草中…" : "AI 起草格式"}
          </button>
          <span className="muted">抽源头部样本行给 AI 提议;草稿不落盘。</span>
        </div>
      )}
      {error && <div className="form-error" style={{ marginTop: 6 }}>{error}</div>}
      {meta && (
        <div style={{ marginTop: 8 }}>
          <div className="ai-draft-warn">
            AI 草稿≠可用格式,人审后才生效。{meta.note || ""}
          </div>
          <div className="muted" style={{ marginBottom: 6 }}>
            模型 {meta.model || "未知"} · 抽样 {meta.sampled_lines} 行;请人工审阅编辑后再校验/导入。
          </div>
          <YamlEditor yaml={yaml} setYaml={setYaml} onImported={onImported} />
        </div>
      )}
    </div>
  );
}
