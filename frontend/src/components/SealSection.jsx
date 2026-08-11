import { useState } from "react";
import { api } from "../api.js";
import { shortSha } from "../util.js";

// M4 封存导出(§1):一案可封存(只读,不锁案件)+ 独立校验封存包。
export default function SealSection({ caseId }) {
  return (
    <div className="section">
      <div className="section-title">封存导出</div>
      <SealCase caseId={caseId} />
      <details style={{ marginTop: 8 }}>
        <summary className="muted">校验封存包(独立校验,不依赖平台数据)</summary>
        <VerifySeal />
      </details>
    </div>
  );
}

function SealCase({ caseId }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.sealCase(caseId));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="form-row">
        <button className="primary" onClick={run} disabled={busy}>
          {busy ? "封存中…" : "封存案件"}
        </button>
        <span className="muted">
          打包 case.db 快照 + 金库原文 + manifest + 审计链;封存不冻结,继续分析请重新打包。
        </span>
      </div>
      {error && <div className="form-error" style={{ marginTop: 6 }}>{error}</div>}
      {result && (
        <div className="detail-block">
          <div>
            封存包:<span className="mono">{result.export_file}</span>
          </div>
          <div className="muted" style={{ marginTop: 4 }}>
            封存时间 <span className="mono">{result.sealed_at}</span> · case.db sha256{" "}
            <span className="mono" title={result.case_db_sha256}>
              {shortSha(result.case_db_sha256)}
            </span>{" "}
            · 日志源 {result.sources} · 金库文件 {result.vault_copied} 个
            {result.vault_missing?.length > 0 && (
              <span className="form-note">
                ;金库缺失 {result.vault_missing.length} 个(零静默):
                {result.vault_missing.join("、")}
              </span>
            )}
          </div>
          {result.audit && (
            <div style={{ marginTop: 4 }}>
              审计链 {result.audit.count} 条,封存时校验{" "}
              {result.audit.chain_ok_at_seal ? (
                <span className="badge badge-ok">通过</span>
              ) : (
                <span className="badge badge-danger">
                  未通过:{result.audit.chain_message_at_seal || "见 manifest"}
                </span>
              )}
            </div>
          )}
          {result.note && <div className="muted" style={{ marginTop: 4 }}>{result.note}</div>}
        </div>
      )}
    </div>
  );
}

function VerifySeal() {
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  async function run() {
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.verifySeal(file));
    } catch (err) {
      setError(err.message); // 422 非可读 zip,原文如实
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ marginTop: 6 }}>
      <div className="form-row">
        <input
          type="file"
          accept=".zip"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />
        <button onClick={run} disabled={busy || !file}>
          {busy ? "校验中…" : "校验封存包"}
        </button>
      </div>
      {error && <div className="form-error" style={{ marginTop: 6 }}>{error}</div>}
      {result && (
        <div className="detail-block">
          {result.ok ? (
            <span className="badge badge-ok">校验通过</span>
          ) : (
            <span className="badge badge-danger">校验未通过</span>
          )}
          <table className="kv-table">
            <tbody>
              {(result.checks || []).map((c, i) => (
                <tr key={i}>
                  <td style={{ width: 160 }}>{c.name}</td>
                  <td style={{ width: 60 }}>
                    {c.ok ? (
                      <span className="form-ok">✓</span>
                    ) : (
                      <span className="form-error">✗</span>
                    )}
                  </td>
                  <td className={c.ok ? "" : "form-error"}>{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {result.failures?.length > 0 && (
            <div className="bad-box">
              失败项:
              {result.failures.map((f, i) => (
                <div key={i} className="mono">{f}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
