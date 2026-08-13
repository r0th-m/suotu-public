import { useEffect, useState } from "react";
import { api } from "../api.js";

/**
 * MCP 接入面板(2026-08-13):端点开关 + token 签发/吊销 + 接入说明。
 * 镣铐前端化:页面写死「只读/候选/裁决在 Web 端」三条纪律。
 */
export default function McpModal({ onClose, showToast }) {
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [label, setLabel] = useState("");
  const [newToken, setNewToken] = useState(null); // 刚签发的明文(仅此一次)

  const refresh = async () => {
    try {
      setStatus(await api.mcpStatus());
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const toggle = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.mcpSetEnabled(!status.enabled);
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.mcpCreateToken(label.trim() || undefined);
      setNewToken(r.token);
      setLabel("");
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (id) => {
    setBusy(true);
    setError(null);
    try {
      await api.mcpRevokeToken(id);
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const copy = (text) => {
    navigator.clipboard?.writeText(text);
    showToast?.("已复制");
  };

  const mcpUrl = `${location.protocol}//${location.host}/mcp`;

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal account-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">MCP 接入(Cherry Studio / Trae 等)</span>
          <button className="link-btn" onClick={onClose}>关闭</button>
        </div>
        <div className="account-body">
          {error && <div className="form-error">{error}</div>}
          {!status && !error && <div className="muted">读取中…</div>}
          {status && !status.available && (
            <div className="muted">本部署形态不含 MCP 模块(现场便携包)。</div>
          )}
          {status && status.available && (
            <>
              <div className="form-row">
                <span>
                  端点状态:
                  <b className={status.enabled ? "form-ok" : ""}>
                    {status.enabled ? "已开启" : "已关闭(默认)"}
                  </b>
                </span>
                <button disabled={busy} onClick={toggle}>
                  {status.enabled ? "关闭端点" : "开启端点"}
                </button>
              </div>
              <div className="form-row">
                <span className="muted">接入地址:</span>
                <code className="mono">{mcpUrl}</code>
                <button className="link-btn" onClick={() => copy(mcpUrl)}>
                  复制
                </button>
              </div>
              <div className="account-note">
                客户端配置:类型选「Streamable HTTP」,地址如上,请求头加
                <code className="mono">Authorization: Bearer &lt;token&gt;</code>。
              </div>
              <hr />
              <div className="form-row">
                <input
                  placeholder="token 备注(如:我的 Trae)"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                />
                <button className="primary" disabled={busy} onClick={create}>
                  签发 token
                </button>
              </div>
              {newToken && (
                <div className="form-ok">
                  新 token(明文只显示这一次):
                  <code className="mono">{newToken}</code>
                  <button className="link-btn" onClick={() => copy(newToken)}>
                    复制
                  </button>
                </div>
              )}
              <ul className="token-list">
                {(status.tokens || []).map((t) => (
                  <li key={t.id}>
                    <span className="mono">{t.label || t.id}</span>{" "}
                    <span className="muted">
                      {t.username} · {(t.created_at || "").slice(0, 10)}
                      {t.last_used_at
                        ? ` · 最近用 ${t.last_used_at.slice(0, 10)}`
                        : " · 未使用"}
                    </span>{" "}
                    {t.revoked_at ? (
                      <span className="badge badge-muted">已吊销</span>
                    ) : (
                      <button
                        className="link-btn danger-text"
                        disabled={busy}
                        onClick={() => revoke(t.id)}
                      >
                        吊销
                      </button>
                    )}
                  </li>
                ))}
              </ul>
              <hr />
              <div className="account-note">
                纪律(协议层写死):MCP 通道<b>只读</b>——不能上传/解析/改裁决/
                跑扫描;AI 排查出的内容恒为候选,具体日志原文请回 Web 端
                「查看」tab 按锚点核对;<b>最终裁决与研判必须在 Web 端由人完成</b>。
                每次调用都记审计链,可随时吊销 token。
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
