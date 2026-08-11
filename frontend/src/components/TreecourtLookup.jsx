import { useEffect, useState } from "react";
import { api } from "../api.js";

// M4 主机取证平台互查弹层(§9 实体桥,只读):按值查主机取证平台各案件/主机该实体出现情况。
// available=false(未配置凭据/不可达/认证失败)→ 如实显示 reason,不报错页。
export default function TreecourtLookup({ initialValue = "", onClose }) {
  const [value, setValue] = useState(initialValue);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);

  async function run(v) {
    const q = (v ?? value).trim();
    if (!q) return;
    setBusy(true);
    setError(null);
    try {
      setData(await api.treecourtEntities(q));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  // 带初始值打开时自动查询一次
  useEffect(() => {
    if (initialValue.trim()) run(initialValue);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>主机取证平台互查(跨平台实体,只读)</span>
          <button className="link-btn" onClick={onClose}>关闭</button>
        </div>
        <div className="form-row">
          <input
            style={{ flex: 1, minWidth: 200 }}
            placeholder="实体值,如 IP / 账号 / 文件名"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
          />
          <button className="primary" onClick={() => run()} disabled={busy || !value.trim()}>
            {busy ? "查询中…" : "查询"}
          </button>
        </div>
        {error && <div className="form-error" style={{ marginTop: 6 }}>{error}</div>}
        {data && !data.available && (
          <div className="bad-box" style={{ marginTop: 8 }}>
            互查不可用:{data.reason || "原因未知"}
          </div>
        )}
        {data && data.available && (
          <div style={{ marginTop: 8 }}>
            {(data.results || []).length === 0 ? (
              <div className="muted">主机取证平台侧无该实体命中。</div>
            ) : (
              <table className="kv-table">
                <thead>
                  <tr>
                    <th>案件</th>
                    <th>主机</th>
                    <th>实体</th>
                    <th>次数</th>
                    <th>canonical_key</th>
                  </tr>
                </thead>
                <tbody>
                  {data.results.map((r, i) => (
                    <tr key={i}>
                      <td>{r.case}</td>
                      <td>{r.host}</td>
                      <td className="mono">{r.entity}</td>
                      <td>{r.count}</td>
                      <td className="mono muted">{r.canonical_key || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <div className="muted" style={{ marginTop: 6 }}>
              跨平台结果仅供人工参考,索图不据此自动下结论。
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
