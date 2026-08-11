import { useState } from "react";
import { api } from "../api.js";

// 案件栏:案件列表 + 新建案件 + 按案件「禁止 AI 外发」开关(合规闸)。
export default function CaseSidebar({ cases, currentId, onSelect, onCreated, onPolicyChanged }) {
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function submit(e) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const c = await api.createCase(name.trim());
      setName("");
      setCreating(false);
      onCreated(c.id);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-title">案件</div>
      {cases.length === 0 && !creating && (
        <div className="case-empty">暂无案件,请新建。</div>
      )}
      <ul className="case-list">
        {cases.map((c) => (
          <li
            key={c.id}
            className={`case-node${c.id === currentId ? " selected" : ""}`}
            onClick={() => onSelect(c.id)}
          >
            <span className="case-name">{c.name}</span>
            <span className="case-meta">{(c.created_at || "").slice(0, 19).replace("T", " ")}</span>
            <button
              className={`link-btn case-ai-btn${c.ai_external_blocked ? " danger-text" : ""}`}
              title={c.ai_external_blocked
                ? "本案已禁止 AI 外发(在线调用被拒;本地 Ollama 可用)——点击解除"
                : "本案允许 AI 外发——点击设为「禁止 AI 外发」(合规开关,审计留痕)"}
              onClick={async (e) => {
                e.stopPropagation();
                const next = !c.ai_external_blocked;
                await api.setCaseAiPolicy(c.id, next);
                onPolicyChanged?.(next);
              }}
            >
              {c.ai_external_blocked ? "🔒AI" : "🌐AI"}
            </button>
          </li>
        ))}
      </ul>
      {creating ? (
        <form className="inline-form" onSubmit={submit}>
          <input
            autoFocus
            placeholder="案件名称(如:XX 系统入侵应急)"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          {error && <div className="form-error">{error}</div>}
          <div className="form-row">
            <button className="primary" type="submit" disabled={busy || !name.trim()}>
              创建
            </button>
            <button type="button" onClick={() => setCreating(false)} disabled={busy}>
              取消
            </button>
          </div>
        </form>
      ) : (
        <button className="new-case" onClick={() => setCreating(true)}>
          + 新建案件
        </button>
      )}
    </aside>
  );
}
