import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api.js";

// M5 交流区:人机对话(§1 文案哲学——AI 回答 = 推测·待核,不是结论;
// offline_lite 时顶部黄条如实标注诚实降级,不伪装成智能在线)。
export default function ChatPane({ caseDetail, aiStatus, chatInit, onChatInitConsumed }) {
  const caseId = caseDetail.id;
  const [sessions, setSessions] = useState(null);
  const [sid, setSid] = useState(null);
  const [messages, setMessages] = useState(null);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const bottomRef = useRef(null);

  const loadSessions = useCallback(async () => {
    try {
      const r = await api.listChatSessions(caseId);
      setSessions(r.items || []);
    } catch (err) {
      setError(err.message);
    }
  }, [caseId]);

  const loadMessages = useCallback(async (id) => {
    try {
      const r = await api.listChatMessages(id);
      setMessages(r.items || []);
    } catch (err) {
      setError(err.message);
      setMessages([]);
    }
  }, []);

  // 切案件:清空会话状态重拉
  useEffect(() => {
    setSessions(null);
    setSid(null);
    setMessages(null);
    setInput("");
    setError(null);
    loadSessions();
  }, [loadSessions]);

  useEffect(() => {
    if (sid) loadMessages(sid);
    else setMessages(null);
  }, [sid, loadMessages]);

  // 新消息到底部
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: "end" });
  }, [messages]);

  // 命中/检索结果「送交流区追问」:选中新建会话 + 预填问题,然后消费掉 chatInit
  useEffect(() => {
    if (!chatInit) return;
    loadSessions();
    setSid(chatInit.sessionId);
    if (chatInit.prefill) setInput(chatInit.prefill);
    onChatInitConsumed?.();
  }, [chatInit, loadSessions, onChatInitConsumed]);

  async function newSession() {
    setBusy(true);
    setError(null);
    try {
      const r = await api.createChatSession(caseId, {});
      await loadSessions();
      setSid(r.id);
      setInput("");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function send() {
    const content = input.trim();
    if (!content || !sid || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.sendChatMessage(sid, content);
      setInput("");
      await loadMessages(sid); // 同步回答已落库,重拉拿权威消息流(含 tool_log/usage)
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const current = (sessions || []).find((s) => s.id === sid);

  return (
    <div className="chat-wrap">
      <div className="chat-sessions">
        <button className="primary" style={{ width: "100%" }} onClick={newSession} disabled={busy}>
          + 新建会话
        </button>
        <div style={{ marginTop: 8 }}>
          {sessions === null && <div className="muted">加载中…</div>}
          {sessions !== null && sessions.length === 0 && (
            <div className="muted">暂无会话。也可在待审区/检索结果上点「送交流区追问」。</div>
          )}
          {(sessions || []).map((s) => (
            <div
              key={s.id}
              className={`chat-session-node${s.id === sid ? " selected" : ""}`}
              onClick={() => setSid(s.id)}
            >
              <div className="chat-session-title">
                {s.title || `会话 #${s.id}`}
                {s.from_hit_id ? <span className="badge badge-info">命中 #{s.from_hit_id}</span> : null}
              </div>
              <div className="case-meta">{s.created_at || s.ts || ""}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="chat-main">
        {aiStatus && !aiStatus.available && (
          <div className="banner banner-warn">
            AI 未配置·诚实降级:{aiStatus.note || "回答为确定性降级文案,不伪装成 AI 推理;L1/L2 确定性分析不受影响。"}
          </div>
        )}
        <div className="advice-note" style={{ margin: "8px 16px 0" }}>
          AI 回答 = 推测·待核:内容仅供人研判参考,结论与入库永远由人点头(§1)。
        </div>
        <div className="chat-msgs">
          {!sid && <div className="muted">请选择左侧会话,或新建一个。</div>}
          {sid && messages === null && <div className="muted">加载中…</div>}
          {sid && current?.from_hit_id && (
            <div className="msg-sys">本会话围绕命中 #{current.from_hit_id} 展开(候选 ≠ 结论)</div>
          )}
          {(messages || []).map((m) => (
            <Msg key={m.id} m={m} />
          ))}
          <div ref={bottomRef} />
        </div>
        {error && (
          <div className="form-error" style={{ padding: "0 16px" }}>{error}</div>
        )}
        <div className="chat-input-row">
          <textarea
            className="chat-input"
            rows={2}
            placeholder={sid ? "输入追问…(Ctrl+Enter 发送)" : "先选择或新建会话"}
            value={input}
            disabled={!sid || busy}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) send();
            }}
          />
          <button className="primary" onClick={send} disabled={!sid || busy || !input.trim()}>
            {busy ? "发送中…" : "发送"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------- 消息气泡 */

// tool_log_json / usage_json 容错解析:坏 JSON 不崩,返回 null 不展示
function parseJsonSafe(v) {
  if (v == null || v === "") return null;
  if (typeof v === "object") return v;
  try {
    return JSON.parse(v);
  } catch {
    return null;
  }
}

function usageText(u) {
  if (!u || typeof u !== "object") return null;
  const entries = Object.entries(u).filter(([, v]) => v != null);
  if (!entries.length) return null;
  return `usage: ${entries.map(([k, v]) => `${k}=${v}`).join(" · ")}`;
}

function Msg({ m }) {
  if (m.role === "system") {
    return <div className="msg-sys">{m.content}</div>;
  }
  const isUser = m.role === "user";
  const toolLog = parseJsonSafe(m.tool_log_json);
  const usage = parseJsonSafe(m.usage_json);
  const usageLine = usageText(usage);
  return (
    <div className={`msg-row ${isUser ? "user" : "ai"}`}>
      <div className="msg-bubble">
        {!isUser && (
          <div className="msg-meta">
            <span className="badge badge-warn" title="AI 输出仅供研判参考,结论由人做">
              AI 推测·待核
            </span>
          </div>
        )}
        <div className="msg-content">{m.content}</div>
        {!isUser && <ToolLog log={toolLog} />}
        {!isUser && usageLine && <div className="msg-meta mono">{usageLine}</div>}
        {m.ts && <div className="msg-meta">{m.ts}</div>}
      </div>
    </div>
  );
}

function ToolLog({ log }) {
  if (!log) return null;
  const items = (Array.isArray(log) ? log : [log]).filter(Boolean);
  if (!items.length) return null;
  const short = (o) => {
    if (o == null) return "—";
    const s = typeof o === "string" ? o : JSON.stringify(o);
    return s.length > 120 ? `${s.slice(0, 120)}…` : s;
  };
  return (
    <details className="norm-detail">
      <summary>调用了 {items.length} 个工具</summary>
      <table className="kv-table">
        <thead>
          <tr>
            <th style={{ width: 140 }}>工具</th>
            <th>参数摘要</th>
            <th style={{ width: 70 }}>结果数</th>
          </tr>
        </thead>
        <tbody>
          {items.map((t, i) => (
            <tr key={i}>
              <td>{t.tool ?? t.name ?? t.tool_name ?? "?"}</td>
              <td>{short(t.args ?? t.params ?? t.arguments)}</td>
              <td>
                {t.result_count ?? t.count ?? (Array.isArray(t.results) ? t.results.length : "—")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}
