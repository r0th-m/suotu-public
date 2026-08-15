import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

// 记录区(案件日志流):扫描轮次/AI 分析自动条目(台账读取时合成,不双写)
// + 人工笔记,统一按时间倒序。
// 文案纪律(§1):自动条目是系统台账的如实转述;笔记是工作记录(非证据),
// 仅本人可删;锚点可点击跳转到对应 tab(由 App 状态提升联动)。
const KIND_LABEL = { scan: "扫描", ai: "AI", note: "笔记" };
const KIND_BADGE = { scan: "badge-info", ai: "badge-bolt", note: "badge-warn" };

const ANCHOR_KINDS = [
  { id: "", name: "无锚点" },
  { id: "hit", name: "候选命中", hint: "命中 id(待审区条目 id)" },
  { id: "scan_round", name: "扫描轮次", hint: "轮次号,如 2" },
  { id: "analysis_run", name: "AI 分析 run", hint: "run id(AI 分析页可查)" },
  { id: "line", name: "原文行", hint: "坐标:日志源 id:行号" },
];

const PAGE_SIZE = 50;

export default function JournalPane({ caseDetail, me, onJumpAnchor }) {
  const [data, setData] = useState(null);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(
    async (off) => {
      setBusy(true);
      setError(null);
      try {
        const r = await api.getJournal(caseDetail.id, {
          limit: PAGE_SIZE,
          offset: off,
        });
        setData(r);
        setOffset(off);
      } catch (err) {
        setError(err.message);
      } finally {
        setBusy(false);
      }
    },
    [caseDetail.id]
  );

  useEffect(() => {
    setOffset(0);
    load(0);
  }, [load]);

  return (
    <div className="pane">
      <div className="advice-note">
        记录区 = 案件日志流:扫描/AI 条目是台账的如实转述(读取时合成),
        人工笔记是工作记录——都不是结论,判断权归人。
      </div>

      <NoteEditor caseId={caseDetail.id} onAdded={() => load(0)} />

      {error && <div className="form-error">{error}</div>}
      {busy && <div className="muted">加载中…</div>}
      {data && data.total === 0 && (
        <div className="muted">
          本案件暂无记录:跑一轮规则扫描、发起一次 AI 分析或写一条笔记后即出现在这里。
        </div>
      )}
      {data &&
        data.items.map((e, i) => (
          <JournalEntry
            key={`${e.kind}-${e.ts}-${i}`}
            entry={e}
            me={me}
            onJumpAnchor={onJumpAnchor}
            onDeleted={() => load(offset)}
          />
        ))}
      {data && data.total > PAGE_SIZE && (
        <div className="pager">
          <button disabled={offset === 0 || busy} onClick={() => load(Math.max(0, offset - PAGE_SIZE))}>
            上一页
          </button>
          <button disabled={offset + PAGE_SIZE >= data.total || busy} onClick={() => load(offset + PAGE_SIZE)}>
            下一页
          </button>
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------- 笔记编辑器 */

function NoteEditor({ caseId, onAdded }) {
  const [body, setBody] = useState("");
  const [anchorKind, setAnchorKind] = useState("");
  const [anchorRef, setAnchorRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.addNote(caseId, {
        body,
        anchorKind: anchorKind || undefined,
        anchorRef: anchorRef.trim() || undefined,
      });
      setBody("");
      setAnchorKind("");
      setAnchorRef("");
      onAdded?.();
    } catch (err) {
      setError(err.message); // 422 等如实提示(锚点不存在/正文超长)
    } finally {
      setBusy(false);
    }
  }

  const kind = ANCHOR_KINDS.find((k) => k.id === anchorKind);
  return (
    <div className="section">
      <div className="section-title">写笔记(工作记录,非证据;仅本人可删)</div>
      <textarea
        style={{ width: "100%", minHeight: 70 }}
        placeholder="排查进展/假设/结论备忘…(≤4000 字)"
        value={body}
        onChange={(e) => setBody(e.target.value)}
      />
      <div className="form-row" style={{ marginTop: 4 }}>
        <label>
          锚点(可选)
          <select value={anchorKind} onChange={(e) => setAnchorKind(e.target.value)}>
            {ANCHOR_KINDS.map((k) => (
              <option key={k.id} value={k.id}>{k.name}</option>
            ))}
          </select>
        </label>
        {anchorKind && (
          <input
            style={{ minWidth: 260 }}
            className="mono"
            placeholder={kind?.hint || ""}
            value={anchorRef}
            onChange={(e) => setAnchorRef(e.target.value)}
          />
        )}
        <button className="primary" onClick={submit} disabled={busy || !body.trim()}>
          {busy ? "保存中…" : "保存笔记"}
        </button>
      </div>
      {anchorKind && (
        <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
          {kind?.hint};保存时后端校验引用对象存在,不存在 422 如实报错。
        </div>
      )}
      {error && <div className="form-error" style={{ marginTop: 4 }}>{error}</div>}
    </div>
  );
}

/* -------------------------------------------------------------- 流条目 */

function anchorLabel(anchor) {
  if (!anchor) return null;
  switch (anchor.kind) {
    case "hit": return "候选命中";
    case "scan_round": return `第 ${anchor.ref} 轮扫描`;
    case "analysis_run": return "AI 分析 run";
    case "line": return `原文 ${anchor.ref}`;
    default: return anchor.kind;
  }
}

function JournalEntry({ entry, me, onJumpAnchor, onDeleted }) {
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const isOwnNote = entry.kind === "note" && entry.author === me;

  async function remove() {
    if (!window.confirm("删除这条笔记?(物理删除,审计留痕)")) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteNote(entry.meta.note_id);
      onDeleted?.();
    } catch (err) {
      setError(err.message); // 他人笔记 403 如实
      setBusy(false);
    }
  }

  return (
    <div className="result-row">
      <div className="result-head">
        <span className={`badge ${KIND_BADGE[entry.kind] || "badge-muted"}`}>
          {KIND_LABEL[entry.kind] || entry.kind}
        </span>
        <span style={{ fontWeight: 600 }}>{entry.title}</span>
        {entry.anchor && (
          <button
            className="badge badge-info link-badge"
            title="点击跳转到锚点对象"
            onClick={() => onJumpAnchor?.(entry.anchor)}
          >
            ⚓ {anchorLabel(entry.anchor)}
          </button>
        )}
        <span className="mono muted">{entry.ts}</span>
        <span className="muted">{entry.author || "—"}</span>
        {isOwnNote && (
          <button className="link-btn" onClick={remove} disabled={busy}>
            {busy ? "删除中…" : "删除"}
          </button>
        )}
      </div>
      <div style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", marginTop: 2 }}>
        {entry.body}
      </div>
      {entry.kind === "scan" && entry.meta?.rule_ids && (
        <div className="mono muted" style={{ fontSize: 12, marginTop: 2 }}>
          规则:{entry.meta.rule_ids.join("、")}
        </div>
      )}
      {error && <div className="form-error" style={{ marginTop: 4 }}>{error}</div>}
    </div>
  );
}
