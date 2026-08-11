import { useEffect, useState } from "react";
import { api } from "../api.js";

// 查看器(金库原文带行号,读前 SHA256 校验);viewer 状态由 App 持有,
// 检索结果/待审区命中/线索锚点可一键跳本 tab 对应行。
export default function ViewerPane({ caseDetail, viewer, setViewer }) {
  const sources = caseDetail.sources || [];
  const [limit, setLimit] = useState(200);
  const [jump, setJump] = useState("");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const { sourceId, offset, highlight } = viewer;

  useEffect(() => {
    if (!sourceId) {
      setData(null);
      return;
    }
    let cancelled = false;
    setBusy(true);
    setError(null);
    api
      .sourceLines(sourceId, offset, limit)
      .then((r) => !cancelled && setData(r))
      .catch((err) => !cancelled && setError(err.message))
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [sourceId, offset, limit]);

  const total = data?.total_lines; // 未解析源为 null,如实显示

  return (
    <div className="pane">
      <div className="pane-header">
        <h2>
          查看 <span className="muted">金库原文 · 读前 SHA256 校验 · 行号锚点</span>
        </h2>
      </div>
      <div className="form-row" style={{ marginBottom: 8 }}>
        <label>
          日志源
          <select
            value={sourceId}
            onChange={(e) => setViewer({ sourceId: e.target.value, offset: 0, highlight: null })}
          >
            <option value="">— 选择日志源 —</option>
            {sources.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </label>
        <label>
          每页
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {[50, 100, 200, 500].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </label>
        <label>
          跳到行
          <input
            style={{ width: 90 }}
            placeholder="行号"
            value={jump}
            onChange={(e) => setJump(e.target.value)}
          />
        </label>
        <button
          disabled={!sourceId || !/^\d+$/.test(jump)}
          onClick={() => {
            const ln = Number(jump);
            setViewer({ sourceId, offset: Math.max(0, ln - 1), highlight: ln });
          }}
        >
          跳转
        </button>
        {data && (
          <span className="muted">
            {data.name} · 总行数 {total ?? "未知(未解析)"} · 当前 {offset + 1}–{offset + data.lines.length}
          </span>
        )}
      </div>
      {error && <div className="form-error">{error}</div>}
      {!sourceId && <div className="muted">请选择日志源;或在检索结果/待审区中点击行号直接跳转。</div>}
      {sourceId && busy && <div className="muted">读取中(读前 SHA256 校验)…</div>}
      {data && data.lines.length === 0 && !busy && (
        <div className="muted">该区间无内容。</div>
      )}
      {data && data.lines.length > 0 && (
        <>
          <table className="viewer-table">
            <tbody>
              {data.lines.map((l) => (
                <tr key={l.line_no} className={l.line_no === highlight ? "hl" : ""}>
                  <td className="ln">{l.line_no}</td>
                  <td>{l.text}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="pager">
            <button
              disabled={offset === 0 || busy}
              onClick={() => setViewer({ sourceId, offset: Math.max(0, offset - limit), highlight: null })}
            >
              上一页
            </button>
            <button
              disabled={data.lines.length < limit || busy}
              onClick={() => setViewer({ sourceId, offset: offset + limit, highlight: null })}
            >
              下一页
            </button>
          </div>
        </>
      )}
    </div>
  );
}
