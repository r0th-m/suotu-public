import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

// M5:命中卡 / 检索结果行共用的二次排查动作菜单(§1:动作只铺路不裁决——
// 跳检索、聚类、追问都是给人递证据,结论仍由人做,机器永不自动定论)。
// 四个动作:提取该实体全部事件 / 按字段再聚类 / 时间窗展开(±5 分钟)/ 送交流区追问。

// 聚类可选字段(与后端 aggregate field 白名单对齐;越界后端 422 如实提示)
const AGG_FIELDS = [
  "src_ip", "ua", "method", "status", "path", "query", "referer", "bytes",
  "actor", "action", "object", "result", "level", "logger", "message",
];

// 命中 ts_utc ±minutes 分钟 → UTC naive ISO 时间窗(检索层 ts_from/ts_to)
function tsWindow(tsUtc, minutes = 5) {
  if (!tsUtc) return null;
  const s = /Z$|[+-]\d{2}:?\d{2}$/.test(tsUtc) ? tsUtc : `${tsUtc}Z`;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return null;
  const iso = (x) => x.toISOString().replace(/\.\d{3}Z$/, "");
  return {
    tsFrom: iso(new Date(d.getTime() - minutes * 60000)),
    tsTo: iso(new Date(d.getTime() + minutes * 60000)),
  };
}

// entity: {field, value} | null;hitId 可空(检索结果行无命中 id,建会话不带 from_hit_id)
export default function HitActions({
  caseId, entity, tsUtc, hitId, contextText, onGotoSearch, onSendToChat,
}) {
  const [aggOpen, setAggOpen] = useState(false);
  const [chatBusy, setChatBusy] = useState(false);
  const win = tsWindow(tsUtc, 5);

  function extractEntity() {
    if (!entity) return;
    onGotoSearch({ filters: [{ field: entity.field, op: "eq", value: entity.value }] });
  }

  async function sendToChat() {
    setChatBusy(true);
    try {
      await onSendToChat({ hitId, contextText });
    } finally {
      // 成败都由 App 统一处理(成功切交流区,失败全局错误条),这里只复位 busy
      setChatBusy(false);
    }
  }

  return (
    <div className="hit-actions">
      <span className="muted">二次排查:</span>
      <button
        disabled={!entity}
        title={entity ? `跳「检索」精确匹配 ${entity.field}=${entity.value} 的全部事件` : "该条无可提取的归一实体字段"}
        onClick={extractEntity}
      >
        提取实体事件
      </button>
      <button title="选字段对全案件事件做聚类分布,bucket 可点跳检索" onClick={() => setAggOpen(true)}>
        按字段再聚类
      </button>
      <button
        disabled={!win}
        title={win ? "跳「检索」带该条 ts_utc ±5 分钟时间窗" : "该条 ts_utc 未归一,无法展开时间窗"}
        onClick={() => win && onGotoSearch(win)}
      >
        时间窗 ±5 分钟
      </button>
      <button
        disabled={chatBusy}
        title="新建交流区会话(命中带 from_hit_id 上下文)并预填追问"
        onClick={sendToChat}
      >
        {chatBusy ? "创建会话…" : "送交流区追问"}
      </button>
      {aggOpen && (
        <AggregateModal
          caseId={caseId}
          onPick={(field, value) => {
            setAggOpen(false);
            onGotoSearch({ filters: [{ field, op: "eq", value }] });
          }}
          onClose={() => setAggOpen(false)}
        />
      )}
    </div>
  );
}

/* ------------------------------------------------------------ 按字段再聚类 */

function AggregateModal({ caseId, onPick, onClose }) {
  const [field, setField] = useState("src_ip");
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(
    async (f) => {
      setBusy(true);
      setError(null);
      try {
        setData(await api.aggregate(caseId, { field: f, limit: 20 }));
      } catch (err) {
        setData(null);
        setError(err.message); // 字段越白名单等 422 如实提示
      } finally {
        setBusy(false);
      }
    },
    [caseId]
  );

  useEffect(() => {
    load(field);
  }, [load, field]);

  const buckets = data?.buckets || [];
  const max = Math.max(1, ...buckets.map((b) => b.count));

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>按字段再聚类(全案件)</span>
          <button className="link-btn" onClick={onClose}>关闭</button>
        </div>
        <div className="form-row" style={{ marginBottom: 8 }}>
          <label>
            字段
            <select value={field} onChange={(e) => setField(e.target.value)} disabled={busy}>
              {AGG_FIELDS.map((f) => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
          </label>
          {busy && <span className="muted">聚合中…</span>}
          {data && (
            <span className="muted">
              共 {data.total_events} 个事件 · Top {buckets.length} 桶
            </span>
          )}
        </div>
        {error && <div className="form-error">{error}</div>}
        {data && buckets.length === 0 && (
          <div className="muted">无分布数据(该字段在已入库事件中缺失,如实为空)。</div>
        )}
        {buckets.length > 0 && (
          <>
            <table className="kv-table">
              <thead>
                <tr>
                  <th>值(点击跳检索)</th>
                  <th style={{ width: 70 }}>count</th>
                  <th style={{ width: 180 }}>占比条</th>
                </tr>
              </thead>
              <tbody>
                {buckets.map((b, i) => (
                  <tr key={i}>
                    <td>
                      <button
                        className="link-btn mono"
                        title={`跳「检索」精确匹配 ${field}=${String(b.value)}`}
                        onClick={() => onPick(field, String(b.value))}
                      >
                        {String(b.value ?? "—")}
                      </button>
                    </td>
                    <td>{b.count}</td>
                    <td>
                      <span className="confidence-bar" style={{ width: 160 }}>
                        <i style={{ width: `${Math.round((b.count / max) * 100)}%` }} />
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
              分布 ≠ 异常:高频可能只是正常业务,低频也未必可疑,交人复核。
            </div>
          </>
        )}
      </div>
    </div>
  );
}
