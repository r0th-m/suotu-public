import { useEffect, useState } from "react";
import { api } from "../api.js";
import { localInputToUtcIso, shortSha, utcIsoToLocalInput } from "../util.js";
import TreecourtLookup from "./TreecourtLookup.jsx";
import HitActions from "./HitActions.jsx";

// 检索区(单一检索层透传):全文词 + 字段条件(IP/UA/方法等,精确/包含)
// + 时间窗 + 源过滤;行号一键跳「查看」tab 对应行。统计聚合附在底部。
const PAGE_SIZE = 50;

// 字段条件的可选字段(norm 归一字段,web 族为主;其他族无该字段=零命中,如实)
const FILTER_FIELDS = ["src_ip", "ua", "method", "status", "path", "query", "referer", "bytes"];

export default function SearchPane({ caseDetail, colorOf, onJump, searchInit, onSearchInitConsumed, onGotoSearch, onSendToChat }) {
  const sources = caseDetail.sources || [];
  const [q, setQ] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [tsFrom, setTsFrom] = useState("");
  const [tsTo, setTsTo] = useState("");
  // 字段条件行:[{field, op, value}];op: eq=精确 / contains=包含
  const [filters, setFilters] = useState([]);
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState(null);
  const [searched, setSearched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  // M4 主机取证平台互查:非 null 时弹层显示;初值为检索词或结果行 src_ip
  const [lookup, setLookup] = useState(null);

  const nameOf = (id) => sources.find((s) => s.id === id)?.name || id;

  function buildFieldFilters(fs) {
    const out = {};
    for (const f of fs) {
      if (!f.value.trim()) continue;
      out[f.field] = f.op === "contains" ? { contains: f.value.trim() } : f.value.trim();
    }
    return Object.keys(out).length ? out : undefined;
  }

  // ov:searchInit 到来时整体覆盖当前条件(避免读未生效的 state);手动检索不传。
  async function run(newOffset, ov) {
    const eff = ov || { q, sourceId, tsFrom, tsTo, filters };
    setBusy(true);
    setError(null);
    try {
      const r = await api.search(caseDetail.id, {
        q: eff.q || undefined,
        sourceId: eff.sourceId || undefined,
        tsFrom: localInputToUtcIso(eff.tsFrom),
        tsTo: localInputToUtcIso(eff.tsTo),
        fieldFilters: buildFieldFilters(eff.filters),
        limit: PAGE_SIZE,
        offset: newOffset,
      });
      setData(r);
      setOffset(newOffset);
      setSearched(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  // M5:命中动作「跳检索」——searchInit 到达时整体重置条件(未提供的项清空)并立即检索。
  useEffect(() => {
    if (!searchInit) return;
    const next = {
      q: searchInit.q || "",
      sourceId: "",
      tsFrom: utcIsoToLocalInput(searchInit.tsFrom),
      tsTo: utcIsoToLocalInput(searchInit.tsTo),
      filters: searchInit.filters || [],
    };
    setQ(next.q);
    setSourceId(next.sourceId);
    setTsFrom(next.tsFrom);
    setTsTo(next.tsTo);
    setFilters(next.filters);
    run(0, next);
    onSearchInitConsumed?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInit]);

  function setFilter(i, patch) {
    setFilters((fs) => fs.map((f, j) => (j === i ? { ...f, ...patch } : f)));
  }

  return (
    <div className="pane">
      <div className="pane-header">
        <h2>
          检索 <span className="muted">全文词 + 字段条件 + 时间窗 + 源(单一检索层)</span>
        </h2>
      </div>
      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          run(0);
        }}
      >
        <div className="form-row">
          <input
            style={{ flex: 1, minWidth: 220 }}
            placeholder="全文检索词(留空 = 仅按条件/时间/源过滤)"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <select value={sourceId} onChange={(e) => setSourceId(e.target.value)}>
            <option value="">全部日志源</option>
            {sources.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </div>

        {filters.map((f, i) => (
          <div className="form-row" key={i}>
            <label>
              字段
              <select value={f.field} onChange={(e) => setFilter(i, { field: e.target.value })}>
                {FILTER_FIELDS.map((k) => (
                  <option key={k} value={k}>{k}</option>
                ))}
              </select>
            </label>
            <label>
              条件
              <select value={f.op} onChange={(e) => setFilter(i, { op: e.target.value })}>
                <option value="eq">精确等于</option>
                <option value="contains">包含子串</option>
              </select>
            </label>
            <input
              style={{ flex: 1, minWidth: 160 }}
              placeholder={f.op === "contains" ? "如:sqlmap(UA 片段)" : "如:203.0.113.9"}
              value={f.value}
              onChange={(e) => setFilter(i, { value: e.target.value })}
            />
            <button type="button" onClick={() => setFilters((fs) => fs.filter((_, j) => j !== i))}>
              移除
            </button>
          </div>
        ))}
        <div className="form-row">
          <button
            type="button"
            onClick={() => setFilters((fs) => [...fs, { field: "src_ip", op: "eq", value: "" }])}
          >
            + 字段条件
          </button>
          <span className="muted">
            多条件 AND;「包含子串」适合 UA/路径片段,「精确等于」适合 IP/状态码/方法。
            字段缺失的族(raw T0/中间件)不参与字段过滤,如实零命中。
          </span>
        </div>

        <div className="form-row">
          <label>
            从
            <input type="datetime-local" value={tsFrom} onChange={(e) => setTsFrom(e.target.value)} />
          </label>
          <label>
            到
            <input type="datetime-local" value={tsTo} onChange={(e) => setTsTo(e.target.value)} />
          </label>
          <span className="muted">时间窗作用于 ts_utc(已归一);本地输入自动换算 UTC。</span>
          <button className="primary" type="submit" disabled={busy}>
            {busy ? "检索中…" : "检索"}
          </button>
          <button
            type="button"
            title="按当前检索词到主机取证平台互查该实体(只读)"
            onClick={() => setLookup(q.trim())}
          >
            主机取证平台互查
          </button>
        </div>
        {error && <div className="form-error">{error}</div>}
      </form>

      {lookup !== null && (
        <TreecourtLookup initialValue={lookup} onClose={() => setLookup(null)} />
      )}

      {searched && data && (
        <div style={{ marginTop: 10 }}>
          <div className="muted" style={{ marginBottom: 6 }}>
            共 {data.total} 条命中
            {data.total > 0 && `,本页 ${offset + 1}–${offset + data.items.length}`}
          </div>
          {data.items.length === 0 && <div className="muted">无命中。</div>}
          {data.items.map((it) => (
            <ResultRow key={it.id} item={it} name={nameOf(it.source_id)} color={colorOf(it.source_id)} onJump={onJump} onLookup={setLookup} caseId={caseDetail.id} onGotoSearch={onGotoSearch} onSendToChat={onSendToChat} />
          ))}
          <div className="pager">
            <button disabled={offset === 0 || busy} onClick={() => run(Math.max(0, offset - PAGE_SIZE))}>
              上一页
            </button>
            <button
              disabled={offset + PAGE_SIZE >= data.total || busy}
              onClick={() => run(offset + PAGE_SIZE)}
            >
              下一页
            </button>
          </div>
        </div>
      )}

      <details style={{ marginTop: 18 }}>
        <summary className="muted">统计聚合(Top IP / 状态码分布,点开展开)</summary>
        <StatsView caseDetail={caseDetail} colorOf={colorOf} />
      </details>
    </div>
  );
}

function ResultRow({ item, name, color, onJump, onLookup, caseId, onGotoSearch, onSendToChat }) {
  const [expand, setExpand] = useState(false);
  const normEntries = Object.entries(item.norm || {});
  const srcIp = item.norm?.src_ip;
  // M5 动作菜单实体:优先 src_ip,其次 UA(§4.5 归一字段,精确匹配)
  const entity = srcIp
    ? { field: "src_ip", value: String(srcIp) }
    : item.norm?.ua
      ? { field: "ua", value: String(item.norm.ua) }
      : null;
  return (
    <div className="result-row">
      <div className="result-head">
        <span>
          <span className="src-dot" style={{ background: color }} />
          {name}
        </span>
        <button className="link-btn mono" title="跳转到查看器对应行" onClick={() => onJump(item.source_id, item.line_no)}>
          L{item.line_no}
        </button>
        {srcIp && (
          <button
            className="link-btn"
            title={`到主机取证平台互查 ${srcIp}(只读)`}
            onClick={() => onLookup(String(srcIp))}
          >
            互查 {srcIp}
          </button>
        )}
        <span className="mono muted">{item.ts_raw ?? "—"}</span>
        {item.ts_utc
          ? <span className="mono muted">UTC {item.ts_utc}</span>
          : <span className="badge badge-warn">时区未归一</span>}
        <span className="mono sha" style={{ marginLeft: "auto" }} title={item.sha256}>
          {shortSha(item.sha256)}
        </span>
      </div>
      <div
        className={`result-raw${expand ? "" : " clamp"}`}
        onClick={() => setExpand((v) => !v)}
        title={expand ? "点击收起" : "点击展开全文"}
      >
        {item.raw}
      </div>
      {normEntries.length > 0 && (
        <details className="norm-detail">
          <summary>归一字段({normEntries.length})</summary>
          <table className="kv-table">
            <tbody>
              {normEntries.map(([k, v]) => (
                <tr key={k}>
                  <td style={{ width: 140, color: "var(--muted)" }}>{k}</td>
                  <td>{typeof v === "object" ? JSON.stringify(v) : String(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
      <HitActions
        caseId={caseId}
        entity={entity}
        tsUtc={item.ts_utc}
        contextText={item.raw}
        onGotoSearch={onGotoSearch}
        onSendToChat={onSendToChat}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ 统计 */

function StatsView({ caseDetail, colorOf }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      setData(await api.stats(caseDetail.id));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseDetail.id]);

  if (error) return <div className="form-error">{error}</div>;
  if (!data) return <div className="muted">{busy ? "统计中…" : "加载中…"}</div>;

  const nameOf = (id) => (caseDetail.sources || []).find((s) => s.id === id)?.name || id;
  const sids = Object.keys(data.by_source || {});

  return (
    <div style={{ marginTop: 8 }}>
      <div className="form-row" style={{ marginBottom: 8 }}>
        <button onClick={load} disabled={busy}>刷新统计</button>
        <span className="muted">字段缺失时如实为空(非 web 格式无 src_ip/状态码字段)。</span>
      </div>
      {sids.length === 0 && <div className="muted">暂无已入库事件。</div>}
      {sids.map((sid) => {
        const st = data.by_source[sid];
        return (
          <div className="section" key={sid}>
            <div className="section-title">
              <span className="src-dot" style={{ background: colorOf(sid) }} />
              {nameOf(sid)}
              <span className="muted" style={{ marginLeft: 10, fontWeight: 400 }}>
                事件 {st.events} · 时间{" "}
                {st.ts_min ? `${st.ts_min} ~ ${st.ts_max}` : "未知(无时区归一)"}
              </span>
            </div>
            <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
              <DistTable title="Top src_ip" rows={st.top_src_ip} />
              <DistTable title="状态码分布" rows={st.status_dist} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DistTable({ title, rows }) {
  return (
    <div style={{ minWidth: 260 }}>
      <div className="muted" style={{ marginBottom: 4 }}>{title}</div>
      {!rows || rows.length === 0 ? (
        <div className="muted">无数据(该源无此字段或未解析)。</div>
      ) : (
        <table className="stats-table">
          <thead>
            <tr><th>值</th><th>次数</th></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.value}>
                <td>{r.value}</td>
                <td>{r.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
