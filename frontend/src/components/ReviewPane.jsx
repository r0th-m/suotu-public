import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { sevBadge, shortSha } from "../util.js";
import HitActions from "./HitActions.jsx";

// 待审区:候选命中的人工裁决(§1 判断权归人——命中只是候选,接受/排除都由人点头)+ 线索列表。
export default function ReviewPane({ caseDetail, colorOf, onJump, onAdjudicated, onGotoSearch, onSendToChat }) {
  const [tab, setTab] = useState("hits");
  // 裁决后让线索列表重新拉取(未打开时不提前请求)。
  const [clueKey, setClueKey] = useState(0);

  function handleAdjudicated() {
    setClueKey((k) => k + 1);
    onAdjudicated?.(); // 刷新 App 的待审计数徽标
  }

  return (
    <div className="pane">
      <div className="advice-note">
        候选 ≠ 结论:以下命中均由规则产生,接受为线索或排除,都由人裁决并留痕;机器永不自动入库。
      </div>
      <div className="subtabs">
        <button className={tab === "hits" ? "primary" : ""} onClick={() => setTab("hits")}>
          候选命中
        </button>
        <button className={tab === "clues" ? "primary" : ""} onClick={() => setTab("clues")}>
          线索列表
        </button>
      </div>
      {tab === "hits" ? (
        <HitsView
          caseDetail={caseDetail}
          colorOf={colorOf}
          onJump={onJump}
          onAdjudicated={handleAdjudicated}
          onGotoSearch={onGotoSearch}
          onSendToChat={onSendToChat}
        />
      ) : (
        <CluesView caseDetail={caseDetail} colorOf={colorOf} onJump={onJump} refreshKey={clueKey} />
      )}
    </div>
  );
}

/* -------------------------------------------------------------- 候选命中 */

const PAGE_SIZE = 50;

const STATUS_TABS = [
  { id: "pending", name: "待审" },
  { id: "accepted", name: "已接受" },
  { id: "rejected", name: "已排除" },
  { id: "all", name: "全部" },
];

const STATUS_LABEL = { pending: "待审", accepted: "已接受", rejected: "已排除" };

function HitsView({ caseDetail, colorOf, onJump, onAdjudicated, onGotoSearch, onSendToChat }) {
  const sources = caseDetail.sources || [];
  const nameOf = (id) => sources.find((s) => s.id === id)?.name || id;
  const [status, setStatus] = useState("pending");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");            // 关键词(rule_id/命中值/摘要/行号)
  const [qApplied, setQApplied] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(
    async (off) => {
      setBusy(true);
      setError(null);
      try {
        const r = await api.listHits(caseDetail.id, {
          status,
          severity: severity || undefined,
          q: qApplied || undefined,
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
    [caseDetail.id, status, severity, qApplied]
  );

  useEffect(() => {
    load(0);
  }, [load]);

  // 裁决成功:pending 视图下即时移出列表;其他视图就地更新状态徽标。
  async function adjudicate(hit, action, note) {
    if (action === "accept") await api.acceptHit(hit.id, note);
    else await api.rejectHit(hit.id, note);
    if (status === "pending") {
      setData((d) => ({
        ...d,
        total: Math.max(0, d.total - 1),
        items: d.items.filter((i) => i.id !== hit.id),
      }));
    } else {
      const next = action === "accept" ? "accepted" : "rejected";
      setData((d) => ({
        ...d,
        items: d.items.map((i) => (i.id === hit.id ? { ...i, status: next } : i)),
      }));
    }
    onAdjudicated?.();
  }

  return (
    <div>
      <div className="form-row" style={{ marginBottom: 8 }}>
        {STATUS_TABS.map((t) => (
          <button
            key={t.id}
            className={status === t.id ? "primary" : ""}
            onClick={() => setStatus(t.id)}
          >
            {t.name}
          </button>
        ))}
        <label style={{ marginLeft: 8 }}>
          级别
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">全部</option>
            {["info", "low", "medium", "high"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
        <input
          style={{ minWidth: 200 }}
          placeholder="搜索:规则/命中值/摘要/行号"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") setQApplied(q.trim()); }}
        />
        <button onClick={() => setQApplied(q.trim())}>搜索</button>
        {qApplied && (
          <button className="link-btn" onClick={() => { setQ(""); setQApplied(""); }}>
            清除「{qApplied}」
          </button>
        )}
        {busy && <span className="muted">加载中…</span>}
      </div>
      {error && <div className="form-error">{error}</div>}
      {data && (
        <>
          <div className="muted" style={{ marginBottom: 6 }}>
            共 {data.total} 条{STATUS_LABEL[status] || ""}候选
            {data.total > 0 && `,本页 ${offset + 1}–${offset + data.items.length}`}
          </div>
          {data.items.length === 0 && (
            <div className="muted">
              {status === "pending" ? "待审区已清空——没有等待裁决的候选。" : "该过滤条件下无候选。"}
            </div>
          )}
          {data.items.map((hit) => (
            <HitCard
              key={hit.id}
              hit={hit}
              name={nameOf(hit.source_id)}
              color={colorOf(hit.source_id)}
              nameOf={nameOf}
              colorOf={colorOf}
              onJump={onJump}
              onAction={(action, note) => adjudicate(hit, action, note)}
              onGotoSearch={onGotoSearch}
              onSendToChat={onSendToChat}
              caseId={caseDetail.id}
            />
          ))}
          <div className="pager">
            <button disabled={offset === 0 || busy} onClick={() => load(Math.max(0, offset - PAGE_SIZE))}>
              上一页
            </button>
            <button disabled={offset + PAGE_SIZE >= data.total || busy} onClick={() => load(offset + PAGE_SIZE)}>
              下一页
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function HitCard({ hit, name, color, nameOf, colorOf, onJump, onAction, onGotoSearch, onSendToChat, caseId }) {
  const [expand, setExpand] = useState(false);
  const [mode, setMode] = useState(null); // null | "accept" | "reject"
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [corroOpen, setCorroOpen] = useState(false); // 互证面板(M2)

  // detail_json 容错解析:后端出库已解析为对象;若仍是字符串(坏 JSON)不崩,如实展示原文
  const detail = parseDetail(hit.detail_json);
  const kind = detail.ok ? detail.value?.kind : null;
  const isCrossSource =
    kind === "cross_source" || hit.rule_id === "cross-source-entity";

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      await onAction(mode, note);
      // 成功:卡片由父组件移出/改状态,无需清理本地状态
    } catch (err) {
      // 重复裁决(409)如实提示,不吞错
      setError(err.status === 409 ? "该命中已被裁决,无需重复操作。" : err.message);
      setBusy(false);
    }
  }

  return (
    <div className="result-row">
      <div className="result-head">
        <span className={`badge ${sevBadge(hit.severity)}`}>{hit.severity}</span>
        <span className="mono">{hit.rule_id}</span>
        {isCrossSource && (
          <span className="badge badge-bolt" title="跨源联动命中:同一 global 实体出现在 ≥2 个源;同值未必同人,交人复核(§7)">
            ⚡ 跨源
          </span>
        )}
        <span>
          <span className="src-dot" style={{ background: color }} />
          {name}
        </span>
        <button
          className="link-btn mono"
          title="跳转到「查看与检索」查看器对应行"
          onClick={() => onJump(hit.source_id, hit.line_no)}
        >
          L{hit.line_no}
        </button>
        {hit.ts_utc
          ? <span className="mono muted">UTC {hit.ts_utc}</span>
          : <span className="badge badge-warn">时区未归一</span>}
        {hit.status !== "pending" && (
          <span className="badge badge-muted">{STATUS_LABEL[hit.status] || hit.status}</span>
        )}
      </div>
      <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
        命中字段 <span className="mono">{hit.matched_field ?? "—"}</span>
        {" = "}
        <span className="mono">{hit.matched_value ?? "—"}</span>
      </div>
      <div
        className={`result-raw${expand ? "" : " clamp"}`}
        onClick={() => setExpand((v) => !v)}
        title={expand ? "点击收起" : "点击展开全文"}
      >
        {hit.snippet}
      </div>

      {detail.has && (
        <details className="norm-detail">
          <summary>
            依据详情
            {kind === "cluster" && "(疑似同源聚簇·弱信号,概率性)"}
            {kind === "cross_source" && "(⚡ 跨源命中)"}
            {kind === "divergence" && "(同键异值分化)"}
            {kind === "rate_spike" && "(同键变率突刺)"}
            {!detail.ok && "(detail_json 解析失败,原文如实展示)"}
          </summary>
          <DetailBody detail={detail} nameOf={nameOf} colorOf={colorOf} />
        </details>
      )}

      <div className="source-actions">
        <button onClick={() => setCorroOpen((v) => !v)}>
          {corroOpen ? "收起互证" : "互证"}
        </button>
        {hit.status === "pending" && !mode && (
          <>
            <button className="primary" onClick={() => setMode("accept")}>
              接受为线索
            </button>
            <button onClick={() => setMode("reject")}>排除</button>
          </>
        )}
      </div>
      <HitActions
        caseId={caseId}
        entity={hitEntity(hit)}
        tsUtc={hit.ts_utc}
        hitId={hit.id}
        contextText={hit.snippet}
        onGotoSearch={onGotoSearch}
        onSendToChat={onSendToChat}
      />
      {corroOpen && (
        <CorroboratePanel hit={hit} nameOf={nameOf} colorOf={colorOf} onJump={onJump} />
      )}

      {hit.status === "pending" && mode && (
        <div className="form-row" style={{ marginTop: 6 }}>
          <input
            style={{ flex: 1, minWidth: 220 }}
            autoFocus
            placeholder={mode === "accept" ? "入库理由(可选,留痕)" : "排除理由(可选,留痕)"}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !busy) confirm();
            }}
            disabled={busy}
          />
          <button className="primary" onClick={confirm} disabled={busy}>
            {busy ? "提交中…" : mode === "accept" ? "确认入库" : "确认排除"}
          </button>
          <button
            onClick={() => {
              setMode(null);
              setNote("");
              setError(null);
            }}
            disabled={busy}
          >
            取消
          </button>
        </div>
      )}
      {error && <div className="form-error" style={{ marginTop: 4 }}>{error}</div>}
    </div>
  );
}

/* ------------------------------------------------------ M2 依据详情 */

// M5:命中 → 「提取实体事件」用的实体 {field, value}。matched_field 须在检索层
// 字段条件白名单内(src_ip/ua/…),否则返回 null,动作按钮禁用并如实提示。
const ENTITY_FIELDS = new Set([
  "src_ip", "ua", "method", "status", "path", "query", "referer", "bytes",
  "actor", "action", "object", "result", "level", "logger", "message",
]);

function hitEntity(hit) {
  if (
    hit.matched_field &&
    ENTITY_FIELDS.has(hit.matched_field) &&
    hit.matched_value != null &&
    hit.matched_value !== ""
  ) {
    return { field: hit.matched_field, value: String(hit.matched_value) };
  }
  return null;
}

// detail_json 容错解析:对象原样用;字符串尝试 JSON.parse,失败保留原文如实展示
function parseDetail(dj) {
  if (dj == null || dj === "") return { has: false, ok: false, value: null, raw: null };
  if (typeof dj === "object") return { has: true, ok: true, value: dj, raw: null };
  try {
    return { has: true, ok: true, value: JSON.parse(dj), raw: null };
  } catch {
    return { has: true, ok: false, value: null, raw: String(dj) };
  }
}

function DetailBody({ detail, nameOf, colorOf }) {
  if (!detail.ok) {
    return (
      <div className="detail-block">
        <div className="form-note">detail_json 不是合法 JSON,原文如实展示:</div>
        <div className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
          {detail.raw}
        </div>
      </div>
    );
  }
  const d = detail.value || {};
  switch (d.kind) {
    case "divergence":
      return <DivergenceDetail d={d} />;
    case "cluster":
      return <ClusterDetail d={d} />;
    case "rate_spike":
      return <RateSpikeDetail d={d} />;
    case "cross_source":
      return <CrossSourceDetail d={d} nameOf={nameOf} colorOf={colorOf} />;
    default:
      // 未知 kind 不吞:结构化原文如实展示
      return (
        <div className="detail-block">
          <div className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {JSON.stringify(d, null, 2)}
          </div>
        </div>
      );
  }
}

// 组键值行:path=/api/item src_ip=1.2.3.4 …
function GroupLine({ group }) {
  if (!group || typeof group !== "object") return null;
  return (
    <div style={{ marginBottom: 4 }}>
      组键:
      {Object.entries(group).map(([k, v]) => (
        <span key={k} className="mono" style={{ marginRight: 10 }}>
          {k}={String(v)}
        </span>
      ))}
    </div>
  );
}

function DivergenceDetail({ d }) {
  const buckets = d.buckets || [];
  return (
    <div className="detail-block">
      <GroupLine group={d.group} />
      <table className="kv-table">
        <thead>
          <tr>
            <th>{d.diverge_field || "分桶"}</th>
            <th style={{ width: 90 }}>count</th>
            <th style={{ width: 140 }}>{d.metric || "metric"} 均值</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((b, i) => (
            <tr key={i}>
              <td>{String(b.value ?? "—")}</td>
              <td>{b.count}</td>
              <td>{b.avg ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ marginTop: 4 }}>
        最高/最低均值比:<span className="mono">{d.ratio == null ? "∞" : `×${d.ratio}`}</span>
      </div>
      <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
        分化≠异常(正常业务 GET/POST 返回体也可能天然不同);line_no 为组内代表行
        {d.rep_line_no ? ` L${d.rep_line_no}` : ""},交人复核。
      </div>
    </div>
  );
}

function ClusterDetail({ d }) {
  const counts = d.counts || [];
  return (
    <div className="detail-block">
      <div className="form-note" style={{ marginBottom: 4 }}>
        疑似同源聚簇(弱信号,概率性):同一稀有值跨多个键出现——可能是同一工具不同跳板,
        也可能是代理池默认配置;不代表同一攻击者,交人复核。
      </div>
      <div style={{ marginBottom: 4 }}>
        值:<span className="mono">{d.value}</span>
        {d.total_freq != null && (
          <span className="muted">(全局频次 {d.total_freq})</span>
        )}
      </div>
      <table className="kv-table">
        <thead>
          <tr>
            <th>键(IP)</th>
            <th style={{ width: 90 }}>count</th>
          </tr>
        </thead>
        <tbody>
          {counts.map((c, i) => (
            <tr key={i}>
              <td>{c.key}</td>
              <td>{c.count}</td>
            </tr>
          ))}
          {counts.length === 0 && (d.keys || []).map((k, i) => (
            <tr key={i}>
              <td>{k}</td>
              <td>—</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
        首见 <span className="mono">{d.first_ts || "时间未知"}</span>
        {" · "}末见 <span className="mono">{d.last_ts || "时间未知"}</span>
      </div>
    </div>
  );
}

function RateSpikeDetail({ d }) {
  return (
    <div className="detail-block">
      <GroupLine group={d.group} />
      <div>
        时间桶 <span className="mono">{d.bucket_start}</span>({d.bucket_seconds}s):
        计数 <b>{d.count}</b>(基线均值 {d.mean} / 标准差 {d.std}),
        z=<span className="mono">{d.z}</span>
      </div>
      <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
        突刺≠攻击(秒杀/定时任务同样突刺);line_no 为桶内代表行,交人复核。
      </div>
    </div>
  );
}

function CrossSourceDetail({ d, nameOf, colorOf }) {
  const sources = d.sources || [];
  return (
    <div className="detail-block">
      <div style={{ marginBottom: 4 }}>
        <span className="badge badge-bolt">⚡ 跨源命中</span>{" "}
        实体 <span className="mono">{d.value}</span>
        {d.entity_type && <span className="muted">({d.entity_type})</span>}{" "}
        出现在 {sources.length} 个源:
      </div>
      <div>
        {sources.map((s, i) => {
          // 后端给 {source_id, name};兜底兼容纯 id 字符串
          const sid = typeof s === "string" ? s : s.source_id;
          const sname = typeof s === "string" ? nameOf(s) : s.name || nameOf(s.source_id);
          return (
            <span key={sid || i} style={{ marginRight: 14 }}>
              <span className="src-dot" style={{ background: colorOf(sid) }} />
              {sname}
            </span>
          );
        })}
      </div>
      <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
        §7 防串味:跨源结论打 ⚡ 标并列明涉及源,只引用不融合;同值未必同人,交人复核。
      </div>
    </div>
  );
}

/* ------------------------------------------------------ M2 互证面板 */

const CORRO_WINDOWS = [60, 300, 900];
const CORRO_STATUS_LABEL = {
  ok: "有互证",
  none: "无互证",
  no_siblings: "无兄弟源",
  no_ts: "时间未知",
};

function CorroboratePanel({ hit, nameOf, colorOf, onJump }) {
  const [win, setWin] = useState(300);
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(
    async (w) => {
      setBusy(true);
      setError(null);
      try {
        setData(await api.corroborateHit(hit.id, w));
      } catch (err) {
        setError(err.message);
      } finally {
        setBusy(false);
      }
    },
    [hit.id]
  );

  useEffect(() => {
    load(win);
  }, [load, win]);

  return (
    <div className="corro-panel">
      <div className="corro-head">
        <span style={{ fontWeight: 600 }}>兄弟源互证</span>
        <label>
          时间窗
          <select value={win} onChange={(e) => setWin(Number(e.target.value))} disabled={busy}>
            {CORRO_WINDOWS.map((w) => (
              <option key={w} value={w}>±{w} 秒</option>
            ))}
          </select>
        </label>
        {busy && <span className="muted">查询中…</span>}
        {data && (
          <span className={`badge ${data.status === "ok" ? "badge-ok" : "badge-muted"}`}>
            {CORRO_STATUS_LABEL[data.status] || data.status}
          </span>
        )}
      </div>
      {error && <div className="form-error">{error}</div>}
      {data && (
        <>
          {data.note && (
            <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>{data.note}</div>
          )}
          {data.status === "ok" && (
            <>
              <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>
                同 system 兄弟源 {(data.siblings || []).length} 个,±{data.window_seconds}s 内
                同 path/同 IP 事件 {data.items.length} 条(≤20;互证≠结论,交人复核):
              </div>
              <table className="kv-table">
                <thead>
                  <tr>
                    <th style={{ width: 200 }}>源</th>
                    <th style={{ width: 80 }}>行号</th>
                    <th style={{ width: 200 }}>时间 (UTC)</th>
                    <th>原文</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((it, i) => (
                    <tr key={`${it.source_id}-${it.line_no}-${i}`}>
                      <td>
                        <span className="src-dot" style={{ background: colorOf(it.source_id) }} />
                        {nameOf(it.source_id)}
                      </td>
                      <td>
                        <button
                          className="link-btn mono"
                          title="跳转到「查看与检索」查看器对应行"
                          onClick={() => onJump(it.source_id, it.line_no)}
                        >
                          L{it.line_no}
                        </button>
                      </td>
                      <td className="mono">{it.ts_utc || "—"}</td>
                      <td>
                        <span className="raw-ellipsis mono" title={it.raw}>
                          {it.raw}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </>
      )}
    </div>
  );
}

/* -------------------------------------------------------------- 线索列表 */

function CluesView({ caseDetail, colorOf, onJump, refreshKey }) {
  const sources = caseDetail.sources || [];
  const nameOf = (id) => sources.find((s) => s.id === id)?.name || id;
  const [clues, setClues] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    api
      .listClues(caseDetail.id)
      .then((r) => !cancelled && setClues(r.items || []))
      .catch((err) => !cancelled && setError(err.message));
    return () => {
      cancelled = true;
    };
  }, [caseDetail.id, refreshKey]);

  if (error) return <div className="form-error">{error}</div>;
  if (!clues) return <div className="muted">加载中…</div>;
  if (clues.length === 0)
    return <div className="muted">暂无线索。线索来自待审区「接受为线索」的人工裁决。</div>;

  return (
    <div>
      <div className="muted" style={{ marginBottom: 6 }}>
        共 {clues.length} 条线索,每条锚定「日志源 + 行号 + SHA256」(证据链不可断)。
      </div>
      <table className="kv-table clue-table">
        <thead>
          <tr>
            <th style={{ width: 180 }}>标题</th>
            <th>内容</th>
            <th style={{ width: 300 }}>锚点</th>
            <th style={{ width: 170 }}>入库时间</th>
            <th style={{ width: 90 }}>入库人</th>
          </tr>
        </thead>
        <tbody>
          {clues.map((c) => (
            <tr key={c.id}>
              <td>{c.title}</td>
              <td>
                <span className="cell-ellipsis" title={c.body || ""}>
                  {c.body || "—"}
                </span>
              </td>
              <td>
                <span className="src-dot" style={{ background: colorOf(c.anchor_source_id) }} />
                {nameOf(c.anchor_source_id)}{" "}
                <button
                  className="link-btn mono"
                  title="跳转到「查看与检索」查看器对应行"
                  onClick={() => onJump(c.anchor_source_id, c.anchor_line_no)}
                >
                  L{c.anchor_line_no}
                </button>{" "}
                <span className="mono sha" title={c.anchor_sha256}>
                  {shortSha(c.anchor_sha256)}
                </span>
              </td>
              <td className="mono">{c.created_at}</td>
              <td>{c.created_by || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
