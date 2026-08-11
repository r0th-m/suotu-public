// 小组件共用工具:源固定配色、时间范围解析、sha 截断。
export const SRC_PALETTE = [
  "#5b9bd5", "#6fcf8f", "#e0b34c", "#e4736f", "#b08ad9",
  "#5bc8c0", "#d98ab0", "#a3b86b", "#d9905b", "#7f93d9",
];

// 源固定配色(§7 防串味:日志源固定配色)——按源在案件内的顺序取色,稳定不随刷新变。
export function sourceColorMap(sources) {
  const map = {};
  (sources || []).forEach((s, i) => {
    map[s.id] = SRC_PALETTE[i % SRC_PALETTE.length];
  });
  return map;
}

// log_sources.time_range 是 JSON 串 {"from","to"} 或 null,解析失败如实当 null。
export function parseTimeRange(tr) {
  if (!tr) return null;
  try {
    const o = JSON.parse(tr);
    if (o && o.from && o.to) return o;
  } catch {
    /* 落 null */
  }
  return null;
}

export function shortSha(sha, n = 12) {
  return sha ? sha.slice(0, n) : "—";
}

// 严重度 → 徽标样式(规则/命中共用):info 蓝、low 灰、medium 黄、high 红。
export const SEV_BADGE = {
  info: "badge-info",
  low: "badge-muted",
  medium: "badge-warn",
  high: "badge-danger",
};

export function sevBadge(sev) {
  return SEV_BADGE[sev] || "badge-muted";
}

// datetime-local 值(浏览器本地时区)→ UTC 的 naive ISO(后端 ts_utc 为无时区 TIMESTAMP)。
export function localInputToUtcIso(v) {
  if (!v) return undefined;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString().replace(/\.\d{3}Z$/, "");
}

// UTC ISO(后端 ts_utc,naive 按 UTC 处理)→ datetime-local 输入值(浏览器本地时区);
// 与 localInputToUtcIso 互逆,M5「时间窗展开」回填检索条件用。非法输入如实回空串。
export function utcIsoToLocalInput(v) {
  if (!v) return "";
  const s = /Z$|[+-]\d{2}:?\d{2}$/.test(v) ? v : `${v}Z`;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
