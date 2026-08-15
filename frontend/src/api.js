// 索图前端 API 集中封装。后端基址 http://127.0.0.1:8100,
// 开发期经 vite proxy 同源访问(见 vite.config.js),故 BASE 为空。
const BASE = "";

async function req(path, { method = "GET", json, form } = {}) {
  const opts = { method, headers: {} };
  if (json !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(json);
  } else if (form !== undefined) {
    opts.body = form; // FormData,浏览器自带 multipart 边界
  }
  const res = await fetch(BASE + path, opts);
  // M4 认证闸:业务端点 401 = 会话失效,广播事件由 App 统一跳登录页。
  // /auth/* 自身(登录/探活)不广播,避免登录页死循环。
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new CustomEvent("suotu:unauthorized"));
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      // FastAPI 错误体 {detail: ...};422 解析失败时 detail 即失败原因原文
      if (typeof body.detail === "string") msg = body.detail;
      else if (body.detail !== undefined) msg = JSON.stringify(body.detail);
    } catch {
      /* 非 JSON 错误体,保留 HTTP 状态码 */
    }
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// 纯文本响应(描述文件导出为 PlainTextResponse,不能走 res.json())
async function reqText(path) {
  const res = await fetch(BASE + path);
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new CustomEvent("suotu:unauthorized"));
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
    } catch {
      /* 非 JSON 错误体,保留 HTTP 状态码 */
    }
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return res.text();
}

export const api = {
  healthz: () => req("/healthz"),

  // ── M4:认证(会话 Cookie 同源自带;401 由 req 广播,App 统一跳登录页) ──
  me: () => req("/auth/me"),
  login: (username, password) =>
    req("/auth/login", { method: "POST", json: { username, password } }),
  logout: () => req("/auth/logout", { method: "POST" }),
  // 仅无用户时开放(首启引导);已初始化 → 403,由调用方如实提示
  setup: (username, password) =>
    req("/auth/setup", { method: "POST", json: { username, password } }),
  changePassword: (oldPassword, newPassword) =>
    req("/auth/change-password", {
      method: "POST",
      json: { old_password: oldPassword, new_password: newPassword },
    }),

  listCases: () => req("/cases"),
  createCase: (name) => req("/cases", { method: "POST", json: { name } }),
  getCase: (id) => req(`/cases/${id}`),

  // 注意:后端 name 取自上传文件名,不接收 name 表单字段(实测 M0 后端)。
  uploadSource: (caseId, file, { system, sourceNote, evidenceKind } = {}) => {
    const form = new FormData();
    form.append("file", file);
    if (system) form.append("system", system);
    if (sourceNote) form.append("source_note", sourceNote);
    if (evidenceKind) form.append("evidence_kind", evidenceKind);
    return req(`/cases/${caseId}/sources:upload`, { method: "POST", form });
  },
  getSource: (id) => req(`/sources/${id}`),
  confirmSource: (id, { formatId, tzDeclared, logType }) =>
    req(`/sources/${id}/confirm`, {
      method: "POST",
      json: {
        format_id: formatId,
        tz_declared: tzDeclared || null,
        log_type: logType,
      },
    }),
  parseSource: (id) => req(`/sources/${id}/parse`, { method: "POST" }),
  sourceLines: (id, offset, limit) =>
    req(`/sources/${id}/lines?offset=${offset}&limit=${limit}`),

  search: (caseId, { q, sourceId, tsFrom, tsTo, fieldFilters, limit, offset } = {}) => {
    const qs = new URLSearchParams();
    if (q) qs.set("q", q);
    if (sourceId) qs.set("source_id", sourceId);
    if (tsFrom) qs.set("ts_from", tsFrom);
    if (tsTo) qs.set("ts_to", tsTo);
    if (fieldFilters) qs.set("field_filters", JSON.stringify(fieldFilters));
    if (limit !== undefined) qs.set("limit", String(limit));
    if (offset !== undefined) qs.set("offset", String(offset));
    return req(`/cases/${caseId}/search?${qs.toString()}`);
  },
  stats: (caseId) => req(`/cases/${caseId}/stats`),

  // ── M1:规则 / 候选命中 / 线索 ──
  listRules: (caseId) => req(`/cases/${caseId}/rules`),
  // sourceId 为空 = 全案件扫描;ruleIds 不传 = 全量(旧行为),
  // 传数组 = 子集扫描(未知 id/未启用自定义后端 422 如实)
  runRules: (caseId, sourceId, ruleIds) =>
    req(`/cases/${caseId}/rules:run`, {
      method: "POST",
      json: {
        ...(sourceId ? { source_id: sourceId } : {}),
        ...(ruleIds ? { rule_ids: ruleIds } : {}),
      },
    }),
  // 扫描轮次台账(待审区轮次过滤下拉用)
  listScanRounds: (caseId) => req(`/cases/${caseId}/scan-rounds`),
  // ── 自定义规则治理(只有 enable 进扫描;内置规则永只读,id 冲突 409) ──
  getCustomRule: (ruleId) => req(`/rules/custom/${encodeURIComponent(ruleId)}`),
  // 创建恒 draft(人审转 enable 才进扫描);坏 YAML 后端 422 如实
  createCustomRule: (yamlText) =>
    req("/rules/custom", { method: "POST", json: { yaml_text: yamlText } }),
  // 内容(yamlText,重过 schema 闸)和/或状态(draft|review|enable)
  updateCustomRule: (ruleId, { yamlText, status } = {}) =>
    req(`/rules/custom/${encodeURIComponent(ruleId)}`, {
      method: "PUT",
      json: {
        ...(yamlText !== undefined ? { yaml_text: yamlText } : {}),
        ...(status ? { status } : {}),
      },
    }),
  // 只许删自定义(内置 id → 404 如实)
  deleteCustomRule: (ruleId) =>
    req(`/rules/custom/${encodeURIComponent(ruleId)}`, { method: "DELETE" }),
  listHits: (caseId, { status, severity, q, round, hitId, limit, offset } = {}) => {
    const qs = new URLSearchParams();
    if (status && status !== "all") qs.set("status", status);
    if (severity) qs.set("severity", severity);
    if (q) qs.set("q", q);
    if (round) qs.set("round", round);   // 轮次号 | history(老数据)
    if (hitId) qs.set("hit_id", hitId);  // 精确锚定单条(记录区跳转用)
    if (limit !== undefined) qs.set("limit", String(limit));
    if (offset !== undefined) qs.set("offset", String(offset));
    return req(`/cases/${caseId}/hits?${qs.toString()}`);
  },
  // ── 记录区(案件日志流):自动条目读取时合成 + 人工笔记 ──
  getJournal: (caseId, { limit, offset } = {}) => {
    const qs = new URLSearchParams();
    if (limit !== undefined) qs.set("limit", String(limit));
    if (offset !== undefined) qs.set("offset", String(offset));
    return req(`/cases/${caseId}/journal?${qs.toString()}`);
  },
  // 锚点引用对象不存在后端 422 如实
  addNote: (caseId, { body, anchorKind, anchorRef }) =>
    req(`/cases/${caseId}/notes`, {
      method: "POST",
      json: {
        body,
        ...(anchorKind ? { anchor_kind: anchorKind } : {}),
        ...(anchorRef ? { anchor_ref: anchorRef } : {}),
      },
    }),
  // 仅本人可删(他人后端 403 如实)
  deleteNote: (noteId) =>
    req(`/notes/${encodeURIComponent(noteId)}`, { method: "DELETE" }),
  // 裁决:接受为线索 / 排除。note 可选;重复裁决后端回 409,由调用方如实提示。
  acceptHit: (id, note) =>
    req(`/hits/${id}:accept`, { method: "POST", json: { note: note || null } }),
  rejectHit: (id, note) =>
    req(`/hits/${id}:reject`, { method: "POST", json: { note: note || null } }),
  listClues: (caseId) => req(`/cases/${caseId}/clues`),
  // ── M2:互证(同 system 兄弟源 ±window 内同 path/同 IP;四态如实区分) ──
  corroborateHit: (hitId, windowSeconds = 300) =>
    req(`/hits/${hitId}/corroborate?window_seconds=${windowSeconds}`),

  // ── M3:AI 状态 / L2 播种 + L3 精读 / KB 解释器 ──
  getAiStatus: () => req("/ai/status"),

  // ── M6:AI 设置(系统级一份,写回 .env 即生效;key 明文永不出后端) ──
  getAiConfig: () => req("/ai/config"),
  // apiKey 空/undefined = 不动现有 key;未知厂商/缺 key 后端 422 如实
  saveAiConfig: ({ provider, baseUrl, model, apiKey, consentExternal }) =>
    req("/ai/config", {
      method: "PUT",
      json: {
        provider,
        base_url: baseUrl || null,
        model: model || null,
        api_key: apiKey || null,
        consent_external: consentExternal || false,
      },
    }),
  // 合规闸(2026-08-11):全局外发同意状态/记录 + 按案件禁外发开关
  getAiConsent: () => req("/ai/consent"),
  setCaseAiPolicy: (caseId, blocked) =>
    req(`/cases/${caseId}/ai-policy`, {
      method: "PATCH",
      json: { ai_external_blocked: blocked },
    }),
  // ── MCP 接入(只读端点 + token 管理;2026-08-13) ──
  mcpStatus: () => req("/mcp-admin/status"),
  mcpSetEnabled: (enabled) =>
    req("/mcp-admin/enabled", { method: "POST", json: { enabled } }),
  mcpCreateToken: (label) =>
    req("/mcp-admin/tokens", { method: "POST", json: { label } }),
  mcpRevokeToken: (id) =>
    req(`/mcp-admin/tokens/${id}/revoke`, { method: "POST" }),
  // 测连表单值(不写 .env、不写审计):成功回模型/延迟,失败回分类 kind
  testAiConfig: ({ provider, baseUrl, model, apiKey }) =>
    req("/ai/config/test", {
      method: "POST",
      json: {
        provider,
        base_url: baseUrl || null,
        model: model || null,
        api_key: apiKey || null,
      },
    }),
  // 202 {run_id, status};同源 running 中 → 409,由调用方如实提示
  // budget:null=缺省;0=不限(用户显式选择,循环检测/中断不受影响)
  runAnalysis: (caseId, sourceId, budget = null) =>
    req(`/cases/${caseId}/analysis:run`, {
      method: "POST",
      json: budget === null ? { source_id: sourceId }
                            : { source_id: sourceId, budget },
    }),
  getAnalysis: (runId) => req(`/analysis/${runId}`),
  abortAnalysis: (runId) => req(`/analysis/${runId}:abort`, { method: "POST" }),
  listAnalysis: (caseId) => req(`/cases/${caseId}/analysis`),
  // kind: path|ua|status;covered=false 即 KB 未覆盖,如实交 AI/人研判
  kbExplain: (kind, value) =>
    req(`/kb/explain?${new URLSearchParams({ kind, value }).toString()}`),

  // ── M4:格式描述文件治理(§4:导入恒 draft,人审 enable 后才可用于解析) ──
  listFormatDescs: () => req("/formatdesc"),
  importFormatDesc: (yamlText) =>
    req("/formatdesc:import", { method: "POST", json: { yaml_text: yamlText } }),
  // 状态机只许向前:draft→review→enable;enable→draft 为停用留痕
  transitionFormatDesc: (name, to) =>
    req(`/formatdesc/${encodeURIComponent(name)}:transition`, {
      method: "POST",
      json: { to },
    }),
  // 仅 draft 可删(review/enable → 409 如实)
  deleteFormatDesc: (name) =>
    req(`/formatdesc/${encodeURIComponent(name)}`, { method: "DELETE" }),
  // 校验 + 抽样试解析预览(不写盘);sampleLines 为空数组则不传
  validateFormatDesc: (yamlText, sampleLines) =>
    req("/formatdesc:validate", {
      method: "POST",
      json: {
        yaml_text: yamlText,
        sample_lines: sampleLines && sampleLines.length ? sampleLines : undefined,
      },
    }),
  // 导出落盘 YAML 原文(纯文本)
  exportFormatDesc: (name) =>
    reqText(`/formatdesc/${encodeURIComponent(name)}:export`),
  // AI 辅助起草(§4.4):草稿不落盘,人审编辑后 :import;offline → 503,AI 输出坏 → 502,如实
  draftFormat: (sourceId, sampleLines) =>
    req(`/sources/${sourceId}/draft-format`, {
      method: "POST",
      json: sampleLines ? { sample_lines: sampleLines } : {},
    }),

  // ── M4:封存导出(只读,不锁案件;继续分析请重新打包) ──
  sealCase: (caseId) => req(`/cases/${caseId}:seal`, { method: "POST" }),
  // 独立校验封存包:multipart 上传 zip → {ok, checks, failures}
  verifySeal: (file) => {
    const form = new FormData();
    form.append("file", file);
    return req("/seal/verify", { method: "POST", form });
  },

  // ── M4:主机取证平台实体互查(只读;available=false + reason 如实,不报错页) ──
  treecourtEntities: (value) =>
    req(`/bridge/treecourt/entities?value=${encodeURIComponent(value)}`),

  // ── M5:交流区(人机对话;AI 回答=推测·待核,offline_lite 诚实降级) ──
  listChatSessions: (caseId) => req(`/cases/${caseId}/chat/sessions`),
  // fromHitId 可选:由命中发起的会话带 from_hit_id,后端生成命中上下文摘要
  createChatSession: (caseId, { title, fromHitId } = {}) =>
    req(`/cases/${caseId}/chat/sessions`, {
      method: "POST",
      json: {
        ...(title ? { title } : {}),
        ...(fromHitId ? { from_hit_id: fromHitId } : {}),
      },
    }),
  listChatMessages: (sessionId) => req(`/chat/sessions/${sessionId}/messages`),
  // 同步返回 AI 回答消息(含 tool_log_json/usage_json);offline_lite 时 content 为诚实降级文案
  sendChatMessage: (sessionId, content) =>
    req(`/chat/sessions/${sessionId}/messages`, { method: "POST", json: { content } }),

  // ── M5:按字段聚类分布(field 白名单由后端校验,越界 422 如实) ──
  aggregate: (caseId, { field, sourceId, fieldFilters, tsFrom, tsTo, limit } = {}) => {
    const qs = new URLSearchParams();
    if (field) qs.set("field", field);
    if (sourceId) qs.set("source_id", sourceId);
    if (fieldFilters) qs.set("field_filters", JSON.stringify(fieldFilters));
    if (tsFrom) qs.set("ts_from", tsFrom);
    if (tsTo) qs.set("ts_to", tsTo);
    if (limit !== undefined) qs.set("limit", String(limit));
    return req(`/cases/${caseId}/aggregate?${qs.toString()}`);
  },

  // ── 运行日志(移植自主机取证平台 v1.2.0):三文件尾部查看 + 一键诊断包 ──
  listLogFiles: () => req("/logs/files"),
  // file: app|error|operation;lines 尾部行数;q 关键字(服务端先取尾部再过滤)
  readLog: (file, { lines, q } = {}) => {
    const qs = new URLSearchParams({ file });
    if (lines !== undefined) qs.set("lines", String(lines));
    if (q) qs.set("q", q);
    return req(`/logs?${qs.toString()}`);
  },
  // 诊断包(POST,zip 二进制;生成动作后端写审计链,key/口令一律打码)
  downloadDiagnostics: async () => {
    const res = await fetch(`${BASE}/diagnostics/bundle`, { method: "POST" });
    if (res.status === 401) {
      window.dispatchEvent(new CustomEvent("suotu:unauthorized"));
    }
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    // 文件名取 Content-Disposition,缺省兜底
    const cd = res.headers.get("Content-Disposition") || "";
    const m = /filename="?([^";]+)"?/.exec(cd);
    return { blob: await res.blob(), filename: m ? m[1] : "suotu_diagnostics.zip" };
  },
};
// 全部可选格式(与 backend/app/formats 注册表一致;后端无清单接口,M0 前端硬编码)
export const FORMATS = [
  { id: "nginx_combined", name: "nginx combined access log" },
  { id: "apache_common", name: "apache common access log (CLF)" },
  { id: "iis_w3c", name: "IIS W3C extended log" },
  { id: "raw", name: "raw T0 原文兜底(每行一事件)" },
];

export const LOG_TYPES = [
  { id: "web", name: "web 访问日志" },
  { id: "middleware", name: "middleware 中间件日志" },
  { id: "audit", name: "audit 业务审计日志" },
  { id: "unknown", name: "unknown 未知" },
];

export const STATUS_LABEL = {
  registered: "已登记",
  confirmed: "已确认",
  parsed: "已解析",
  failed: "失败",
};
