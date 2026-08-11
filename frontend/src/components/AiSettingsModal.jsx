import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";

// 索图两档(§6 三档梯度的索图取舍):online 覆盖云端厂商与本地 Ollama
const PROFILE_LABEL = {
  offline_lite: "离线·诚实降级(仅确定性)",
  online: "在线(云端或本地 Ollama)",
};
const PROFILE_DESC = {
  offline_lite:
    "未配置 AI:L3 精读/交流区 AI 回答不可用,L1/L2 确定性分析不受影响。",
  online:
    "云端厂商 API:分析内容会发往外部服务,请确认合规边界;" +
    "Ollama 为本地模型,数据不出本机。",
};

// 测连失败分类 → 中文提示(kind 由后端如实分类)
const KIND_HINT = {
  network: "网络不可达或超时:检查 base_url 与本机网络",
  auth: "认证失败:API key 无效或无权限",
  not_found: "模型不存在或端点 404:检查模型名与 base_url",
  rate_limit: "服务限流(429),稍后重试",
  server: "服务端错误(5xx),稍后重试",
  client: "请求被拒(4xx):检查参数",
  offline: "未配置 API key 或模型,无可测的云端通道",
  bad_response: "响应结构不符(非 OpenAI 兼容返回)",
};

/**
 * AI 设置(M6,移植自主机取证平台设置面板):系统级一份,写回项目根 .env 即生效。
 * 纪律:key 明文永不出后端——输入框只放掩码 placeholder,绝不预填;
 * 测连测的是当前表单值(后端不写 .env、不写审计),保存才落盘(写审计,
 * 审计永不记 key)。
 */
export default function AiSettingsModal({ onClose, onSaved }) {
  const [cfg, setCfg] = useState(null); // GET /ai/config 快照
  const [status, setStatus] = useState(null); // GET /ai/status
  const [loadErr, setLoadErr] = useState(null);
  const [provider, setProvider] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState(""); // 仅本次输入;空 = 不动现有 key
  const [keyConfigured, setKeyConfigured] = useState(false);
  const [keyHint, setKeyHint] = useState(null);
  const [localModels, setLocalModels] = useState([]); // ollama 拉取的本地模型
  const [testResult, setTestResult] = useState(null); // { ok, text }
  const [saveErr, setSaveErr] = useState(null);
  const [savedNote, setSavedNote] = useState(null);
  const [busy, setBusy] = useState(false);
  const [consent, setConsent] = useState(null); // GET /ai/consent {consented,...}
  const [consentChecked, setConsentChecked] = useState(false);

  useEffect(() => {
    let dead = false;
    Promise.all([api.getAiConfig(), api.getAiStatus(), api.getAiConsent()])
      .then(([snap, st, cs]) => {
        if (dead) return;
        setCfg(snap);
        setStatus(st);
        setProvider(snap.provider || "custom");
        setBaseUrl(snap.base_url || "");
        setModel(snap.model || "");
        setKeyConfigured(!!snap.key_configured);
        setKeyHint(snap.key_hint || null);
        setConsent(cs);
      })
      .catch((e) => {
        if (!dead) setLoadErr(e.message);
      });
    return () => {
      dead = true;
    };
  }, []);

  const presets = cfg?.presets || [];
  const preset = useMemo(
    () => presets.find((p) => p.id === provider) || null,
    [presets, provider],
  );
  const isOllama = provider === "ollama";
  const needsKey = preset ? preset.needs_key !== false : true;

  // 模型候选:ollama 用拉到的本地清单,其余用预设 recommended_models
  const modelOptions = isOllama
    ? localModels
    : preset?.recommended_models || [];

  const switchProvider = (id) => {
    const p = presets.find((x) => x.id === id);
    setProvider(id);
    setBaseUrl(p?.base_url || "");
    setModel(p?.recommended_models?.[0] || "");
    setApiKey("");
    setTestResult(null);
    setSaveErr(null);
    setSavedNote(null);
    setLocalModels([]);
  };

  const formValues = () => ({
    provider,
    baseUrl: baseUrl.trim(),
    model: model.trim(),
    apiKey: apiKey.trim(), // 空 = 不动现有 key / 沿用已保存的 key 测
    consentExternal: consentChecked || undefined, // 勾选才带(合规闸)
  });

  const refreshStatus = async () => {
    try {
      setStatus(await api.getAiStatus());
    } catch {
      /* 徽标刷新失败不挡主流程 */
    }
  };

  const save = async () => {
    if (busy) return;
    setBusy(true);
    setSaveErr(null);
    setSavedNote(null);
    try {
      const snap = await api.saveAiConfig(formValues());
      setKeyConfigured(!!snap.key_configured);
      setKeyHint(snap.key_hint || null);
      setApiKey("");
      if (consentChecked) {
        setConsent({ consented: true });
        setConsentChecked(false);
      }
      setSavedNote("已保存(写回本机 .env,即生效)。");
      refreshStatus();
      onSaved?.();
    } catch (e) {
      setSaveErr(e.message); // 422 原文如实(未知厂商/缺 key)
    } finally {
      setBusy(false);
    }
  };

  /** 测连:测当前表单值(后端不写 .env、不写审计);
   *  fillModels=true 时把 ollama 本地模型清单填进候选。 */
  const test = async ({ fillModels = false } = {}) => {
    if (busy) return;
    setBusy(true);
    setSaveErr(null);
    setSavedNote(null);
    setTestResult(null);
    try {
      const r = await api.testAiConfig(formValues());
      if (r.ok) {
        if (r.provider === "ollama") {
          const list = r.local_models || [];
          if (fillModels) {
            setLocalModels(list);
            if (!model.trim() && list.length) setModel(list[0]);
          }
          const present =
            r.model_present === true
              ? `;当前模型 ${r.model} 在清单中`
              : r.model_present === false
                ? `;注意:当前模型 ${r.model || "(未填)"} 不在本地清单`
                : "";
          setTestResult({
            ok: true,
            text:
              `✓ 连接成功(${r.latency_ms} ms),本地模型 ${list.length} 个:` +
              `${list.join("、") || "(无)"}${present}`,
          });
        } else {
          setTestResult({
            ok: true,
            text: `✓ 连接成功,延迟 ${r.latency_ms} ms,模型 ${r.model}`,
          });
        }
      } else {
        const hint = KIND_HINT[r.kind] || "测试失败";
        setTestResult({
          ok: false,
          text: `✗ ${hint}${r.error ? `(${r.error})` : ""}`,
        });
      }
    } catch (e) {
      setTestResult({ ok: false, text: `✗ 测试失败:${e.message}` });
    } finally {
      setBusy(false);
    }
  };

  const profLabel = status
    ? PROFILE_LABEL[status.profile] || status.profile
    : null;

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal ai-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>AI 设置</span>
          <button className="link-btn" onClick={onClose}>
            关闭
          </button>
        </div>
        {loadErr && <div className="form-error">配置读取失败:{loadErr}</div>}
        {!cfg && !loadErr && <div className="muted">配置读取中…</div>}
        {cfg && (
          <div className="inline-form">
            <div className="form-row">
              当前档位:
              <span
                className={`badge ${status?.profile === "offline_lite" ? "badge-muted" : "badge-ok"}`}
                title={status?.note || ""}
              >
                {profLabel || "查询中…"}
              </span>
            </div>
            {status?.profile && (
              <div className="muted">{PROFILE_DESC[status.profile]}</div>
            )}
            <label>
              厂商
              <select
                value={provider}
                onChange={(e) => switchProvider(e.target.value)}
                disabled={busy}
              >
                {presets.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Base URL(OpenAI 兼容端点)
              <input
                value={baseUrl}
                disabled={busy}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="留空用厂商预设默认"
                autoComplete="off"
              />
            </label>
            <label>
              模型(可下拉选择,也可手改)
              <input
                list="ai-model-list"
                value={model}
                disabled={busy}
                onChange={(e) => setModel(e.target.value)}
                placeholder={
                  isOllama ? "先点「拉取本地模型」获取清单" : "模型名"
                }
                autoComplete="off"
              />
              <datalist id="ai-model-list">
                {modelOptions.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </label>
            <label>
              API key
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={
                  keyConfigured
                    ? `已配置 ${keyHint || "***"}(留空则不修改)`
                    : "未配置"
                }
                autoComplete="new-password"
                disabled={busy || !needsKey}
              />
            </label>
            {isOllama && <div className="muted">Ollama 本地免 key。</div>}
            {!isOllama && !consent?.consented && (
              <label className="checkbox-label ai-consent">
                <input
                  type="checkbox"
                  checked={consentChecked}
                  onChange={(e) => setConsentChecked(e.target.checked)}
                  disabled={busy}
                />
                <span>
                  我已知晓并同意:使用在线厂商时,<b>案件数据将发送至第三方
                  模型服务</b>(一次性同意,操作人留痕可审计;单个案件可在
                  案件列表另设「禁止 AI 外发」)。
                </span>
              </label>
            )}
            {!isOllama && consent?.consented && (
              <div className="muted">
                外发同意已记录(操作人 {consent.actor || "—"},全程可审计);
                单个案件可在案件列表另设「禁止 AI 外发」。
              </div>
            )}
            {saveErr && <div className="form-error">{saveErr}</div>}
            {savedNote && <div className="form-ok">{savedNote}</div>}
            {testResult && (
              <div className={testResult.ok ? "form-ok" : "form-error"}>
                {testResult.text}
              </div>
            )}
            <div className="muted">
              key 只落本机项目根 .env,不进数据库、不进审计、不出机;留空即
              「不动现有 key」。AI 永远可关:清空为无 key 配置即回到
              offline_lite 诚实降级,L1/L2 确定性分析不受影响。测连测当前
              表单值,不写 .env、不写审计;保存才落盘(审计只记厂商/模型,
              永不记 key)。
            </div>
            <div className="form-row">
              <button disabled={busy || !provider} onClick={() => test()}>
                {busy ? "处理中…" : "测试连接"}
              </button>
              {isOllama && (
                <button disabled={busy} onClick={() => test({ fillModels: true })}>
                  拉取本地模型
                </button>
              )}
              <button
                className="primary"
                disabled={busy || !provider}
                onClick={save}
              >
                {busy ? "处理中…" : "保存"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
