import { useCallback, useEffect, useState } from "react";
import { api } from "./api.js";
import { sourceColorMap } from "./util.js";
import LoginGate from "./components/LoginGate.jsx";
import AiSettingsModal from "./components/AiSettingsModal.jsx";
import McpModal from "./components/McpModal.jsx";
import CaseSidebar from "./components/CaseSidebar.jsx";
import SourcesPane from "./components/SourcesPane.jsx";
import FormatDescPane from "./components/FormatDescPane.jsx";
import SearchPane from "./components/SearchPane.jsx";
import ViewerPane from "./components/ViewerPane.jsx";
import RulesPane from "./components/RulesPane.jsx";
import ReviewPane from "./components/ReviewPane.jsx";
import AiPane from "./components/AiPane.jsx";
import ChatPane from "./components/ChatPane.jsx";
import LogViewer from "./components/LogViewer.jsx";

// 索图单页骨架:案件栏(侧)+ 案件内视图(日志源/格式治理/检索/查看/规则与扫描/待审区/AI 分析/交流区),状态切换无路由。
export default function App() {
  // M4 认证闸:loading=探活中 / anon=未登录(全屏登录页)/ authed=已登录
  const [auth, setAuth] = useState({ state: "loading", username: null });
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState(null);
  const [cases, setCases] = useState([]);
  const [currentId, setCurrentId] = useState(null);
  const [caseDetail, setCaseDetail] = useState(null);
  const [view, setView] = useState("sources"); // sources | formatdesc | search | viewer | rules | review | ai | chat
  const [pendingCount, setPendingCount] = useState(0);
  // M3:全局 AI 档位(online / offline_lite 诚实降级),顶栏徽标 + AI 分析 tab 共用
  const [aiStatus, setAiStatus] = useState(null);
  // viewer 状态提升到 App:检索结果/待审区命中/线索锚点可一键跳「查看」tab 对应行。
  const [viewer, setViewer] = useState({ sourceId: "", offset: 0, highlight: null });
  // M5:命中动作菜单的跨 tab 状态提升(与 viewer 同模式)——
  // searchInit:跳「检索」并自动填条件(filters/tsFrom/tsTo)后立即检索;
  // chatInit:跳「交流区」指定会话并预填追问。
  const [searchInit, setSearchInit] = useState(null);
  const [chatInit, setChatInit] = useState(null);
  const [error, setError] = useState(null);
  const [pwOpen, setPwOpen] = useState(false);
  const [aiCfgOpen, setAiCfgOpen] = useState(false); // M6:AI 设置弹窗
  const [mcpOpen, setMcpOpen] = useState(false); // MCP 接入面板
  const [logOpen, setLogOpen] = useState(false); // 运行日志弹窗(排障,系统级)

  const refreshCases = useCallback(async () => {
    try {
      const r = await api.listCases();
      setCases(r.items || []);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  const refreshCase = useCallback(async (id) => {
    if (!id) return;
    try {
      setCaseDetail(await api.getCase(id));
    } catch (err) {
      setError(err.message);
    }
  }, []);

  // 待审计数:进案件时拉取;扫描后、裁决后由子面板回调刷新。失败不打断主流程。
  const fetchPending = useCallback(async (id) => {
    if (!id) {
      setPendingCount(0);
      return;
    }
    try {
      const r = await api.listHits(id, { status: "pending", limit: 1 });
      setPendingCount(r.total || 0);
    } catch {
      /* 计数失败保持旧徽标,不报全局错 */
    }
  }, []);

  // 启动先探会话:401 → 全屏登录页;已登录 → 进主界面拉数据
  useEffect(() => {
    api
      .me()
      .then((r) => setAuth({ state: "authed", username: r.username }))
      .catch(() => setAuth({ state: "anon", username: null }));
  }, []);

  // 业务端点 401(会话过期/被改密踢出)→ 统一回登录页
  useEffect(() => {
    const onUnauth = () =>
      setAuth((a) => (a.state === "authed" ? { state: "anon", username: null } : a));
    window.addEventListener("suotu:unauthorized", onUnauth);
    return () => window.removeEventListener("suotu:unauthorized", onUnauth);
  }, []);

  // AI 状态只报配置在不在(后端不测活);失败不影响主流程,徽标省略
  const refreshAiStatus = useCallback(() => {
    api.getAiStatus().then(setAiStatus).catch(() => {});
  }, []);

  useEffect(() => {
    if (auth.state !== "authed") return;
    api
      .healthz()
      .then(setHealth)
      .catch((err) => setHealthError(err.message));
    refreshAiStatus();
    refreshCases();
  }, [auth.state, refreshCases, refreshAiStatus]);

  useEffect(() => {
    refreshCase(currentId);
    fetchPending(currentId);
  }, [currentId, refreshCase, fetchPending]);

  const colors = sourceColorMap(caseDetail?.sources);
  const colorOf = (id) => colors[id] || "#8b96a1";

  function jumpToLine(sourceId, lineNo) {
    setViewer({ sourceId, offset: Math.max(0, lineNo - 1), highlight: lineNo });
    setView("viewer");
  }

  // M5:命中动作「跳检索」——整体重置检索条件(filters/tsFrom/tsTo)并立即检索;key 保证同条件也重触发。
  function gotoSearch(init) {
    setSearchInit({ ...init, key: Date.now() });
    setView("search");
  }

  // M5:命中动作「送交流区追问」——建会话(命中带 from_hit_id,后端生成命中上下文摘要)
  // → 切交流区选中该会话并预填追问。失败如实全局错误条,不静默。
  async function sendToChat({ hitId, contextText } = {}) {
    try {
      const r = await api.createChatSession(currentId, {
        title: hitId ? `命中 #${hitId} 追问` : "检索结果追问",
        fromHitId: hitId,
      });
      const prefill =
        "这条命中可疑吗?请结合日志证据分析。" +
        (contextText ? `\n相关原文:${contextText}` : "");
      setChatInit({ key: Date.now(), sessionId: r.id, prefill });
      setView("chat");
    } catch (err) {
      setError(err.message);
    }
  }

  function selectCase(id) {
    setCurrentId(id);
    setView("sources");
    setViewer({ sourceId: "", offset: 0, highlight: null });
    setSearchInit(null);
    setChatInit(null);
  }

  function resetSessionState() {
    setCases([]);
    setCurrentId(null);
    setCaseDetail(null);
    setView("sources");
    setViewer({ sourceId: "", offset: 0, highlight: null });
    setSearchInit(null);
    setChatInit(null);
    setPendingCount(0);
    setError(null);
    setPwOpen(false);
  }

  async function doLogout() {
    try {
      await api.logout();
    } catch {
      /* 登出请求失败也本地清态回登录页 */
    }
    resetSessionState();
    setAuth({ state: "anon", username: null });
  }

  if (auth.state === "loading") {
    return <div className="login-page muted">加载中…</div>;
  }
  if (auth.state === "anon") {
    return (
      <LoginGate
        onAuthed={(username) => {
          resetSessionState();
          setAuth({ state: "authed", username });
        }}
      />
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <span className="brand">索图</span>
          <span className="brand-sub">应用层日志分析工作台 · 按图索骥</span>
        </div>
        <div className="topbar-right">
          {caseDetail && <span className="topbar-case">案件:{caseDetail.name}</span>}
          {aiStatus &&
            (aiStatus.available ? (
              <span
                className="badge badge-ok"
                title={aiStatus.note || "仅表示已配置凭据,不代表服务实测连通"}
              >
                AI online{aiStatus.model ? `·${aiStatus.model}` : ""}
              </span>
            ) : (
              <span
                className="badge badge-muted"
                title={aiStatus.note || "未配置 API key,L1/L2 确定性分析不受影响"}
              >
                AI 未配置·诚实降级(仅确定性)
              </span>
            ))}
          {health && <span>后端 {health.version}</span>}
          {healthError && <span className="badge badge-danger">后端不可达</span>}
          <span className="topbar-user" title="当前登录用户">
            {auth.username}
          </span>
          <button className="link-btn" onClick={() => setAiCfgOpen(true)}>
            AI 设置
          </button>
          <button className="link-btn" onClick={() => setMcpOpen(true)}>
            MCP 接入
          </button>
          <button className="link-btn" onClick={() => setLogOpen(true)}>
            运行日志
          </button>
          <button className="link-btn" onClick={() => setPwOpen(true)}>
            修改密码
          </button>
          <button className="link-btn" onClick={doLogout}>
            退出
          </button>
        </div>
      </header>

      {pwOpen && <ChangePasswordModal onClose={() => setPwOpen(false)} />}
      {mcpOpen && (
        <McpModal onClose={() => setMcpOpen(false)} />
      )}
      {aiCfgOpen && (
        <AiSettingsModal
          onClose={() => setAiCfgOpen(false)}
          onSaved={refreshAiStatus}
        />
      )}
      {logOpen && (
        <div className="modal-mask" onClick={() => setLogOpen(false)}>
          <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <span>运行日志(app / error / operation,与审计链严格分离)</span>
              <button className="link-btn" onClick={() => setLogOpen(false)}>关闭</button>
            </div>
            <LogViewer />
          </div>
        </div>
      )}

      {healthError && (
        <div className="banner banner-error">
          无法连接后端(http://127.0.0.1:8100):{healthError}。请先启动后端。
        </div>
      )}
      {error && (
        <div className="banner banner-error" onClick={() => setError(null)} title="点击关闭">
          {error}
        </div>
      )}

      <div className="body">
        <CaseSidebar
          cases={cases}
          currentId={currentId}
          onSelect={selectCase}
          onCreated={(id) => {
            refreshCases();
            selectCase(id);
          }}
          onPolicyChanged={() => refreshCases()}
        />
        <main className="main">
          {!caseDetail ? (
            <div className="placeholder">
              {currentId ? "加载中…" : "请选择或新建一个案件。"}
            </div>
          ) : (
            <>
              <nav className="tabs">
                <button
                  className={`tab${view === "sources" ? " active" : ""}`}
                  onClick={() => setView("sources")}
                >
                  日志源
                </button>
                <button
                  className={`tab${view === "formatdesc" ? " active" : ""}`}
                  onClick={() => setView("formatdesc")}
                >
                  格式治理
                </button>
                <button
                  className={`tab${view === "search" ? " active" : ""}`}
                  onClick={() => setView("search")}
                >
                  检索
                </button>
                <button
                  className={`tab${view === "viewer" ? " active" : ""}`}
                  onClick={() => setView("viewer")}
                >
                  查看
                </button>
                <button
                  className={`tab${view === "rules" ? " active" : ""}`}
                  onClick={() => setView("rules")}
                >
                  规则与扫描
                </button>
                <button
                  className={`tab${view === "review" ? " active" : ""}`}
                  onClick={() => setView("review")}
                >
                  待审区
                  {pendingCount > 0 && <span className="count-badge">{pendingCount}</span>}
                </button>
                <button
                  className={`tab${view === "ai" ? " active" : ""}`}
                  onClick={() => setView("ai")}
                >
                  AI 分析
                </button>
                <button
                  className={`tab${view === "chat" ? " active" : ""}`}
                  onClick={() => setView("chat")}
                >
                  交流区
                </button>
              </nav>
              {view === "sources" && (
                <SourcesPane
                  caseDetail={caseDetail}
                  colorOf={colorOf}
                  onChanged={() => refreshCase(currentId)}
                />
              )}
              {view === "formatdesc" && (
                <FormatDescPane caseDetail={caseDetail} />
              )}
              {view === "search" && (
                <SearchPane
                  caseDetail={caseDetail}
                  colorOf={colorOf}
                  onJump={jumpToLine}
                  searchInit={searchInit}
                  onSearchInitConsumed={() => setSearchInit(null)}
                  onGotoSearch={gotoSearch}
                  onSendToChat={sendToChat}
                />
              )}
              {view === "viewer" && (
                <ViewerPane
                  caseDetail={caseDetail}
                  viewer={viewer}
                  setViewer={setViewer}
                />
              )}
              {view === "rules" && (
                <RulesPane caseDetail={caseDetail} onScanned={() => fetchPending(currentId)} />
              )}
              {view === "review" && (
                <ReviewPane
                  caseDetail={caseDetail}
                  colorOf={colorOf}
                  onJump={jumpToLine}
                  onAdjudicated={() => fetchPending(currentId)}
                  onGotoSearch={gotoSearch}
                  onSendToChat={sendToChat}
                />
              )}
              {view === "ai" && (
                <AiPane
                  caseDetail={caseDetail}
                  aiStatus={aiStatus}
                  onGotoReview={() => {
                    fetchPending(currentId);
                    setView("review");
                  }}
                  onFindingsChanged={() => fetchPending(currentId)}
                />
              )}
              {view === "chat" && (
                <ChatPane
                  caseDetail={caseDetail}
                  aiStatus={aiStatus}
                  chatInit={chatInit}
                  onChatInitConsumed={() => setChatInit(null)}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}

// 修改密码小弹窗:旧口令校验;改后其它会话全部失效(后端行为),当前会话保留。
function ChangePasswordModal({ onClose }) {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    if (newPw !== newPw2) {
      setError("两次输入的新口令不一致。");
      return;
    }
    setBusy(true);
    try {
      const r = await api.changePassword(oldPw, newPw);
      setNotice(r.message || "口令已修改。");
      setOldPw("");
      setNewPw("");
      setNewPw2("");
    } catch (err) {
      setError(err.message); // 401 旧口令错 / 422 长度不足,原文如实
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>修改密码</span>
          <button className="link-btn" onClick={onClose}>关闭</button>
        </div>
        <form className="inline-form" onSubmit={submit}>
          <input
            type="password"
            placeholder="旧口令"
            autoComplete="current-password"
            value={oldPw}
            onChange={(e) => setOldPw(e.target.value)}
          />
          <input
            type="password"
            placeholder="新口令(至少 8 位)"
            autoComplete="new-password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
          />
          <input
            type="password"
            placeholder="再次输入新口令"
            autoComplete="new-password"
            value={newPw2}
            onChange={(e) => setNewPw2(e.target.value)}
          />
          {error && <div className="form-error">{error}</div>}
          {notice && <div className="form-ok">{notice}</div>}
          <div className="form-row">
            <button className="primary" type="submit" disabled={busy || !oldPw || !newPw}>
              {busy ? "提交中…" : "确认修改"}
            </button>
            <span className="muted">改后其它设备/浏览器的会话将全部失效。</span>
          </div>
        </form>
      </div>
    </div>
  );
}
