import { useState } from "react";
import { api } from "../api.js";

// M4 登录闸:未认证时全屏登录页。无用户首启可切「初始化管理员」setup 表单
// (后端仅无用户时开放,已初始化 → 403 如实);setup 成功后回登录表单。
export default function LoginGate({ onAuthed }) {
  const [mode, setMode] = useState("login"); // login | setup
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    if (mode === "setup" && password !== password2) {
      setError("两次输入的口令不一致。");
      return;
    }
    setBusy(true);
    try {
      if (mode === "setup") {
        const r = await api.setup(username.trim(), password);
        setMode("login");
        setPassword("");
        setPassword2("");
        setNotice(r.message || "首个账号已创建,请登录。");
      } else {
        const r = await api.login(username.trim(), password);
        onAuthed(r.username);
      }
    } catch (err) {
      // setup 已初始化 → 403 原文;登录失败 → 401/423 原文(含锁定时长)
      setError(err.message);
      if (mode === "setup" && err.status === 403) setMode("login");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">索图</div>
        <div className="login-sub">按图索骥 · 应用层日志分析工作台</div>
        <div className="login-sub">描述一副地图，找出那个不合理。</div>
        <form onSubmit={submit}>
          <input
            autoFocus
            placeholder="用户名"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder={mode === "setup" ? "口令(至少 8 位)" : "口令"}
            autoComplete={mode === "setup" ? "new-password" : "current-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {mode === "setup" && (
            <input
              type="password"
              placeholder="再次输入口令"
              autoComplete="new-password"
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
            />
          )}
          {error && <div className="form-error">{error}</div>}
          {notice && <div className="form-ok">{notice}</div>}
          <button
            className="primary"
            type="submit"
            disabled={busy || !username.trim() || !password}
          >
            {busy ? "请稍候…" : mode === "setup" ? "初始化管理员" : "登录"}
          </button>
        </form>
        <div className="login-switch">
          {mode === "login" ? (
            <button
              className="link-btn"
              onClick={() => {
                setMode("setup");
                setError(null);
                setNotice(null);
              }}
            >
              首次使用?初始化管理员账号
            </button>
          ) : (
            <button
              className="link-btn"
              onClick={() => {
                setMode("login");
                setError(null);
                setNotice(null);
              }}
            >
              已有账号?返回登录
            </button>
          )}
        </div>
        <div className="login-foot muted">
          判断权归人 · 证据链不可断 —— 本机数据不出机
        </div>
      </div>
    </div>
  );
}
