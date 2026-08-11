"""登录认证与账号(M4,主机取证平台 M5b 模式平移:多账号、无角色,模型 B)。

设计决策(与主机取证平台同口径,差异处注明):
- 所有登录用户权限相同;任何登录用户可新建/停用账号——有意简化,
  适用于单案件小组内网部署,不是 RBAC;
- 口令哈希:stdlib hashlib.pbkdf2_hmac('sha256'),20 万轮,每用户随机盐,零新依赖;
- 会话:登录签发 32 字节随机 token,**库中只落 SHA256 哈希**(token 明文不落库),
  持久化到 auth.db(服务重启不踢人),12 小时滑动过期(每次请求续期);
  HttpOnly + SameSite=Strict Cookie(路径 /;无 TLS 环境不设 Secure);
- 防爆破:同一账号连续失败 5 次锁 **10 分钟**(主机取证平台为 15,本端按 M4 定稿 10);
  内存计数,**服务重启清零**——锁只是减速带,不是安全边界,重启清零是有意取舍;
- 账号库独立文件 data/auth.db:用户跨案件,不随案件封存/删除走;
- 审计锚真人:登录成功/失败/锁定/登出/建号/停号/改密全部写哈希链审计
  (audit_log.case_id='system', scope='auth');审计记事件事实,
  **永不记口令/token 明文**;登录成功/失败/锁定同时落 app.log 运行日志
  (排障用,与审计严格分离,同样不记口令);
- 改密后:该用户**其它会话全部失效**,当前会话保留(与主机取证平台同取舍)。

锁定计数在进程内存:并发下不加锁(CPython GIL 下 dict 操作原子,多算少算一次
不影响「连续 5 次」语义的防守目的)。
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import config, db, logging_setup

COOKIE_NAME = "suotu_session"
SESSION_TTL = timedelta(hours=12)          # 滑动过期:每次认证通过即续期
LOCK_THRESHOLD = 5                          # 连续失败次数上限
LOCK_MINUTES = 10                           # 锁定时长(M4 定稿;主机取证平台为 15)
PBKDF2_ROUNDS = 200_000
MIN_PASSWORD_LEN = 8

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES users(username),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

router = APIRouter(prefix="/auth", tags=["auth"])

# username -> [连续失败次数, 锁定截止时刻(None=未锁)];进程内存,重启清零(有意取舍)
_fails: dict[str, list] = {}


# ==================== 库与口令 ====================

def _conn() -> sqlite3.Connection:
    path = config.auth_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    # 与 case.db 同一并发硬化:会话校验是每请求一次的读,登录/滑动续期是写,
    # WAL 下互不挡;写冲突等锁 5s。
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    return conn


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS).hex()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def has_users() -> bool:
    conn = _conn()
    try:
        return conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] > 0
    finally:
        conn.close()


def create_user(username: str, password: str) -> None:
    """建账号(口令落 pbkdf2 哈希+随机盐,明文绝不留存)。用户名冲突抛 409。"""
    username = username.strip()
    if not username:
        raise HTTPException(422, "用户名不能为空")
    if len(password) < MIN_PASSWORD_LEN:
        raise HTTPException(422, f"口令至少 {MIN_PASSWORD_LEN} 位")
    salt = secrets.token_bytes(16)
    conn = _conn()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, created_at, disabled)"
                " VALUES (?,?,?,?,0)",
                (username, _hash_password(password, salt), salt.hex(),
                 _now().isoformat()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"用户名已存在: {username}")
    finally:
        conn.close()


def _verify(username: str, password: str) -> bool:
    """校验口令;用户不存在或已停用一律 False(不区分,防账号枚举)。"""
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT password_hash, salt, disabled FROM users WHERE username = ?",
            (username,)).fetchone()
    finally:
        conn.close()
    if row is None or row["disabled"]:
        return False
    return secrets.compare_digest(
        _hash_password(password, bytes.fromhex(row["salt"])), row["password_hash"])


def _set_disabled(username: str, disabled: bool) -> None:
    conn = _conn()
    try:
        with conn:
            cur = conn.execute("UPDATE users SET disabled = ? WHERE username = ?",
                               (int(disabled), username))
            if cur.rowcount == 0:
                raise HTTPException(404, f"用户不存在: {username}")
            if disabled:                       # 停用即踢:该用户会话全部销毁
                conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
    finally:
        conn.close()


def change_password(username: str, old: str, new: str,
                    keep_token: str | None = None) -> None:
    """改密:旧口令校验通过才改;改后其它会话全失效,keep_token 当前会话保留。"""
    if len(new) < MIN_PASSWORD_LEN:
        raise HTTPException(422, f"新口令至少 {MIN_PASSWORD_LEN} 位")
    if not _verify(username, old):
        raise HTTPException(401, "旧口令不正确")
    salt = secrets.token_bytes(16)
    conn = _conn()
    try:
        with conn:
            conn.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                         (_hash_password(new, salt), salt.hex(), username))
            if keep_token is None:
                conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
            else:
                conn.execute(
                    "DELETE FROM sessions WHERE username = ? AND token_hash != ?",
                    (username, _token_hash(keep_token)))
    finally:
        conn.close()


# ==================== 会话 ====================

def create_session(username: str) -> str:
    """签发会话 token(32 字节随机);库里只落哈希,token 明文仅此返回值。"""
    token = secrets.token_urlsafe(32)
    conn = _conn()
    try:
        with conn:
            conn.execute(
                "INSERT INTO sessions (token_hash, username, expires_at, created_at)"
                " VALUES (?,?,?,?)",
                (_token_hash(token), username,
                 (_now() + SESSION_TTL).isoformat(), _now().isoformat()))
    finally:
        conn.close()
    return token


def validate_session(token: str) -> str | None:
    """校验会话:存在 ∧ 未过期 ∧ 用户未停用 → 滑动续期并返回用户名,否则 None。"""
    if not token:
        return None
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT s.token_hash, s.username, s.expires_at, u.disabled"
            " FROM sessions s JOIN users u ON u.username = s.username"
            " WHERE s.token_hash = ?", (_token_hash(token),)).fetchone()
        if row is None or row["disabled"]:
            return None
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            return None
        if expires <= _now():                  # 过期即清,不留死会话
            with conn:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?",
                             (row["token_hash"],))
            return None
        with conn:                             # 滑动续期(每次请求重置 12h)
            conn.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
                         ((_now() + SESSION_TTL).isoformat(), row["token_hash"]))
        return row["username"]
    finally:
        conn.close()


def destroy_session(token: str) -> None:
    conn = _conn()
    try:
        with conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?",
                         (_token_hash(token),))
    finally:
        conn.close()


# ==================== 防爆破锁定(内存计数,重启清零) ====================

def _lock_remaining(username: str) -> int:
    """剩余锁定分钟;未锁/锁已到期返回 0(到期顺手清零计数)。"""
    state = _fails.get(username)
    if not state or state[1] is None:
        return 0
    left = (state[1] - _now()).total_seconds()
    if left <= 0:
        _fails.pop(username, None)
        return 0
    return max(1, int(left // 60) + 1)


def _record_failure(username: str) -> int:
    """记一次失败;达到阈值上锁。返回剩余锁定分钟(未锁为 0)。"""
    state = _fails.setdefault(username, [0, None])
    state[0] += 1
    if state[0] >= LOCK_THRESHOLD:
        state[1] = _now() + timedelta(minutes=LOCK_MINUTES)
        return LOCK_MINUTES
    return 0


def _record_success(username: str) -> None:
    _fails.pop(username, None)


# ==================== FastAPI 依赖 ====================

def require_user(request: Request) -> str:
    """认证依赖:Cookie 取 token → 校验+滑动续期 → 返回用户名;失败 401。"""
    username = validate_session(request.cookies.get(COOKIE_NAME, ""))
    if username is None:
        raise HTTPException(401, "未认证或会话过期")
    return username


def current_username(request: Request) -> str:
    """取当前用户名(全局认证闸已认证过则直接读 state,否则现场认证)。"""
    cached = getattr(request.state, "username", None)
    return cached if cached else require_user(request)


# ==================== 审计(case_id='system';记事件不记秘密) ====================

def _audit(actor: str, action: str, target: str | None = None,
           detail: dict | None = None) -> None:
    d = dict(detail or {})
    if target is not None:
        d["target"] = target
    conn = db.connect()
    try:
        with conn:
            db.append_audit(conn, "system", actor=actor, action=action,
                            scope="auth", detail=d)
    finally:
        conn.close()


# ==================== 端点 ====================

class Credentials(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class UserCreate(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=MIN_PASSWORD_LEN)


class UserPatch(BaseModel):
    disabled: bool


class PasswordChange(BaseModel):
    old_password: str = Field(min_length=1)
    new_password: str = Field(min_length=MIN_PASSWORD_LEN)


@router.post("/setup", status_code=201)
def setup(body: Credentials):
    """首启引导:仅在系统无任何用户时可建首个账号;有用户后一律 403。"""
    if has_users():
        raise HTTPException(403, "系统已初始化,首启引导关闭;请登录后由已有账号建号")
    username = body.username.strip()
    create_user(username, body.password)
    _audit(username, "user_create", target=username,
           detail={"via": "setup", "first_user": True})
    return {"username": username, "message": "首个账号已创建,请登录"}


@router.post("/login")
def login(body: Credentials, response: Response):
    """登录:口令校验 → 签发会话 Cookie;连续失败 5 次锁 10 分钟。"""
    username = body.username.strip()
    remaining = _lock_remaining(username)
    if remaining:
        _audit(username, "login_failed", target=username,
               detail={"reason": "locked", "remaining_minutes": remaining})
        # 运行日志记认证事件(永不记口令;与审计并行,各记各的)
        logging_setup.app_logger().warning(
            "登录失败(锁定中) user=%s remaining=%dmin", username, remaining)
        raise HTTPException(423, f"账号已锁定,请 {remaining} 分钟后再试")
    if not _verify(username, body.password):
        locked = _record_failure(username)
        if locked:
            _audit(username, "login_locked", target=username,
                   detail={"threshold": LOCK_THRESHOLD, "lock_minutes": LOCK_MINUTES})
            logging_setup.app_logger().warning(
                "账号锁定 user=%s 连续失败 %d 次,锁 %d 分钟",
                username, LOCK_THRESHOLD, LOCK_MINUTES)
            raise HTTPException(423, f"连续失败 {LOCK_THRESHOLD} 次,账号锁定 "
                                     f"{LOCK_MINUTES} 分钟")
        _audit(username, "login_failed", target=username,
               detail={"reason": "bad_credentials"})
        logging_setup.app_logger().warning("登录失败(凭据不符) user=%s", username)
        raise HTTPException(401, "用户名或口令不正确")
    _record_success(username)
    token = create_session(username)
    _audit(username, "login_success", target=username)
    logging_setup.app_logger().info("登录成功 user=%s", username)
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, samesite="strict", path="/",
        max_age=int(SESSION_TTL.total_seconds()))
    return {"username": username, "message": "登录成功"}


@router.post("/logout")
def logout(request: Request, response: Response):
    """登出:销毁会话 + 清 Cookie + 写审计。"""
    username = current_username(request)
    destroy_session(request.cookies.get(COOKIE_NAME, ""))
    response.delete_cookie(COOKIE_NAME, path="/")
    _audit(username, "logout", target=username)
    return {"message": "已登出"}


@router.get("/me")
def me(request: Request):
    return {"username": current_username(request)}


@router.post("/users", status_code=201)
def create_user_endpoint(body: UserCreate, request: Request):
    """建号(模型 B:任何登录用户可建,无角色)。"""
    actor = current_username(request)
    username = body.username.strip()
    create_user(username, body.password)
    _audit(actor, "user_create", target=username, detail={"via": "users_api"})
    return {"username": username, "message": "账号已创建"}


@router.patch("/users/{username}")
def patch_user(username: str, body: UserPatch, request: Request):
    """停用/启用账号(停用即销毁其全部会话)。"""
    actor = current_username(request)
    _set_disabled(username, body.disabled)
    _audit(actor, "user_disable" if body.disabled else "user_enable",
           target=username)
    return {"username": username, "disabled": body.disabled}


@router.post("/change-password")
def change_password_endpoint(body: PasswordChange, request: Request):
    """改密:旧口令校验;改后该用户其它会话全部失效,当前会话保留。"""
    username = current_username(request)
    change_password(username, body.old_password, body.new_password,
                    keep_token=request.cookies.get(COOKIE_NAME))
    _audit(username, "password_change", target=username)
    return {"message": "口令已修改;其它会话已失效,当前会话保留"}
