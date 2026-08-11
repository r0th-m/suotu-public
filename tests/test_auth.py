"""M4 登录认证:setup→login→me→改密→新密码登录;错密 5 连锁定 423;
未登录访问业务端点 401;disabled 用户拒登;白名单端点免认证。

测试纪律:凭据仅测试用(auth_session fixture 注入的 tester 同理),
.env 永不进测试;防爆破内存计数由 auth_session fixture 每用例清零。
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import auth
from backend.app.main import app


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


def test_unauthenticated_business_endpoints_401(client):
    """全局认证闸:白名单外一律 401;白名单(/healthz /auth/login /auth/setup)
    与 SPA 入口(/、/assets/*)免认证。"""
    client.cookies.clear()
    assert client.get("/cases").status_code == 401
    assert client.post("/cases", json={"name": "x"}).status_code == 401
    assert client.get("/auth/me").status_code == 401
    # 白名单
    assert client.get("/healthz").status_code == 200
    # SPA 入口公开(React 自判登录态渲染登录页;浏览器不应吃到 401 JSON)
    assert client.get("/").status_code == 200
    r = client.post("/auth/login",
                    json={"username": "tester", "password": "Tester#2026pass"})
    assert r.status_code == 200


def test_me_with_session(client):
    r = client.get("/auth/me")
    assert r.status_code == 200 and r.json()["username"] == "tester"


def test_setup_only_when_no_users(client):
    """首启引导:无用户开放,有用户后 403 关闭。"""
    client.cookies.clear()
    # fixture 已建 tester → 已初始化,setup 关闭
    assert client.post("/auth/setup", json={
        "username": "x", "password": "12345678"}).status_code == 403
    # 清空用户表模拟首启(测试专用手法,非生产路径)
    conn = auth._conn()
    with conn:
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM users")
    conn.close()
    r = client.post("/auth/setup",
                    json={"username": "admin", "password": "Admin#2026pass"})
    assert r.status_code == 201
    assert client.post("/auth/setup", json={
        "username": "y", "password": "12345678"}).status_code == 403
    # 新首号可登录
    r = client.post("/auth/login",
                    json={"username": "admin", "password": "Admin#2026pass"})
    assert r.status_code == 200


def test_login_logout_roundtrip(client):
    client.cookies.clear()
    r = client.post("/auth/login",
                    json={"username": "tester", "password": "Tester#2026pass"})
    assert r.status_code == 200 and auth.COOKIE_NAME in r.cookies
    assert client.get("/auth/me").json()["username"] == "tester"
    assert client.post("/auth/logout").status_code == 200
    client.cookies.clear()     # 登出后 Cookie 已销毁,清空本地模拟浏览器行为
    assert client.get("/auth/me").status_code == 401


def test_wrong_password_locks_after_5(client):
    """同一账号连续失败 5 次锁 10 分钟:第 5 次即 423,锁定期内正确口令也 423。"""
    client.cookies.clear()
    for i in range(4):
        r = client.post("/auth/login",
                        json={"username": "tester", "password": "wrong-pass"})
        assert r.status_code == 401, f"第 {i + 1} 次应 401"
    r = client.post("/auth/login",
                    json={"username": "tester", "password": "wrong-pass"})
    assert r.status_code == 423                      # 第 5 次上锁,如实 423
    assert "锁定" in r.json()["detail"]
    # 锁定期内即使口令正确也 423(锁是减速带)
    r = client.post("/auth/login",
                    json={"username": "tester", "password": "Tester#2026pass"})
    assert r.status_code == 423


def test_change_password_then_new_login(client):
    """改密:旧口令校验;改后旧口令拒、新口令登;当前会话保留。"""
    r = client.post("/auth/change-password", json={
        "old_password": "Tester#2026pass", "new_password": "NewPass#2026"})
    assert r.status_code == 200
    assert client.get("/auth/me").status_code == 200      # 当前会话保留
    client.cookies.clear()
    assert client.post("/auth/login", json={
        "username": "tester", "password": "Tester#2026pass"}
        ).status_code == 401                              # 旧口令已废
    r = client.post("/auth/login",
                    json={"username": "tester", "password": "NewPass#2026"})
    assert r.status_code == 200                           # 新口令可登
    # 旧口令错 → 改密 401
    assert client.post("/auth/change-password", json={
        "old_password": "nope-nope", "new_password": "Another#2026"}
        ).status_code == 401


def test_create_and_disable_user(client):
    """建号(登录态)→ 新号可登;停用 → 拒登且会话即毁;启用 → 恢复。"""
    r = client.post("/auth/users",
                    json={"username": "bob", "password": "Bob#2026pass"})
    assert r.status_code == 201
    assert client.post("/auth/users", json={
        "username": "bob", "password": "Bob#2026pass"}).status_code == 409

    bob = TestClient(app)
    bob.cookies.clear()
    r = bob.post("/auth/login",
                 json={"username": "bob", "password": "Bob#2026pass"})
    assert r.status_code == 200

    r = client.patch("/auth/users/bob", json={"disabled": True})
    assert r.status_code == 200 and r.json()["disabled"] is True
    assert bob.get("/auth/me").status_code == 401          # 停用即踢
    assert bob.post("/auth/login", json={
        "username": "bob", "password": "Bob#2026pass"}
        ).status_code == 401                               # 停用拒登

    client.patch("/auth/users/bob", json={"disabled": False})
    assert bob.post("/auth/login", json={
        "username": "bob", "password": "Bob#2026pass"}).status_code == 200
    assert client.patch("/auth/users/nobody",
                        json={"disabled": True}).status_code == 404


def test_auth_actions_audited(client):
    """审计锚真人:登录/建号全部进哈希链(case_id='system', actor 是真人),
    且永不记口令明文。"""
    client.cookies.clear()
    client.post("/auth/login",
                json={"username": "tester", "password": "Tester#2026pass"})
    from backend.app import db
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT actor, action, detail_json FROM audit_log"
            " WHERE case_id = 'system' AND scope = 'auth'"
            " ORDER BY id").fetchall()
        assert any(r["action"] == "login_success" and r["actor"] == "tester"
                   for r in rows)
        assert all("Tester#2026pass" not in (r["detail_json"] or "")
                   for r in rows)                       # 秘密永不出本层
        ok, msg = db.verify_audit(conn)
        assert ok, msg
    finally:
        conn.close()
