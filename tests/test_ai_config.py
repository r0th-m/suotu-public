"""M6 AI 设置面板契约测试(移植自树庭,断言级焊死)。

纪律(同 conftest ai_env):
- .env 永不进测试:_env_file monkeypatch 到 tmp_path,真实凭据文件不读不写;
- AI_* / DEEPSEEK_* 环境变量逐用例清空,按需 setenv;
- 真实 HTTP 永不发生:云端测连 mock _call_api,ollama 测连 mock urlopen。

覆盖:快照掩码(key 不出接口)/ 保存写 .env 保留无关行 / legacy DEEPSEEK_*
兜底 / 厂商校验(未知 422)/ needs_key 缺 key 422 / ollama 免 key online /
无 key 非 ollama → offline_lite / PUT 审计不含 key / test 端点不写盘不写审计。
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.app import ai
from backend.app.main import app

SECRET = "sk-test-abcdef1234567890"     # 合成凭据,非真实 key


@pytest.fixture()
def ai_cfg(tmp_path, monkeypatch):
    """AI 设置测试环境:.env 重定向到 tmp(真实文件不进测试),
    AI_* / DEEPSEEK_* 环境变量清空;返回 tmp .env 路径供断言。"""
    env_path = tmp_path / ".env"
    monkeypatch.setattr(ai, "_env_file", lambda: env_path)
    for key in ("AI_PROVIDER", "AI_BASE_URL", "AI_MODEL", "AI_API_KEY",
                "DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL"):
        monkeypatch.delenv(key, raising=False)
    return env_path


def _client():
    return TestClient(app)               # 会话 Cookie 由 conftest 统一注入


# ---------------------------------------------------------------- 快照掩码

def test_snapshot_masks_key(ai_cfg, monkeypatch):
    """key 明文永不出接口:快照只有 has_key + 掩码,全文不含明文。"""
    monkeypatch.setenv("AI_PROVIDER", "deepseek")
    monkeypatch.setenv("AI_API_KEY", SECRET)
    snap = ai.config_snapshot()
    assert snap["key_configured"] is True
    assert snap["key_hint"] and "…" in snap["key_hint"]
    assert SECRET not in json.dumps(snap, ensure_ascii=False)
    with _client() as c:
        r = c.get("/ai/config")
    assert r.status_code == 200
    assert SECRET not in r.text           # HTTP 层同样不含明文
    body = r.json()
    assert body["key_configured"] is True and body["provider"] == "deepseek"
    assert any(p["id"] == "ollama" for p in body["presets"])


# ---------------------------------------------------------------- 保存写 .env

def test_save_preserves_unrelated_lines(ai_cfg):
    """写回 .env:已有键原位替换,注释/空行/无关键原样保留。"""
    ai_cfg.write_text(
        "# 部署备注:勿动\n"
        "\n"
        "OTHER_KEY=keepme\n"
        "AI_PROVIDER=deepseek\n", encoding="utf-8")
    snap = ai.save_config("openai", None, None, SECRET)
    text = ai_cfg.read_text(encoding="utf-8")
    assert "# 部署备注:勿动" in text and "OTHER_KEY=keepme" in text
    assert text.count("AI_PROVIDER=") == 1        # 原位替换,不重复追加
    assert "AI_PROVIDER=openai" in text
    assert f"AI_API_KEY={SECRET}" in text
    assert snap["provider"] == "openai"
    assert snap["base_url"] == "https://api.openai.com/v1"   # 预设兜底
    assert snap["model"] == "gpt-4o-mini"
    # 环境变量优先于 .env:保存后重读仍走文件(本用例未 setenv)
    assert ai._resolve_config()["api_key"] == SECRET


def test_save_empty_key_keeps_existing(ai_cfg):
    """key 留空 = 不动现有 key(设置面板语义)。"""
    ai.save_config("deepseek", None, None, SECRET)
    snap = ai.save_config("deepseek", "https://api.deepseek.com",
                          "deepseek-v4-pro", "")
    assert snap["model"] == "deepseek-v4-pro"
    assert ai._resolve_config()["api_key"] == SECRET


# ---------------------------------------------------------------- legacy 兜底

def test_legacy_deepseek_fallback(ai_cfg, monkeypatch):
    """只有旧 DEEPSEEK_* 键的部署:零迁移按 deepseek 处理,档位 online。"""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k-legacy")
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    cfg = ai._resolve_config()
    assert cfg["provider"] == "deepseek"
    assert cfg["base_url"] == "https://api.deepseek.com"
    assert cfg["model"]                     # 预设推荐兜底,非空
    assert ai.profile() == "online" and ai.ai_available() is True


def test_normalized_keys_take_precedence(ai_cfg, monkeypatch):
    """规范键 AI_* 优先于旧 DEEPSEEK_* 键。"""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k-legacy")
    monkeypatch.setenv("AI_PROVIDER", "zhipu")
    monkeypatch.setenv("AI_API_KEY", "k-new")
    cfg = ai._resolve_config()
    assert cfg["provider"] == "zhipu" and cfg["api_key"] == "k-new"
    assert cfg["base_url"] == "https://open.bigmodel.cn/api/paas/v4"


# ---------------------------------------------------------------- 档位

def test_ollama_online_without_key(ai_cfg, monkeypatch):
    """ollama 本地免 key:无 key 也 online(索图两档取舍)。"""
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    assert ai.profile() == "online" and ai.ai_available() is True
    st = ai.status()
    assert st["available"] is True and st["provider"] == "ollama"
    assert st["key_configured"] is False


def test_no_key_non_ollama_offline_lite(ai_cfg, monkeypatch):
    """无 key 且非 ollama → offline_lite(诚实降级)。"""
    monkeypatch.setenv("AI_PROVIDER", "openai")
    assert ai.profile() == "offline_lite" and ai.ai_available() is False
    st = ai.status()
    assert st["available"] is False and "降级" in st["note"]


# ---------------------------------------------------------------- 端点校验/审计

def test_put_unknown_provider_422(ai_cfg):
    with _client() as c:
        r = c.put("/ai/config", json={"provider": "nope-such"})
    assert r.status_code == 422
    assert "未知厂商" in r.json()["detail"]


def test_put_needs_key_without_key_422(ai_cfg):
    """needs_key 厂商:新填与已存皆无 key → 422;ollama 免 key 放行。"""
    with _client() as c:
        r = c.put("/ai/config", json={"provider": "openai"})
        assert r.status_code == 422 and "key" in r.json()["detail"].lower()
        r2 = c.put("/ai/config", json={"provider": "ollama"})
    assert r2.status_code == 200
    assert r2.json()["provider"] == "ollama"
    assert r2.json()["base_url"] == "http://localhost:11434/v1"


def test_put_audit_never_contains_key(ai_cfg, conn):
    """PUT 写审计:actor 锚真人,detail 只有厂商/模型/base_url,永不记 key。"""
    with _client() as c:
        r = c.put("/ai/config",
                  json={"provider": "moonshot", "api_key": SECRET,
                        "consent_external": True})   # 合规闸(2026-08-11)
    assert r.status_code == 200
    rows = conn.execute(
        "SELECT actor, action, scope, detail_json FROM audit_log"
        " WHERE action = 'ai_config_change'").fetchall()
    assert len(rows) == 1
    assert rows[0]["actor"] == "tester"     # 会话真人(conftest 注入)
    assert rows[0]["scope"] == "ai"
    assert SECRET not in rows[0]["detail_json"]
    detail = json.loads(rows[0]["detail_json"])
    assert detail["provider"] == "moonshot" and "api_key" not in detail


# ---------------------------------------------------------------- 测连端点

def _ok_resp(model="m-test"):
    return {"content": "pong", "tool_calls": None, "model": model,
            "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                      "total_tokens": 2}}


def test_test_endpoint_no_write_no_audit(ai_cfg, conn, monkeypatch):
    """测连成功:回模型/延迟;不写 .env、不写 ai_config_change 审计。"""
    monkeypatch.setattr(ai, "_call_api", lambda *a, **k: _ok_resp())
    with _client() as c:
        r = c.post("/ai/config/test",
                   json={"provider": "deepseek", "api_key": SECRET})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["model"] == "m-test"
    assert isinstance(body["latency_ms"], int)
    assert not ai_cfg.exists()              # 测连不落盘
    n = conn.execute(
        "SELECT COUNT(*) AS c FROM audit_log"
        " WHERE action = 'ai_config_change'").fetchone()["c"]
    assert n == 0                           # 测连不写审计


def test_test_endpoint_failure_classified(ai_cfg, monkeypatch):
    """测连失败如实分类(auth),不吞不混;同样不写盘。"""
    def _boom(*a, **k):
        raise ai.AIError(ai.KIND_AUTH, "AI 鉴权失败(HTTP 401):检查 API key")

    monkeypatch.setattr(ai, "_call_api", _boom)
    with _client() as c:
        r = c.post("/ai/config/test",
                   json={"provider": "deepseek", "api_key": "bad"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["kind"] == "auth"
    assert not ai_cfg.exists()


def test_test_endpoint_offline_without_key(ai_cfg):
    """无 key 云端测连 → ok=False,kind=offline(不发生任何调用)。"""
    with _client() as c:
        r = c.post("/ai/config/test", json={"provider": "openai"})
    assert r.status_code == 200
    assert r.json()["ok"] is False and r.json()["kind"] == "offline"


def test_test_endpoint_unknown_provider_422(ai_cfg):
    with _client() as c:
        r = c.post("/ai/config/test", json={"provider": "nope-such"})
    assert r.status_code == 422


class _FakeResp:
    """urlopen 假响应:read() 给 api/tags JSON。"""

    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


def test_test_endpoint_ollama_lists_local_models(ai_cfg, monkeypatch):
    """ollama 测连:GET {base 去 /v1}/api/tags,回本地模型清单;免 key。"""
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        return _FakeResp({"models": [{"name": "qwen3:8b"},
                                     {"name": "llama3.1:8b"}]})

    monkeypatch.setattr(ai.urllib.request, "urlopen", fake_urlopen)
    with _client() as c:
        r = c.post("/ai/config/test",
                   json={"provider": "ollama",
                         "base_url": "http://localhost:11434/v1",
                         "model": "qwen3:8b"})
    assert r.status_code == 200
    body = r.json()
    assert seen["url"] == "http://localhost:11434/api/tags"   # v1 已剥
    assert body["ok"] is True
    assert body["local_models"] == ["llama3.1:8b", "qwen3:8b"]  # 排序
    assert body["model_present"] is True
    assert not ai_cfg.exists()


def test_test_endpoint_ollama_unreachable(ai_cfg, monkeypatch):
    """ollama 不可达 → kind=network 如实。"""
    import urllib.error

    def _boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(ai.urllib.request, "urlopen", _boom)
    with _client() as c:
        r = c.post("/ai/config/test", json={"provider": "ollama"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["kind"] == "network"


# -------------------------------------------------- 外发同意闸(2026-08-11)

def test_put_online_without_consent_422(ai_cfg):
    """在线厂商 + 未同意 → 422;不写 .env、不留审计(闸门要响,不静默)。"""
    with _client() as c:
        r = c.put("/ai/config", json={"provider": "deepseek",
                                      "api_key": SECRET})
        assert r.status_code == 422 and "外发" in r.json()["detail"]
        assert c.get("/ai/consent").json()["consented"] is False
    assert not ai_cfg.exists()                      # 配置未写入
    with _client() as c:
        # 勾选后放行 + 同意记录落库(审计锚人)
        r2 = c.put("/ai/config", json={"provider": "deepseek",
                                       "api_key": SECRET,
                                       "consent_external": True})
        assert r2.status_code == 200
        cs = c.get("/ai/consent").json()
        assert cs["consented"] is True and cs["actor"] == "tester"


def test_consent_endpoint_idempotent(ai_cfg, conn):
    """POST /ai/consent 幂等;每次都留痕(动作如实)。"""
    with _client() as c:
        r1 = c.post("/ai/consent")
        assert r1.status_code == 200 and r1.json()["consented"] is True
        c.post("/ai/consent")
    rows = conn.execute(
        "SELECT actor FROM audit_log WHERE action = 'ai_external_consent'"
    ).fetchall()
    assert len(rows) == 2 and all(r["actor"] == "tester" for r in rows)


def test_chat_gate_consent_required(ai_cfg, monkeypatch, conn):
    """外发档无同意记录 → chat() 硬闸 consent_required(调用未发生)。"""
    monkeypatch.setenv("AI_PROVIDER", "deepseek")
    monkeypatch.setenv("AI_API_KEY", SECRET)
    with pytest.raises(ai.AIError) as ei:
        ai.chat([{"role": "user", "content": "hi"}])
    assert ei.value.kind == "consent_required"


def test_chat_gate_case_blocked(ai_cfg, monkeypatch, conn):
    """已同意但本案禁外发 → external_blocked;解除后放行(mock 出口);
    ollama 本地档不受闸(数据不出机)。"""
    monkeypatch.setenv("AI_PROVIDER", "deepseek")
    monkeypatch.setenv("AI_API_KEY", SECRET)
    with conn:
        conn.execute("INSERT INTO cases (id, name, created_at)"
                     " VALUES ('c-gate','闸','now')")
    ai.set_case_external_blocked(conn, "c-gate", True, "tester")
    # 未同意先撞全局闸
    with pytest.raises(ai.AIError) as ei:
        ai.chat([{"role": "user", "content": "hi"}], run_id=None)
    assert ei.value.kind == "consent_required"
    ai.record_external_consent(conn, "tester")

    # 同意后,案件闸需要 run 语境(case_id 经 run_id 反查);直接单元验闸门函数
    with pytest.raises(ai.AIError) as ei2:
        ai._external_gate(conn, "c-gate")
    assert ei2.value.kind == "external_blocked"
    ai._external_gate(conn, "c-other")            # 别的案件放行
    ai.set_case_external_blocked(conn, "c-gate", False, "tester")
    ai._external_gate(conn, "c-gate")             # 解除后放行

    # ollama 档:provider=ollama 直绕闸门(无需 mock,不到调用就说明过闸)
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.delenv("AI_API_KEY")
    monkeypatch.setattr(ai, "_call_api", lambda *a, **k: {
        "content": "ok", "tool_calls": None, "model": "qwen3:8b",
        "usage": {"total_tokens": 1}})
    out = ai.chat([{"role": "user", "content": "hi"}])
    assert out["content"] == "ok"


def test_case_ai_policy_endpoint(ai_cfg):
    """PATCH 开关端点:设置/读取/404 + 案件列表带标志位。"""
    with _client() as c:
        cid = c.post("/cases", json={"name": "闸"}).json()["id"]
        r = c.patch(f"/cases/{cid}/ai-policy",
                    json={"ai_external_blocked": True})
        assert r.status_code == 200 and r.json()["ai_external_blocked"] is True
        items = c.get("/cases").json()["items"]
        row = next(i for i in items if i["id"] == cid)
        assert row["ai_external_blocked"] == 1
        assert c.patch("/cases/nope/ai-policy",
                       json={"ai_external_blocked": True}).status_code == 404
