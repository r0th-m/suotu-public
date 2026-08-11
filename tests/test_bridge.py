"""M4 主机取证平台实体互查(§9 实体桥 v2):mock urllib 主机取证平台响应 → results 组装;
不可达/未配置凭据/认证失败 → available=false 如实(不报错页)。

测试纪律:.env 永不进测试——_read_env_file monkeypatch 为空,
凭据全部走环境变量 monkeypatch(仅测试用,非真实凭据)。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest
from fastapi.testclient import TestClient

from backend.app import ai, bridge
from backend.app.main import app


@pytest.fixture(autouse=True)
def bridge_env(monkeypatch):
    """互查测试环境:禁读 .env + 清 TREE_COURT_*,用例按需 setenv。"""
    monkeypatch.setattr(ai, "_read_env_file", lambda: {})
    for key in ("TREE_COURT_URL", "TREE_COURT_USER", "TREE_COURT_PASS"):
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


class _FakeResp:
    """urllib 响应假身:read + headers.get + 上下文管理器。"""

    def __init__(self, payload: dict, set_cookie: str | None = None):
        self._body = json.dumps(payload).encode("utf-8")
        self._headers = {"Set-Cookie": set_cookie} if set_cookie else {}

    def read(self):
        return self._body

    @property
    def headers(self):
        return self._headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_treecourt(req: urllib.request.Request, **kwargs):
    """主机取证平台假服务:login 发 Cookie;一案两主机,1.2.3.4 在 host-1 出现 2 次。"""
    url = req.full_url
    if url.endswith("/auth/login"):
        return _FakeResp({"username": "tc"},
                         set_cookie="winsc_session=fake; HttpOnly")
    if url.endswith("/cases"):
        return _FakeResp({"cases": [{"id": "c1", "name": "主机取证平台案一"}]})
    if url.endswith("/cases/c1/hosts"):
        return _FakeResp({"hosts": [{"id": "h1", "hostname": "web-01"},
                                    {"id": "h2", "hostname": "db-01"}]})
    if "/entities/search" in url:
        return _FakeResp({"items": [
            {"raw_value": "1.2.3.4", "canonical_key": "ip:1.2.3.4",
             "entity_type": "ip", "qualifier": "global", "host_id": "h1"},
            {"raw_value": "1.2.3.4", "canonical_key": "ip:1.2.3.4",
             "entity_type": "ip", "qualifier": "global", "host_id": "h1"},
            {"raw_value": "1.2.3.4", "canonical_key": "ip:1.2.3.4",
             "entity_type": "ip", "qualifier": "global", "host_id": "h2"},
        ]})
    raise AssertionError(f"未预期的请求: {url}")


def _configured(monkeypatch):
    monkeypatch.setenv("TREE_COURT_URL", "http://treecourt.test:8000")
    monkeypatch.setenv("TREE_COURT_USER", "tc")
    monkeypatch.setenv("TREE_COURT_PASS", "tc-pass")   # 仅测试用,非真实凭据


def test_results_assembled(bridge_env, monkeypatch):
    """登录→逐案件/主机实体检索 → 按 (案件,主机,值) 聚合计数。"""
    _configured(bridge_env)
    monkeypatch.setattr(urllib.request, "urlopen", _fake_treecourt)
    out = bridge.query_entities("1.2.3.4")
    assert out["available"] is True
    assert out["source_platform"] == "treecourt"       # 前端联动预留
    by_host = {r["host"]: r for r in out["results"]}
    assert by_host["web-01"]["count"] == 2             # 同主机同值聚合
    assert by_host["db-01"]["count"] == 1
    assert by_host["web-01"]["case"] == "主机取证平台案一"
    assert by_host["web-01"]["canonical_key"] == "ip:1.2.3.4"


def test_api_endpoint(bridge_env, monkeypatch, data_dir):
    _configured(bridge_env)
    monkeypatch.setattr(urllib.request, "urlopen", _fake_treecourt)
    with TestClient(app) as client:
        r = client.get("/bridge/treecourt/entities",
                       params={"value": "1.2.3.4"})
    assert r.status_code == 200 and r.json()["available"] is True


def test_unreachable_is_available_false(bridge_env, monkeypatch):
    """主机取证平台不可达 → available=false + reason 如实,不报错页不装查无结果。"""
    _configured(bridge_env)

    def _down(req, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _down)
    out = bridge.query_entities("1.2.3.4")
    assert out["available"] is False and out["results"] == []
    assert "不可达" in out["reason"]


def test_unconfigured_is_available_false(bridge_env):
    """未配置凭据 → available=false + reason 指明缺什么(不读 .env)。"""
    out = bridge.query_entities("1.2.3.4")
    assert out["available"] is False
    assert "TREE_COURT_USER" in out["reason"]


def test_auth_failure_is_available_false(bridge_env, monkeypatch):
    """主机取证平台拒凭据(401)→ available=false + reason 如实分类为认证失败。"""
    _configured(bridge_env)

    def _deny(req, **kwargs):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized",
                                     None, None)

    monkeypatch.setattr(urllib.request, "urlopen", _deny)
    out = bridge.query_entities("1.2.3.4")
    assert out["available"] is False and "认证失败" in out["reason"]
