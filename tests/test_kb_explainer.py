"""M3 KB 解释器测试(确定性,断言级):命中/未覆盖不硬解释/坏 YAML 加载即暴露。"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import kb_explainer
from backend.app.main import app


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------- 命中/未覆盖

def test_path_covered():
    for value in ("/wp-login.php", "/ADMIN/panel", "/.git/config",
                  "/phpMyAdmin/index.php"):
        res = kb_explainer.explain("path", value)
        assert res["covered"] is True and res["text"], value


def test_path_not_covered_no_hard_explain():
    res = kb_explainer.explain("path", "/some/obscure/endpoint-xyz")
    assert res["covered"] is False
    assert "text" not in res or res.get("text") is None      # 不硬解释


def test_ua_covered_and_not():
    assert kb_explainer.explain("ua", "sqlmap/1.5.2#stable")["covered"] is True
    assert kb_explainer.explain("ua", "curl/7.68.0")["covered"] is True
    assert kb_explainer.explain(
        "ua", "Mozilla/5.0 (Windows NT 10.0) Chrome/120")["covered"] is True
    assert kb_explainer.explain("ua", "my-bespoke-agent/0.1")["covered"] is False


def test_status_covered_and_not():
    for code in ("200", "301", "302", "400", "401", "403", "404",
                 "500", "502", "503"):
        assert kb_explainer.explain("status", code)["covered"] is True, code
    assert kb_explainer.explain("status", "418")["covered"] is False
    assert kb_explainer.explain("status", "")["covered"] is False


def test_bad_kind_rejected():
    with pytest.raises(kb_explainer.KBError):
        kb_explainer.explain("cookie", "x")


# ---------------------------------------------------------------- 加载即校验

def test_builtin_kb_loads():
    kb = kb_explainer.load_explain_kb()
    assert kb["paths"] and kb["uas"] and kb["statuses"]


def test_bad_yaml_exposed_on_load(tmp_path):
    bad = tmp_path / "bad_syntax.yaml"
    bad.write_text("paths: [unclosed\n  - {match", encoding="utf-8")
    with pytest.raises(kb_explainer.KBError):
        kb_explainer.load_explain_kb(bad)
    bad2 = tmp_path / "bad_struct.yaml"
    bad2.write_text("id: x\ntitle: t\nstatuses:\n  '99': 两位数字键不合法\n",
                    encoding="utf-8")
    with pytest.raises(kb_explainer.KBError) as ei:
        kb_explainer.load_explain_kb(bad2)
    assert "三位数字" in str(ei.value)
    bad3 = tmp_path / "empty.yaml"
    bad3.write_text("id: x\ntitle: t\n", encoding="utf-8")
    with pytest.raises(kb_explainer.KBError):
        kb_explainer.load_explain_kb(bad3)


# ---------------------------------------------------------------- API

def test_kb_api(client):
    res = client.get("/kb/explain", params={"kind": "status", "value": "404"})
    assert res.status_code == 200
    body = res.json()
    assert body["covered"] is True and body["text"]
    res = client.get("/kb/explain", params={"kind": "path",
                                            "value": "/no-such-thing-zz"})
    assert res.json()["covered"] is False
    res = client.get("/kb/explain", params={"kind": "bogus", "value": "x"})
    assert res.status_code == 400
