"""API 契约:healthz、案件/源端点、查看器,及★单一检索层契约——
query.search 模块直调与 /search API 结果一致(同一份数据,两个入口)。"""
from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient

from backend.app import query
from backend.app.main import app

from conftest import IIS_TEXT, NGINX_TEXT, make_zip


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def parsed_case(client):
    """建案 → 上传 nginx → 确认 → 解析,返回 (case_id, source_id)。"""
    case_id = client.post("/cases", json={"name": "API 测试案"}).json()["id"]
    up = client.post(f"/cases/{case_id}/sources:upload",
                     files={"file": ("access.log", NGINX_TEXT.encode(), "text/plain")},
                     data={"system": "web-01"})
    assert up.status_code == 200
    sid = up.json()["sources"][0]["source_id"]
    r = client.post(f"/sources/{sid}/confirm",
                    json={"format_id": "nginx_combined",
                          "tz_declared": "Asia/Shanghai", "log_type": "web"})
    assert r.status_code == 200
    r = client.post(f"/sources/{sid}/parse")
    assert r.status_code == 200 and r.json()["parsed"] == 3
    return case_id, sid


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["version"] == "v1.0.0"


def test_cases_crud(client):
    cid = client.post("/cases", json={"name": "案一"}).json()["id"]
    assert client.get("/cases").json()["items"][0]["id"] == cid
    detail = client.get(f"/cases/{cid}").json()
    assert detail["name"] == "案一" and detail["sources"] == []
    assert client.get("/cases/nope").status_code == 404


def test_upload_gives_fingerprint_suggestion(client):
    cid = client.post("/cases", json={"name": "x"}).json()["id"]
    up = client.post(f"/cases/{cid}/sources:upload",
                     files={"file": ("u_ex.log", IIS_TEXT.encode(), "text/plain")})
    src = up.json()["sources"][0]
    assert src["status"] == "registered"
    assert src["fingerprint"]["suggestions"][0]["format_id"] == "iis_w3c"
    # 只建议不确认:登记行 format_id 仍为空
    got = client.get(f"/sources/{src['source_id']}").json()
    assert got["format_id"] is None and got["status"] == "registered"


def test_source_view_and_parse_report(client, parsed_case):
    _, sid = parsed_case
    got = client.get(f"/sources/{sid}").json()
    assert got["status"] == "parsed" and got["line_count"] == 3
    assert got["parse_report"]["parsed"] == 3
    assert client.get("/sources/nope").status_code == 404


def test_parse_api_422_on_failed(client):
    cid = client.post("/cases", json={"name": "x"}).json()["id"]
    up = client.post(f"/cases/{cid}/sources:upload",
                     files={"file": ("alien.log", b"@@@###\n###@@@\n", "text/plain")})
    sid = up.json()["sources"][0]["source_id"]
    client.post(f"/sources/{sid}/confirm", json={"format_id": "nginx_combined"})
    r = client.post(f"/sources/{sid}/parse")
    assert r.status_code == 422                        # 失败如实 422,不装成功
    assert "0 行命中" in r.json()["detail"]


def test_zip_upload_api(client):
    cid = client.post("/cases", json={"name": "x"}).json()["id"]
    blob = make_zip({"a.log": NGINX_TEXT, "b.log": IIS_TEXT})
    up = client.post(f"/cases/{cid}/sources:upload",
                     files={"file": ("b.zip", blob, "application/zip")})
    assert up.json()["kind"] == "zip" and len(up.json()["sources"]) == 2


def test_lines_viewer_api(client, parsed_case):
    _, sid = parsed_case
    r = client.get(f"/sources/{sid}/lines", params={"offset": 1, "limit": 2})
    assert r.status_code == 200
    body = r.json()
    assert [l["line_no"] for l in body["lines"]] == [2, 3]
    assert body["total_lines"] == 3


def test_search_api_matches_module_direct(client, parsed_case):
    """★单一检索层契约:API 与模块直调同参同果(两个入口一份数据)。"""
    case_id, sid = parsed_case
    params = {"q": "scannerbot", "limit": 10, "offset": 0}
    api = client.get(f"/cases/{case_id}/search", params=params).json()
    direct = query.search(case_id, q="scannerbot", limit=10, offset=0)
    assert api["total"] == direct["total"] == 1
    assert [i["id"] for i in api["items"]] == [i["id"] for i in direct["items"]]

    # 字段过滤 + 时间窗同参同果
    params2 = {"field_filters": json.dumps({"status": "302"})}
    api2 = client.get(f"/cases/{case_id}/search", params=params2).json()
    direct2 = query.search(case_id, field_filters={"status": "302"})
    assert api2["total"] == direct2["total"] == 1
    assert api2["items"][0]["id"] == direct2["items"][0]["id"]


def test_search_api_bad_params(client, parsed_case):
    case_id, _ = parsed_case
    r = client.get(f"/cases/{case_id}/search",
                   params={"field_filters": "not-json"})
    assert r.status_code == 400
    r = client.get(f"/cases/{case_id}/search", params={"ts_from": "junk"})
    assert r.status_code == 400


def test_stats_and_entities_api(client, parsed_case):
    case_id, sid = parsed_case
    s = client.get(f"/cases/{case_id}/stats").json()
    assert s["by_source"][sid]["events"] == 3
    e = client.get(f"/cases/{case_id}/entities/lookup",
                   params={"value": "93.184.216.34", "cross_source": True}).json()
    assert e["items"] and e["items"][0]["qualifier"] == "global"
    e2 = client.get(f"/cases/{case_id}/entities/lookup",
                    params={"value": "192.168.1.10", "cross_source": True}).json()
    assert e2["items"] == []                           # 防串味闸在 API 面同样生效
