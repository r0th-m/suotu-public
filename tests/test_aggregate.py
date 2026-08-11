"""M5 即席聚合(query.aggregate + GET /cases/{id}/aggregate)测试。

覆盖:
- 字段白名单闸:非 mini-ECS 归一字段 → API 400;检索层自身 _field_expr
  安全闸(非法字段名 → ValueError);
- 分布正确:GROUP BY 计数/buckets 降序/NULL 不进桶(如实);
- field_filters / 时间窗 / 源过滤:与 search 同语义;
- ★与 search 同源一致(单一检索层契约):同一过滤条件下 total_events
  == search.total;
- 防跨案串味:他案 source_id → 空结果。
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import query
from backend.app.main import app

from conftest import NGINX_TEXT, register_confirm_parse


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def parsed_case(client):
    """建案 → 上传 nginx(3 行)→ 确认 → 解析,返回 (case_id, source_id)。"""
    case_id = client.post("/cases", json={"name": "聚合测试案"}).json()["id"]
    up = client.post(f"/cases/{case_id}/sources:upload",
                     files={"file": ("access.log", NGINX_TEXT.encode(),
                                     "text/plain")},
                     data={"system": "web-01"})
    sid = up.json()["sources"][0]["source_id"]
    client.post(f"/sources/{sid}/confirm",
                json={"format_id": "nginx_combined",
                      "tz_declared": "Asia/Shanghai", "log_type": "web"})
    r = client.post(f"/sources/{sid}/parse")
    assert r.status_code == 200 and r.json()["parsed"] == 3
    return case_id, sid


# ---------------------------------------------------------------- 白名单闸

def test_field_whitelist_api(client, parsed_case):
    case_id, _ = parsed_case
    assert client.get(f"/cases/{case_id}/aggregate",
                      params={"field": "ua"}).status_code == 200
    r = client.get(f"/cases/{case_id}/aggregate",
                   params={"field": "raw"})          # raw 非归一字段
    assert r.status_code == 400 and "白名单" in r.json()["detail"]
    r = client.get(f"/cases/{case_id}/aggregate",
                   params={"field": "status;DROP"})  # 注入形状同闸
    assert r.status_code == 400


def test_field_safety_gate_module(parsed_case):
    """检索层纵深防御:绕过 API 直调 query,非法字段名 → ValueError。"""
    case_id, _ = parsed_case
    with pytest.raises(ValueError):
        query.aggregate(case_id, "ev il")


# ---------------------------------------------------------------- 分布正确

def test_distribution_correct(client, parsed_case):
    case_id, _ = parsed_case
    body = client.get(f"/cases/{case_id}/aggregate",
                      params={"field": "status"}).json()
    assert body["field"] == "status" and body["total_events"] == 3
    buckets = {b["value"]: b["count"] for b in body["buckets"]}
    assert buckets == {"200": 1, "302": 1, "404": 1}
    # ua 分布:三个不同 UA 各 1;referer 只有一行有(NULL 不进桶,如实)
    body = client.get(f"/cases/{case_id}/aggregate",
                      params={"field": "ua"}).json()
    assert body["total_events"] == 3 and len(body["buckets"]) == 3
    body = client.get(f"/cases/{case_id}/aggregate",
                      params={"field": "method"}).json()
    buckets = {b["value"]: b["count"] for b in body["buckets"]}
    assert buckets == {"GET": 2, "POST": 1}         # 降序:GET 在前
    assert body["buckets"][0]["value"] == "GET"


def test_field_filters_and_time_window(client, parsed_case):
    case_id, _ = parsed_case
    # field_filters 与 search 同语义(精确/contains)
    body = client.get(
        f"/cases/{case_id}/aggregate",
        params={"field": "ua", "field_filters": '{"status":"404"}'}).json()
    assert body["total_events"] == 1
    assert body["buckets"] == [
        {"value": "Mozilla/5.0 (scannerbot)", "count": 1}]
    # 时间窗:ts_utc 按声明时区(+0800)归一 = 05:55:36/05:56:01/05:57:22Z
    body = client.get(
        f"/cases/{case_id}/aggregate",
        params={"field": "path",
                "ts_from": "2000-10-10T05:56:00"}).json()
    assert body["total_events"] == 2
    assert {b["value"] for b in body["buckets"]} == {"/login", "/missing"}
    # 窗全在未来 → 空(如实,不报错)
    body = client.get(
        f"/cases/{case_id}/aggregate",
        params={"field": "path", "ts_from": "2030-01-01T00:00:00"}).json()
    assert body["total_events"] == 0 and body["buckets"] == []
    # 坏时间 → 400
    assert client.get(f"/cases/{case_id}/aggregate",
                      params={"field": "path",
                              "ts_from": "不是时间"}).status_code == 400


# ---------------------------------------------------------------- 作用域 / 同源一致

def test_source_scope_and_cross_case(client, parsed_case):
    case_id, sid = parsed_case
    body = client.get(f"/cases/{case_id}/aggregate",
                      params={"field": "status", "source_id": sid}).json()
    assert body["total_events"] == 3
    # 他案 source_id → 空结果(防跨案串味,不报错不猜)
    other = client.post("/cases", json={"name": "另一案"}).json()["id"]
    body = client.get(f"/cases/{other}/aggregate",
                      params={"field": "status", "source_id": sid}).json()
    assert body["total_events"] == 0 and body["buckets"] == []
    assert client.get("/cases/不存在/aggregate",
                      params={"field": "status"}).status_code == 404


def test_consistent_with_search(parsed_case):
    """★单一检索层契约:同一过滤条件下 aggregate.total_events == search.total。"""
    case_id, sid = parsed_case
    for filters in (None, {"status": "404"}, {"ua": {"contains": "curl"}}):
        agg = query.aggregate(case_id, "path", source_id=sid,
                              field_filters=filters)
        sea = query.search(case_id, source_id=sid, field_filters=filters)
        assert agg["total_events"] == sea["total"]
        # 桶计数之和 ≤ total(差额=path 为 NULL 的量,nginx 全有 path 故相等)
        assert sum(b["count"] for b in agg["buckets"]) == sea["total"]
