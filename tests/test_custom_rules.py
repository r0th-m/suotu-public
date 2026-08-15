"""自定义规则治理链契约测试(存储 data/rules_custom/,照 formatdesc 纪律)。

覆盖:
- 建 draft → 扫描不含;转 enable → 扫描含(判断权归人:人点头才进扫描);
- 清单 API(/cases/{id}/rules 的 custom 段)如实标状态;
- 坏 YAML/坏参数 → 422;撞内置 id → 409(内置永只读);删内置 → 404;
- 规则 id 不可变(内容更新换 id → 422);删除自定义 → 200 且清单消失;
- 统计类自定义规则(enable 后进统计段扫描)端到端。
"""
from __future__ import annotations

import io

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.app import ingest, rules
from backend.app.main import app

SIG_YAML = yaml.safe_dump(
    {"id": "my-ua-watch", "title": "自定义 UA 关注", "severity": "low",
     "target": "any", "match": {"ua": ["watch-me"]},
     "note": "测试自定义签名规则"}, allow_unicode=True)

STAT_YAML = yaml.safe_dump(
    {"id": "my-seq-watch", "title": "自定义链式", "operator": "sequence",
     "severity": "low", "key_fields": ["src_ip", "path"],
     "steps": [{"field": "status", "in": ["401"]},
               {"field": "status", "in": ["200"]}],
     "window_seconds": 300, "min_first_step_count": 3}, allow_unicode=True)


def _line(ip: str, path: str, status: int, minute: int, second: int = 0,
          ua: str = "Mozilla/5.0") -> str:
    ts = f"10/Oct/2000:13:{minute:02d}:{second:02d} +0000"
    return (f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} 100 "-" "{ua}"')


def _parse(conn, case_id, text, name="access.log"):
    reg = ingest.register_upload(conn, case_id, name, io.BytesIO(text.encode()))
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, "nginx_combined",
                          tz_declared="UTC", log_type="web")
    assert ingest.parse_source(conn, sid)["status"] == "parsed"
    return sid


def _hits(conn, case_id, rule_id):
    return [h for h in rules.list_hits(conn, case_id, limit=1000)["items"]
            if h["rule_id"] == rule_id]


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


def test_create_draft_not_scanned_then_enable_scanned(client, conn, case_id):
    _parse(conn, case_id, _line("93.184.216.34", "/x", 200, 0, ua="watch-me/1.0")
           + "\n")
    # 建 draft:创建恒 draft,扫描不含
    r = client.post("/rules/custom", json={"yaml_text": SIG_YAML})
    assert r.status_code == 201
    assert r.json()["status"] == "draft"
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "my-ua-watch") == []
    # 清单如实标状态
    body = client.get(f"/cases/{case_id}/rules").json()
    custom = {c["id"]: c for c in body["custom"]}
    assert custom["my-ua-watch"]["status"] == "draft"
    assert custom["my-ua-watch"]["kind"] == "signature"
    # 转 enable → 扫描含
    r = client.put("/rules/custom/my-ua-watch", json={"status": "enable"})
    assert r.status_code == 200 and r.json()["status"] == "enable"
    rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "my-ua-watch")
    assert len(hits) == 1 and hits[0]["status"] == "pending"


def test_create_forces_draft_even_if_yaml_says_enable(client, data_dir):
    r = client.post("/rules/custom", json={
        "yaml_text": SIG_YAML + "status: enable\n"})
    assert r.status_code == 201
    assert r.json()["status"] == "draft"              # 永不自动启用
    assert r.json()["note"]


def test_bad_yaml_422(client):
    for bad in ("id: [unclosed",                       # YAML 解析失败
                "foo: bar",                            # 无法判定类型
                yaml.safe_dump({"id": "Bad_ID", "title": "t", "severity": "low",
                                "target": "any", "match": {"ua": ["x"]}}),
                yaml.safe_dump({"id": "ok-bad", "title": "t",
                                "operator": "ml_magic", "severity": "low"}),
                yaml.safe_dump({"id": "ok-bad2", "title": "t",
                                "operator": "periodicity", "severity": "low",
                                "key_fields": ["http_hdr"]})):
        r = client.post("/rules/custom", json={"yaml_text": bad})
        assert r.status_code == 422, bad[:40]


def test_builtin_id_conflict_rejected(client):
    doc = {"id": "sqli-union-select", "title": "抢内置", "severity": "low",
           "target": "any", "match": {"ua": ["x"]}}
    r = client.post("/rules/custom",
                    json={"yaml_text": yaml.safe_dump(doc)})
    assert r.status_code == 409                        # 内置永只读,不可覆盖
    doc2 = {"id": "ip-rate-spike", "title": "抢内置统计",
            "operator": "periodicity", "severity": "low",
            "key_fields": ["src_ip"]}
    r = client.post("/rules/custom",
                    json={"yaml_text": yaml.safe_dump(doc2)})
    assert r.status_code == 409


def test_duplicate_custom_id_rejected(client):
    assert client.post("/rules/custom",
                       json={"yaml_text": SIG_YAML}).status_code == 201
    r = client.post("/rules/custom", json={"yaml_text": SIG_YAML})
    assert r.status_code == 409                        # 撞已有自定义 id


def test_delete_builtin_404_and_custom_ok(client, conn, case_id):
    r = client.delete("/rules/custom/sqli-union-select")
    assert r.status_code == 404                        # 内置只读,删不到
    client.post("/rules/custom", json={"yaml_text": SIG_YAML})
    r = client.delete("/rules/custom/my-ua-watch")
    assert r.status_code == 200 and r.json()["deleted"] is True
    assert client.get("/rules/custom/my-ua-watch").status_code == 404
    body = client.get(f"/cases/{case_id}/rules").json()
    assert not any(c["id"] == "my-ua-watch" for c in body["custom"])


def test_update_content_and_id_immutable(client):
    client.post("/rules/custom", json={"yaml_text": SIG_YAML})
    # 内容更新(改 title):重过 schema 闸,状态保持 draft
    doc = {"id": "my-ua-watch", "title": "改名后", "severity": "medium",
           "target": "web", "match": {"ua": ["watch-me"]}}
    r = client.put("/rules/custom/my-ua-watch",
                   json={"yaml_text": yaml.safe_dump(doc)})
    assert r.status_code == 200 and r.json()["status"] == "draft"
    got = client.get("/rules/custom/my-ua-watch").json()
    assert got["title"] == "改名后" and got["severity"] == "medium"
    # 规则 id 不可变
    doc["id"] = "renamed-id"
    r = client.put("/rules/custom/my-ua-watch",
                   json={"yaml_text": yaml.safe_dump(doc)})
    assert r.status_code == 422
    # 坏 status 值
    r = client.put("/rules/custom/my-ua-watch", json={"status": "live"})
    assert r.status_code == 422


def test_custom_stat_rule_scanned_when_enabled(client, conn, case_id):
    # 统计类自定义:3×401 后 200 同键(min_first_step_count 3)→ enable 后命中
    lines = [_line("93.184.216.34", "/login", 401, 0, s) for s in (0, 10, 20)]
    lines.append(_line("93.184.216.34", "/login", 200, 0, 30))
    _parse(conn, case_id, "\n".join(lines) + "\n")
    assert client.post("/rules/custom",
                       json={"yaml_text": STAT_YAML}).status_code == 201
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "my-seq-watch") == []   # draft 不进扫描
    client.put("/rules/custom/my-seq-watch", json={"status": "enable"})
    rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "my-seq-watch")
    assert len(hits) == 1
    assert hits[0]["detail_json"]["kind"] == "sequence"


def test_custom_rules_isolated_per_data_dir(client, conn, case_id):
    """自定义规则随 SUOTU_DATA_DIR(测试夹具每用例独立目录)→ 默认空清单。"""
    body = client.get(f"/cases/{case_id}/rules").json()
    assert body["custom"] == []
