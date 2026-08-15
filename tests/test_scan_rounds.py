"""规则子集扫描 + 扫描轮次(round)测试(合成纪律,契约焊死)。

覆盖:
- 子集扫描:rule_ids 只跑选中规则(正);未知 id → 422(负);
  选中 draft 自定义规则 → 422(负);不传 = 全量(旧行为不回归);
  跨源内置条目在统一 id 空间内可选;
- 轮次:每案件递增(1,2,3…)、同案独立计数(两案各自从 1 起);
  scan_runs 台账带 rule_ids/actor/摘要;报告带 round_no;
- hits 带 round_no;重跑幂等(老命中保留首轮 round_no 不覆盖);
- 待审区 round 过滤:轮次号 / history(老数据 NULL);非法值 400;
- 老数据兼容:hits 直接落 NULL round_no 的行 → 过滤 history 可见、
  响应 round_no 为 None(展示「历史」)。
"""
from __future__ import annotations

import io

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.app import ingest, rules, rulescustom
from backend.app.main import app

ATTACK = ('93.184.216.34 - - [10/Oct/2000:13:55:36 +0000] "GET'
          ' /search?q=1%27%20UNION%20SELECT%20password%20FROM%20users'
          ' HTTP/1.1" 200 10 "-" "Mozilla/5.0"')
TRACE = ('93.184.216.34 - - [10/Oct/2000:13:55:37 +0000]'
         ' "TRACE / HTTP/1.1" 200 10 "-" "Mozilla/5.0"')
TEXT = ATTACK + "\n" + TRACE + "\n"

CUSTOM_SIG = yaml.safe_dump(
    {"id": "round-watch", "title": "轮次测试自定义", "severity": "low",
     "target": "any", "match": {"ua": ["mozilla"]}}, allow_unicode=True)


def _parse(conn, case_id, text=TEXT, name="access.log"):
    reg = ingest.register_upload(conn, case_id, name, io.BytesIO(text.encode()))
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, "nginx_combined",
                          tz_declared="UTC", log_type="web")
    assert ingest.parse_source(conn, sid)["status"] == "parsed"
    return sid


def _hits(conn, case_id, rule_id=None):
    items = rules.list_hits(conn, case_id, limit=1000)["items"]
    return [h for h in items if rule_id is None or h["rule_id"] == rule_id]


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


# ==================== 需求①:子集扫描 ====================

def test_subset_run_only_selected(conn, case_id):
    _parse(conn, case_id)
    report = rules.run_rules(conn, case_id, rule_ids=["sqli-union-select"])
    assert report["round_no"] == 1
    assert report["hits_new"] == 1
    # 只跑选中规则:per_rule 只列选中项,TRACE 行不命中 abnormal-method
    assert [p["rule_id"] for p in report["per_rule"]] == ["sqli-union-select"]
    assert report["signature"]["hits_new"] == 1
    assert report["stats"]["hits_new"] == 0
    assert report["cross_source"]["hits_new"] == 0      # 未选中跨源内置
    assert _hits(conn, case_id, "abnormal-method") == []
    assert len(_hits(conn, case_id, "sqli-union-select")) == 1


def test_subset_run_stat_and_cross_source(conn, case_id):
    # 统计规则 + 跨源内置条目都在统一 id 空间可选(如实跑,零命中也如实)
    _parse(conn, case_id)
    report = rules.run_rules(
        conn, case_id, rule_ids=["ip-rate-spike", "cross-source-entity"])
    assert report["hits_new"] == 0
    assert [p["rule_id"] for p in report["stats"]["per_rule"]] == ["ip-rate-spike"]


def test_full_run_unchanged_when_no_rule_ids(conn, case_id):
    _parse(conn, case_id)
    report = rules.run_rules(conn, case_id)              # 不传 = 全量旧行为
    assert report["hits_new"] == 2                       # 两条攻击行都命中
    assert {h["rule_id"] for h in _hits(conn, case_id)} == \
        {"sqli-union-select", "abnormal-method"}


def test_subset_unknown_id_422(client, conn, case_id):
    _parse(conn, case_id)
    r = client.post(f"/cases/{case_id}/rules:run",
                    json={"rule_ids": ["sqli-union-select", "no-such-rule"]})
    assert r.status_code == 422
    assert "未知规则 id" in r.json()["detail"]
    assert _hits(conn, case_id) == []                    # 非法选择一条不跑


def test_subset_draft_custom_422(client, conn, case_id):
    _parse(conn, case_id)
    assert client.post("/rules/custom",
                       json={"yaml_text": CUSTOM_SIG}).status_code == 201
    r = client.post(f"/cases/{case_id}/rules:run",
                    json={"rule_ids": ["round-watch"]})
    assert r.status_code == 422                          # draft 不可跑
    assert "未启用" in r.json()["detail"]
    assert _hits(conn, case_id) == []
    # 转 enable 后可选可跑
    client.put("/rules/custom/round-watch", json={"status": "enable"})
    r = client.post(f"/cases/{case_id}/rules:run",
                    json={"rule_ids": ["round-watch"]})
    assert r.status_code == 200
    assert r.json()["hits_new"] == 2                     # 两行 ua 都含 mozilla


# ==================== 需求②:扫描轮次 ====================

def test_round_increments_and_hits_carry_round(conn, case_id):
    _parse(conn, case_id)
    r1 = rules.run_rules(conn, case_id, rule_ids=["sqli-union-select"])
    r2 = rules.run_rules(conn, case_id, rule_ids=["abnormal-method"])
    assert (r1["round_no"], r2["round_no"]) == (1, 2)    # 递增
    h1 = _hits(conn, case_id, "sqli-union-select")[0]
    h2 = _hits(conn, case_id, "abnormal-method")[0]
    assert h1["round_no"] == 1 and h2["round_no"] == 2   # 命中带轮次
    # 台账:两轮,rule_ids 如实记
    rounds = rules.list_scan_rounds(conn, case_id)
    assert rounds["total"] == 2
    assert rounds["items"][0]["rule_ids"] == ["sqli-union-select"]
    assert rounds["items"][0]["summary"]["hits_new"] == 1
    assert rounds["items"][1]["round_no"] == 2
    # 重跑幂等:老命中保留首轮 round_no,不覆盖
    r3 = rules.run_rules(conn, case_id)
    assert r3["round_no"] == 3 and r3["hits_new"] == 0
    h1 = _hits(conn, case_id, "sqli-union-select")[0]
    assert h1["round_no"] == 1


def test_round_per_case_independent(conn, case_id):
    _parse(conn, case_id)
    with conn:
        conn.execute("INSERT INTO cases (id, name, created_at)"
                     " VALUES ('case-test-2','第二案','2026-08-15T00:00:00+00:00')")
    _parse(conn, "case-test-2", name="b.log")
    rules.run_rules(conn, case_id)
    rules.run_rules(conn, case_id)
    r = rules.run_rules(conn, "case-test-2")
    assert r["round_no"] == 1                            # 同案独立计数
    assert rules.list_scan_rounds(conn, "case-test-2")["total"] == 1


def test_hits_round_filter(client, conn, case_id):
    _parse(conn, case_id)
    rules.run_rules(conn, case_id, rule_ids=["sqli-union-select"])
    rules.run_rules(conn, case_id, rule_ids=["abnormal-method"])
    # 按轮次过滤
    r = client.get(f"/cases/{case_id}/hits", params={"round": "2"})
    assert r.status_code == 200
    items = r.json()["items"]
    assert {h["rule_id"] for h in items} == {"abnormal-method"}
    assert all(h["round_no"] == 2 for h in items)
    # 老数据(round_no NULL)模拟:直落一行,过滤 history 可见
    with conn:
        conn.execute(
            "INSERT INTO hits (id, case_id, source_id, line_no, rule_id,"
            " severity, matched_field, matched_value, snippet, status,"
            " created_at) VALUES ('legacy-1', ?, ?, 1, 'old-rule', 'low',"
            " 'ua', 'x', 'old', 'pending', '2026-08-01T00:00:00+00:00')",
            (case_id, items[0]["source_id"]))
    r = client.get(f"/cases/{case_id}/hits", params={"round": "history"})
    legacy = [h for h in r.json()["items"] if h["id"] == "legacy-1"]
    assert len(legacy) == 1 and legacy[0]["round_no"] is None   # 展示「历史」
    # 全部过滤时老数据与新数据同列
    r = client.get(f"/cases/{case_id}/hits")
    assert {h["round_no"] for h in r.json()["items"]} == {None, 1, 2}
    # 非法轮次值 → 400 如实
    r = client.get(f"/cases/{case_id}/hits", params={"round": "abc"})
    assert r.status_code == 400


def test_scan_rounds_api(client, conn, case_id):
    _parse(conn, case_id)
    assert client.get(f"/cases/{case_id}/scan-rounds").json()["total"] == 0
    client.post(f"/cases/{case_id}/rules:run", json={})
    body = client.get(f"/cases/{case_id}/scan-rounds").json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["round_no"] == 1
    assert item["rule_ids"] is None                      # 全量
    assert item["summary"]["hits_new"] == 2
    assert item["actor"] == "tester"
