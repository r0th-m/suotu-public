"""M2 统计规则(键值比对算子族)+ 跨源联动 + 互证端点测试(合成纪律)。

覆盖:
- 统计规则加载治理:内置包可加载;未知算子/未知字段/缺参数/坏阈值/
  未知归一字段/重复 id 一律 RuleError;排除 KB 损坏加载即暴露;
- 三算子各:正样本命中 + 参数边界(min_group_events/min_keys/
  max_value_freq/min_bucket_count 以下不命中)+ 阈值边界(diverge_ratio/
  zscore 不够不命中);
- 排除 KB:爬虫/库默认 UA 前缀不命中;
- rate_spike:ts_utc 全 NULL 的源如实跳过并在报告 skipped 段注明;
- 跨源联动:global IP 双源出 hit;私网 IP 双源不出(断言级,防张冠李戴);
- 互证端点:ok/none/no_siblings/no_ts 四态 + 窗口边界;
- hits detail_json 完整;run_rules 幂等(统计命中重扫 hits_new=0);
- run 报告按 signature/stats/cross_source 分段;规则清单 API 并入统计规则。
"""
from __future__ import annotations

import io

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.app import ingest, rules
from backend.app.main import app

from conftest import register_confirm_parse

# ---- 合成样本构造(对 nginx combined spec 写) ----


def _line(ip: str, method: str, path: str, status: int, nbytes: int,
          ua: str, minute: int, second: int = 0, hour: int = 13) -> str:
    ts = f"10/Oct/2000:{hour:02d}:{minute:02d}:{second:02d} +0000"
    return (f'{ip} - - [{ts}] "{method} {path} HTTP/1.1"'
            f' {status} {nbytes} "-" "{ua}"')


def _text(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


def _parse(conn, case_id, text, name="access.log", system=None, tz="UTC"):
    """三段式一把梭,可带 system/tz(互证与时间未知用例用)。"""
    reg = ingest.register_upload(conn, case_id, name,
                                 io.BytesIO(text.encode()), system=system)
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, "nginx_combined",
                          tz_declared=tz, log_type="web")
    report = ingest.parse_source(conn, sid)
    assert report["status"] == "parsed"
    return sid


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


# ---- 算子① 同键异值分化:同 path+IP+UA,GET 100B / POST 1000B(×10) ----

DIVERGENCE_LINES = [
    _line("93.184.216.34", m, "/api/item", 200, b, "Mozilla/5.0", i, s)
    for i in range(6)
    for m, b, s in (("GET", 100, 0), ("POST", 1000, 30))
]


def _hits(conn, case_id, rule_id):
    return [h for h in rules.list_hits(conn, case_id, limit=1000)["items"]
            if h["rule_id"] == rule_id]


# ==================== 加载治理(schema 校验/重复 id/KB 损坏即暴露) ====================

def test_builtin_stat_rules_load():
    loaded = rules.load_stat_rules()
    assert len(loaded) == 6
    assert {r["operator"] for r in loaded} == rules.STAT_OPERATORS
    ids = [r["id"] for r in loaded]
    assert len(ids) == len(set(ids))
    for r in loaded:
        assert r["note"]                              # 每条必带依据说明
        assert r["severity"] in rules.SEVERITIES
    # 对外视图无内部派生键
    for r in rules.list_stat_rules():
        assert not any(k.startswith("_") for k in r)


def test_stat_schema_rejects_bad_rules():
    base = {"id": "ok-stat", "title": "t", "operator": "rate_spike",
            "severity": "medium", "key_fields": ["src_ip"],
            "bucket_seconds": 60, "zscore": 4.0, "min_bucket_count": 30}
    # 未知算子(新算子不许偷偷进)
    with pytest.raises(rules.RuleError, match="未知算子"):
        rules.validate_stat_rule({**base, "operator": "ml_magic"})
    # 未知顶层字段
    with pytest.raises(rules.RuleError, match="未知字段"):
        rules.validate_stat_rule({**base, "threshold": 3})
    # 缺算子必填参数
    with pytest.raises(rules.RuleError, match="缺必填参数"):
        rules.validate_stat_rule(
            {k: v for k, v in base.items() if k != "zscore"})
    # 未知归一字段(键/分化/值字段必须落在 mini-ECS 白名单)
    with pytest.raises(rules.RuleError, match="未知归一字段"):
        rules.validate_stat_rule({**base, "key_fields": ["http_x_header"]})
    # 坏阈值:zscore 须 > 0、min_keys 须 ≥ 2、metric 白名单
    with pytest.raises(rules.RuleError):
        rules.validate_stat_rule({**base, "zscore": 0})
    cluster = {"id": "ok-cluster", "title": "t",
               "operator": "cross_key_same_value", "severity": "low",
               "value_field": "ua", "key_fields": ["src_ip"],
               "min_keys": 2, "max_value_freq": 50}
    with pytest.raises(rules.RuleError):
        rules.validate_stat_rule({**cluster, "min_keys": 1})
    divergence = {"id": "ok-div", "title": "t",
                  "operator": "same_key_divergence", "severity": "low",
                  "key_fields": ["path"], "diverge_field": "method",
                  "metric": "bytes", "min_group_events": 10,
                  "diverge_ratio": 3.0}
    with pytest.raises(rules.RuleError, match="metric"):
        rules.validate_stat_rule({**divergence, "metric": "latency"})
    with pytest.raises(rules.RuleError):
        rules.validate_stat_rule({**divergence, "diverge_ratio": 1.0})


def test_duplicate_stat_rule_id_rejected(tmp_path):
    good = {"id": "dup-stat", "title": "a", "operator": "rate_spike",
            "severity": "low", "key_fields": ["src_ip"],
            "bucket_seconds": 60, "zscore": 4.0, "min_bucket_count": 30}
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(good), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(
        yaml.safe_dump({**good, "title": "b"}), encoding="utf-8")
    with pytest.raises(rules.RuleError, match="重复"):
        rules.load_stat_rules(tmp_path)


def test_kb_load_and_corrupt(tmp_path):
    kb = rules.load_kb("common_uas")                  # 内置 KB 完好
    assert "curl/" in kb["tokens"] and "googlebot" in kb["tokens"]
    # 缺文件 → 加载即暴露
    with pytest.raises(rules.RuleError, match="不存在"):
        rules.load_kb("no_such_kb", kb_dir=tmp_path)
    # 坏结构(prefixes 缺失/非列表)→ 加载即暴露
    (tmp_path / "bad.yaml").write_text("id: bad\nprefixes: not-a-list\n",
                                       encoding="utf-8")
    with pytest.raises(rules.RuleError, match="tokens"):
        rules.load_kb("bad", kb_dir=tmp_path)
    # 统计规则引用坏 KB → load_stat_rules 即报错(加载即校验同一纪律)
    (tmp_path / "common_uas.yaml").write_text("prefixes: 42\n",
                                              encoding="utf-8")
    with pytest.raises(rules.RuleError):
        rules.load_stat_rules(kb_dir=tmp_path)


# ==================== 算子① same_key_divergence ====================

def test_divergence_hit(conn, case_id):
    _parse(conn, case_id, _text(DIVERGENCE_LINES))
    report = rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "method-bytes-divergence")
    assert len(hits) == 1
    h = hits[0]
    assert h["status"] == "pending"
    assert "分化≠异常" in h["snippet"]                # 诚实文案焊死
    d = h["detail_json"]
    assert d["kind"] == "divergence"
    assert d["group"] == {"path": "/api/item",
                          "src_ip": "93.184.216.34", "ua": "Mozilla/5.0"}
    assert d["ratio"] == pytest.approx(10.0)
    assert {b["value"] for b in d["buckets"]} == {"GET", "POST"}
    assert d["rep_line_no"] == h["line_no"]           # 代表行如实标注
    # 合成样本 12 事件等间隔 30s(完全规律)→ 内置 periodic-beacon 同样命中,
    # 统计段新增 = 分化 1 + 周期信标 1(如实分列,不藏)
    assert report["stats"]["hits_new"] == 2
    beacon = _hits(conn, case_id, "periodic-beacon")
    assert len(beacon) == 1 and beacon[0]["detail_json"]["cv"] == 0


def test_divergence_below_min_group_events(conn, case_id):
    # 4+4=8 事件 < min_group_events 10 → 不命中(小样本噪声闸)
    lines = DIVERGENCE_LINES[:8]
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "method-bytes-divergence") == []


def test_divergence_below_ratio(conn, case_id):
    # ×2.5 < diverge_ratio 3.0 → 不命中(阈值边界)
    lines = [_line("93.184.216.34", m, "/api/item", 200, b, "Mozilla/5.0", i, s)
             for i in range(6)
             for m, b, s in (("GET", 100, 0), ("POST", 250, 30))]
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "method-bytes-divergence") == []


# ==================== 算子② cross_key_same_value ====================

def test_cluster_hit(conn, case_id):
    lines = [
        _line("93.184.216.34", "GET", "/a", 200, 100, "NessusSOAP/0.1", 0),
        _line("8.8.8.8", "GET", "/b", 200, 100, "NessusSOAP/0.1", 1),
    ]
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "rare-ua-cross-ip")
    assert len(hits) == 1
    h = hits[0]
    assert "疑似同源聚簇(弱信号)" in h["snippet"]     # 概率标注,严禁定论
    d = h["detail_json"]
    assert d["kind"] == "cluster" and d["value"] == "NessusSOAP/0.1"
    assert sorted(d["keys"]) == ["8.8.8.8", "93.184.216.34"]
    assert d["total_freq"] == 2
    assert d["first_ts"] and d["last_ts"]


def test_cluster_below_min_keys(conn, case_id):
    # 稀有 UA 只出现在 1 个 IP → 不命中(键数闸)
    lines = [_line("93.184.216.34", "GET", f"/p{i}", 200, 100,
                   "NessusSOAP/0.1", i) for i in range(3)]
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "rare-ua-cross-ip") == []


def test_cluster_above_max_freq(conn, case_id):
    # 2 个 IP × 25 = 50 次,不 < max_value_freq 50 → 不命中(稀有度闸)
    lines = [_line(ip, "GET", f"/p{i}", 200, 100, "RareTool/9.9", i)
             for i in range(25)
             for ip in ("93.184.216.34", "8.8.8.8")]
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "rare-ua-cross-ip") == []


def test_cluster_kb_excluded(conn, case_id):
    # curl 跨 3 个 IP:命中排除 KB 前缀 → 不聚簇(已知库默认 UA)
    lines = [_line(ip, "GET", "/x", 200, 100, "curl/7.68.0", i)
             for i, ip in enumerate(("93.184.216.34", "8.8.8.8", "1.1.1.1"))]
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "rare-ua-cross-ip") == []


# ==================== 算子③ rate_spike ====================

def _spike_lines(spike_count: int, baseline_buckets: int) -> list[str]:
    """baseline_buckets 个基线桶(每桶 2 事件)+ 1 个突刺桶。"""
    lines = [_line("93.184.216.34", "GET", "/", 200, 100, "Mozilla/5.0", m, s)
             for m in range(baseline_buckets) for s in (0, 30)]
    lines += [_line("93.184.216.34", "GET", "/", 200, 100, "Mozilla/5.0",
                    baseline_buckets, s) for s in range(spike_count)]
    return lines


def test_rate_spike_hit(conn, case_id):
    # 30 基线桶×2 + 突刺桶 35:z≈5.48 ≥ 4 且 35 ≥ min_bucket_count 30
    _parse(conn, case_id, _text(_spike_lines(35, 30)))
    rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "ip-rate-spike")
    assert len(hits) == 1
    h = hits[0]
    assert "速率突刺≠攻击" in h["snippet"]            # 诚实文案焊死
    d = h["detail_json"]
    assert d["kind"] == "rate_spike"
    assert d["count"] == 35 and d["z"] >= 4.0
    assert d["group"] == {"src_ip": "93.184.216.34"}
    assert d["bucket_seconds"] == 60 and d["rep_line_no"] == h["line_no"]


def test_rate_spike_below_min_bucket_count(conn, case_id):
    # z≈5.48 过线但突刺桶 25 < 30 → 不命中(防小基数闸)
    _parse(conn, case_id, _text(_spike_lines(25, 30)))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "ip-rate-spike") == []


def test_rate_spike_below_zscore(conn, case_id):
    # 3 基线桶×2 + 突刺 30:z≈1.73 < 4 → 不命中(zscore 阈值边界)
    _parse(conn, case_id, _text(_spike_lines(30, 3)))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "ip-rate-spike") == []


def test_rate_spike_null_ts_source_skipped(conn, case_id):
    # tz 未声明 → ts_utc 全 NULL:时序算子如实跳过,报告 skipped 注明
    sid = _parse(conn, case_id, _text(_spike_lines(35, 30)), tz=None)
    report = rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "ip-rate-spike") == []
    skipped = report["stats"]["skipped"]
    assert any(s["rule_id"] == "ip-rate-spike" and s["source_id"] == sid
               and "ts_utc" in s["reason"] for s in skipped)


# ==================== 跨源联动(global 才跨源,私网断言级不跨) ====================

def test_cross_source_global_ip_hit(conn, case_id):
    text = _text([_line("8.8.8.8", "GET", "/", 200, 100, "Mozilla/5.0", 0)])
    sid_a = _parse(conn, case_id, text, name="a.log")
    sid_b = _parse(conn, case_id, text, name="b.log")
    report = rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "cross-source-entity")
    assert {h["source_id"] for h in hits} == {sid_a, sid_b}   # 每源一条
    for h in hits:
        assert h["severity"] == "high"
        d = h["detail_json"]
        assert d["kind"] == "cross_source" and d["value"] == "ip:8.8.8.8"
        assert len(d["sources"]) == 2
    assert report["cross_source"]["entities"] == ["ip:8.8.8.8"]


def test_cross_source_private_ip_never(conn, case_id):
    # 私网 IP 双源复现:host_scoped 永不跨源(防张冠李戴闸,断言级)
    text = _text([_line("192.168.1.10", "GET", "/", 200, 100,
                        "Mozilla/5.0", 0)])
    _parse(conn, case_id, text, name="a.log")
    _parse(conn, case_id, text, name="b.log")
    report = rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "cross-source-entity") == []
    assert report["cross_source"]["hits_new"] == 0


# ==================== 幂等 / 分段报告 / 清单 API ====================

def test_run_rules_idempotent_with_stats(conn, case_id):
    _parse(conn, case_id, _text(DIVERGENCE_LINES))
    first = rules.run_rules(conn, case_id)
    second = rules.run_rules(conn, case_id)
    assert first["hits_new"] > 0
    assert second["hits_new"] == 0                      # 统计命中重扫也幂等
    assert second["stats"]["hits_new"] == 0
    assert second["cross_source"]["hits_new"] == 0
    assert second["hits_total"] == first["hits_total"]


def test_run_report_segments(conn, case_id):
    _parse(conn, case_id, _text(DIVERGENCE_LINES))
    report = rules.run_rules(conn, case_id)
    assert report["signature"]["scanned"] == len(DIVERGENCE_LINES)
    assert {"signature", "stats", "cross_source"} <= set(report)
    stat_ids = {r["rule_id"] for r in report["stats"]["per_rule"]}
    assert stat_ids == {"method-bytes-divergence", "rare-ua-cross-ip",
                        "ip-rate-spike", "path-size-outlier",
                        "auth-bruteforce-success", "periodic-beacon"}


def test_rules_api_merged(client, case_id):
    r = client.get(f"/cases/{case_id}/rules")
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 11                     # M1 契约 + waf-checker-ua(2026-08-09)
    assert all(i["operator"] is None for i in body["items"])
    stats = {s["id"]: s for s in body["stats"]}
    assert {"method-bytes-divergence", "rare-ua-cross-ip",
            "ip-rate-spike", "cross-source-entity"} <= set(stats)
    assert stats["ip-rate-spike"]["operator"] == "rate_spike"
    assert stats["ip-rate-spike"]["bucket_seconds"] == 60
    assert stats["cross-source-entity"]["operator"] == "cross_source_entity"


# ==================== 互证端点(四态 + 窗口边界) ====================

_ATTACK = ('93.184.216.34 - - [10/Oct/2000:13:55:36 +0000] "GET'
           ' /search?q=1%27%20UNION%20SELECT%20password%20FROM%20users'
           ' HTTP/1.1" 200 10 "-" "Mozilla/5.0"')


def _signature_hit(conn, case_id, rule_id="sqli-union-select"):
    rules.run_rules(conn, case_id)
    return _hits(conn, case_id, rule_id)[0]


def test_corroborate_ok(client, conn, case_id):
    _parse(conn, case_id, _text([_ATTACK]), name="access.log",
           system="oa-web")
    sibling = _line("93.184.216.34", "GET", "/search?q=hello", 200, 500,
                    "Mozilla/5.0", 58)                  # +144s,同 path 同 IP
    sid_b = _parse(conn, case_id, _text([sibling]), name="error.log",
                   system="oa-web")
    hit = _signature_hit(conn, case_id)
    r = client.get(f"/hits/{hit['id']}/corroborate")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["items"] and body["items"][0]["source_id"] == sid_b
    assert len(body["items"]) <= 20                     # 限量
    assert body["siblings"][0]["id"] == sid_b


def test_corroborate_none_then_wider_window(client, conn, case_id):
    _parse(conn, case_id, _text([_ATTACK]), name="access.log",
           system="oa-web")
    sibling = _line("93.184.216.34", "GET", "/search?q=hello", 200, 500,
                    "Mozilla/5.0", 1, hour=14)          # +324s > 默认 300
    _parse(conn, case_id, _text([sibling]), name="error.log",
           system="oa-web")
    hit = _signature_hit(conn, case_id)
    r = client.get(f"/hits/{hit['id']}/corroborate")
    assert r.json()["status"] == "none"                 # 有兄弟源但窗内无
    r2 = client.get(f"/hits/{hit['id']}/corroborate",
                    params={"window_seconds": 600})
    assert r2.json()["status"] == "ok"                  # 窗口放宽即互证


def test_corroborate_no_siblings(client, conn, case_id):
    _parse(conn, case_id, _text([_ATTACK]), name="access.log",
           system="oa-web")
    _parse(conn, case_id, _text([_line(
        "93.184.216.34", "GET", "/search", 200, 10, "Mozilla/5.0", 56)]),
        name="other.log", system="另一系统")            # 不同 system 不算兄弟
    hit = _signature_hit(conn, case_id)
    r = client.get(f"/hits/{hit['id']}/corroborate")
    assert r.json()["status"] == "no_siblings"


def test_corroborate_no_ts(client, conn, case_id):
    # tz 未声明 → 锚点行 ts_utc NULL:时间未知不硬算,no_ts 如实
    _parse(conn, case_id, _text([_ATTACK]), name="access.log",
           system="oa-web", tz=None)
    hit = _signature_hit(conn, case_id)
    r = client.get(f"/hits/{hit['id']}/corroborate")
    body = r.json()
    assert body["status"] == "no_ts" and "时间未知" in body["note"]


def test_corroborate_hit_not_found(client):
    assert client.get("/hits/nope/corroborate").status_code == 404


def test_size_outlier_operator(conn, case_id):
    """算子④ size_outlier:同键组内字节离群逐条出,锚点=异常响应本身;
    带内组不出;小样本组不参与。"""
    lines = []
    # 组 A:/api/item GET 200,25 次 ~1000B,2 次离群(5000B 和 60B)
    for i in range(25):
        lines.append(_line("1.1.1.1", "GET", "/api/item", 200,
                           1000 + i, "Mozilla/5.0", i, hour=10))
    lines.append(_line("2.2.2.2", "GET", "/api/item", 200, 5000, "Mozilla/5.0", 30, hour=10))
    lines.append(_line("2.2.2.2", "GET", "/api/item", 200, 60, "Mozilla/5.0", 31, hour=10))
    # 组 B:全在带内(900~1100),不出
    for i in range(22):
        lines.append(_line("3.3.3.3", "GET", "/stable", 200,
                           900 + i * 8, "Mozilla/5.0", i, hour=11))
    # 组 C:小样本(5 次含离群),不参与
    for i in range(5):
        b = 5000 if i == 0 else 100
        lines.append(_line("4.4.4.4", "GET", "/small", 200, b, "Mozilla/5.0", i, hour=12))
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "path-size-outlier")
    vals = {h["detail_json"]["value"] for h in hits}
    assert 5000 in vals and 60 in vals              # 两个离群都抓到
    assert len(hits) == 2
    for h in hits:
        d = h["detail_json"]
        assert d["kind"] == "size_outlier"
        assert "尺寸离群≠实锤" in h["snippet"]
        assert d["line_no"] == h["line_no"]         # 锚点=该次异常响应本身
        assert d["group"] == {"path": "/api/item", "method": "GET", "status": "200"}
    # 组 B/C 不出命中
    assert not any(h["detail_json"]["group"].get("path") == "/stable" for h in hits)
    assert not any(h["detail_json"]["group"].get("path") == "/small" for h in hits)
