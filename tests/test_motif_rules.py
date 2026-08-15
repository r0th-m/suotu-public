"""链式 motif(sequence)/ 周期信标(periodicity)算子 + 命中预算帽测试
(合成正/负样本纪律,对 spec 写不对值写)。

覆盖:
- sequence:正样本(401×5 后窗口内 200 同键 → 命中,锚点=末步行,证据带
  step1 计数与时间窗);负样本(401 潮无 200 → 不中;200 在窗口外 → 不中;
  min_first_step_count 不够 → 不中);ts_utc 全 NULL → 报告 skipped 如实标注;
- periodicity:正样本(等间隔 8 次跨 10.5 分钟 → 命中,锚点=组内首行,
  证据带间隔均值/cv/次数);负样本(随机间隔 → 不中;跨度不足 → 不中);
  ts_utc 全 NULL → skipped;
- schema 闸:steps 步数/结构/未知字段、坏阈值一律 RuleError;
- 预算帽:签名/统计规则 max_hits 超限 → 命中数==帽值且报告 per_rule 带
  truncated 溢出条数。
"""
from __future__ import annotations

import io

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.app import ingest, rules, rulescustom
from backend.app.main import app


def _line(ip: str, path: str, status: int, minute: int, second: int = 0,
          hour: int = 13, method: str = "POST") -> str:
    ts = f"10/Oct/2000:{hour:02d}:{minute:02d}:{second:02d} +0000"
    return (f'{ip} - - [{ts}] "{method} {path} HTTP/1.1"'
            f' {status} 100 "-" "Mozilla/5.0"')


def _text(lines: list[str]) -> str:
    return "\n".join(lines) + "\n"


def _parse(conn, case_id, text, name="access.log", tz="UTC"):
    reg = ingest.register_upload(conn, case_id, name, io.BytesIO(text.encode()))
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, "nginx_combined",
                          tz_declared=tz, log_type="web")
    report = ingest.parse_source(conn, sid)
    assert report["status"] == "parsed"
    return sid


def _hits(conn, case_id, rule_id):
    return [h for h in rules.list_hits(conn, case_id, limit=1000)["items"]
            if h["rule_id"] == rule_id]


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


# ==================== 算子⑤ sequence(链式 motif) ====================

def _bruteforce_lines(fail_count: int = 5, success_minute: int = 1) -> list[str]:
    """同 IP 同 path:fail_count 个 401(10s 一个)后 success_minute 接 200。"""
    lines = [_line("93.184.216.34", "/login", 401, 0, s)
             for s in range(0, fail_count * 10, 10)]
    lines.append(_line("93.184.216.34", "/login", 200, success_minute))
    return lines


def test_sequence_hit(conn, case_id):
    # 401×5(0:00~0:40)后 1:00 接 200:末次失败后 20s,在 300s 窗内 → 命中
    _parse(conn, case_id, _text(_bruteforce_lines()))
    report = rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "auth-bruteforce-success")
    assert len(hits) == 1
    h = hits[0]
    assert h["status"] == "pending"
    assert "链式命中≠成功入侵" in h["snippet"]        # 诚实文案焊死
    d = h["detail_json"]
    assert d["kind"] == "sequence"
    assert d["group"] == {"src_ip": "93.184.216.34", "path": "/login"}
    assert d["first_step_count"] == 5
    assert d["window_seconds"] == 300
    assert d["rep_line_no"] == h["line_no"] == 6     # 锚点=末步(200)行
    assert d["chain_line_nos"][-1] == 6
    assert d["first_step_last_ts"] and d["final_ts"]
    assert any(r["rule_id"] == "auth-bruteforce-success"
               for r in report["stats"]["per_rule"])


def test_sequence_no_success_no_hit(conn, case_id):
    # 401 潮但窗口内无 200 → 不命中(链不完整)
    lines = [_line("93.184.216.34", "/login", 401, 0, s) for s in range(0, 50, 10)]
    lines.append(_line("93.184.216.34", "/login", 404, 1))   # 非 200 不成链
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "auth-bruteforce-success") == []


def test_sequence_success_outside_window(conn, case_id):
    # 401×5(末次 0:40),200 在 7:00:超 300s 窗 → 不命中
    _parse(conn, case_id, _text(_bruteforce_lines(success_minute=7)))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "auth-bruteforce-success") == []


def test_sequence_below_min_first_step_count(conn, case_id):
    # 401×4 + 200:第一步次数 < min_first_step_count 5 → 不命中(防偶然闸)
    _parse(conn, case_id, _text(_bruteforce_lines(fail_count=4)))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "auth-bruteforce-success") == []


def test_sequence_different_key_no_hit(conn, case_id):
    # 401 在 /login、200 在 /other:跨键不成链 → 不命中
    lines = [_line("93.184.216.34", "/login", 401, 0, s) for s in range(0, 50, 10)]
    lines.append(_line("93.184.216.34", "/other", 200, 1))
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "auth-bruteforce-success") == []


def test_sequence_null_ts_source_skipped(conn, case_id):
    # tz 未声明 → ts_utc 全 NULL:时序算子整源跳过,报告 skipped 如实注明
    sid = _parse(conn, case_id, _text(_bruteforce_lines()), tz=None)
    report = rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "auth-bruteforce-success") == []
    skipped = report["stats"]["skipped"]
    assert any(s["rule_id"] == "auth-bruteforce-success" and s["source_id"] == sid
               and "ts_utc" in s["reason"] for s in skipped)


# ==================== 算子⑥ periodicity(周期信标) ====================

def _beacon_lines() -> list[str]:
    """8 次等间隔 90s(0:00~10:30,跨度 630s),cv=0。"""
    return [_line("93.184.216.34", "/api/ping", 200, m, s, method="GET")
            for m, s in ((0, 0), (1, 30), (3, 0), (4, 30), (6, 0), (7, 30),
                         (9, 0), (10, 30))]


def test_periodicity_hit(conn, case_id):
    _parse(conn, case_id, _text(_beacon_lines()))
    rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "periodic-beacon")
    assert len(hits) == 1
    h = hits[0]
    assert h["status"] == "pending"
    assert "周期≠恶意" in h["snippet"]                # 诚实文案焊死
    d = h["detail_json"]
    assert d["kind"] == "periodicity"
    assert d["group"] == {"src_ip": "93.184.216.34", "path": "/api/ping"}
    assert d["events"] == 8
    assert d["interval_mean"] == pytest.approx(90.0)
    assert d["cv"] == pytest.approx(0.0)
    assert d["span_seconds"] == pytest.approx(630.0)
    assert d["rep_line_no"] == h["line_no"] == 1     # 锚点=组内首行


def test_periodicity_jitter_no_hit(conn, case_id):
    # 间隔 10/10/10/270/300/300/300s:cv≈0.66 > 0.2 → 不命中(不够规律)
    offsets = [0, 10, 20, 30, 300, 600, 900, 1200]   # 秒
    lines = [_line("93.184.216.34", "/api/ping", 200, (13 * 3600 + o) // 60 % 60,
                   o % 60, hour=13 + o // 3600, method="GET") for o in offsets]
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "periodic-beacon") == []


def test_periodicity_short_span_no_hit(conn, case_id):
    # 8 次 10s 间隔:跨度 70s < min_span_seconds 300 → 不命中(防短簇闸)
    lines = [_line("93.184.216.34", "/api/ping", 200, 0, s, method="GET")
             for s in range(0, 80, 10)]
    _parse(conn, case_id, _text(lines))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "periodic-beacon") == []


def test_periodicity_few_events_no_hit(conn, case_id):
    # 5 次等间隔:事件数 < min_events 6 → 不命中(小样本噪声闸)
    _parse(conn, case_id, _text(_beacon_lines()[:5]))
    rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "periodic-beacon") == []


def test_periodicity_null_ts_source_skipped(conn, case_id):
    sid = _parse(conn, case_id, _text(_beacon_lines()), tz=None)
    report = rules.run_rules(conn, case_id)
    assert _hits(conn, case_id, "periodic-beacon") == []
    skipped = report["stats"]["skipped"]
    assert any(s["rule_id"] == "periodic-beacon" and s["source_id"] == sid
               and "ts_utc" in s["reason"] for s in skipped)


# ==================== schema 闸(新算子参数校验,加载即校验) ====================

def test_sequence_schema_rejects_bad_rules():
    base = {"id": "ok-seq", "title": "t", "operator": "sequence",
            "severity": "high", "key_fields": ["src_ip", "path"],
            "steps": [{"field": "status", "in": ["401", "403"]},
                      {"field": "status", "in": ["200"]}],
            "window_seconds": 300}
    ok = rules.validate_stat_rule(base)
    assert ok["min_first_step_count"] == 3            # 默认值
    assert ok["steps"][0]["in"] == ["401", "403"]
    # steps 步数越界(1 步/4 步)
    with pytest.raises(rules.RuleError, match="2~3"):
        rules.validate_stat_rule({**base, "steps": base["steps"][:1]})
    with pytest.raises(rules.RuleError, match="2~3"):
        rules.validate_stat_rule({**base, "steps": base["steps"] * 2})
    # step 结构错(多键/缺 in)
    with pytest.raises(rules.RuleError, match="field"):
        rules.validate_stat_rule(
            {**base, "steps": [{"field": "status", "in": ["401"], "x": 1},
                               {"field": "status", "in": ["200"]}]})
    # step.field 未知归一字段
    with pytest.raises(rules.RuleError, match="归一字段"):
        rules.validate_stat_rule(
            {**base, "steps": [{"field": "http_hdr", "in": ["401"]},
                               {"field": "status", "in": ["200"]}]})
    # step.in 空列表 / window_seconds 缺省(必填)/坏值
    with pytest.raises(rules.RuleError, match="非空协议常量列表"):
        rules.validate_stat_rule(
            {**base, "steps": [{"field": "status", "in": []},
                               {"field": "status", "in": ["200"]}]})
    with pytest.raises(rules.RuleError, match="缺必填参数"):
        rules.validate_stat_rule(
            {k: v for k, v in base.items() if k != "window_seconds"})
    with pytest.raises(rules.RuleError, match="window_seconds"):
        rules.validate_stat_rule({**base, "window_seconds": 0})


def test_periodicity_schema_rejects_bad_rules():
    base = {"id": "ok-per", "title": "t", "operator": "periodicity",
            "severity": "medium", "key_fields": ["src_ip"]}
    ok = rules.validate_stat_rule(base)
    assert (ok["min_events"], ok["max_cv"], ok["min_span_seconds"]) == \
        (6, 0.2, 300)                                 # 默认值
    with pytest.raises(rules.RuleError, match="min_events"):
        rules.validate_stat_rule({**base, "min_events": 2})   # 间隔至少 2 段
    with pytest.raises(rules.RuleError, match="max_cv"):
        rules.validate_stat_rule({**base, "max_cv": 0})
    with pytest.raises(rules.RuleError, match="min_span_seconds"):
        rules.validate_stat_rule({**base, "min_span_seconds": -1})


def test_max_hits_schema():
    # max_hits 可选、须正整数;签名/统计同一闸
    with pytest.raises(rules.RuleError, match="max_hits"):
        rules.validate_stat_rule(
            {"id": "ok-per", "title": "t", "operator": "periodicity",
             "severity": "low", "key_fields": ["src_ip"], "max_hits": 0})
    with pytest.raises(rules.RuleError, match="max_hits"):
        rules.validate_rule(
            {"id": "ok-sig", "title": "t", "severity": "low", "target": "any",
             "match": {"ua": ["x"]}, "max_hits": -1})
    ok = rules.validate_rule(
        {"id": "ok-sig", "title": "t", "severity": "low", "target": "any",
         "match": {"ua": ["x"]}, "max_hits": 10})
    assert ok["max_hits"] == 10


# ==================== 需求④:每规则每案命中预算帽 ====================

def test_signature_max_hits_capped(conn, case_id):
    # 自定义签名规则 max_hits=2,5 行全命中 → 入库 2 条,truncated=3
    lines = [_line("93.184.216.34", f"/p{i}", 200, i, method="GET")
             for i in range(5)]
    _parse(conn, case_id, _text(lines))
    doc = {"id": "cap-sig", "title": "帽测", "severity": "low", "target": "any",
           "match": {"method": ["get"]}, "max_hits": 2}
    rulescustom.create_rule(conn, yaml.safe_dump(doc, allow_unicode=True))
    rulescustom.update_rule(conn, "cap-sig", status="enable")
    report = rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "cap-sig")
    assert len(hits) == 2                              # 命中数==帽值
    row = next(r for r in report["signature"]["per_rule"]
               if r["rule_id"] == "cap-sig")
    assert row["hits"] == 2 and row["truncated"] == 3  # 溢出如实标注


def test_stat_max_hits_capped(conn, case_id):
    # 自定义 sequence 规则 max_hits=1,两个键组各自成链 → 入库 1 条,
    # truncated=1
    lines = []
    for ip, minute in (("93.184.216.34", 0), ("198.51.100.5", 20)):
        lines += [_line(ip, "/login", 401, minute, s)
                  for s in range(0, 30, 10)]
        lines.append(_line(ip, "/login", 200, minute + 1))
    _parse(conn, case_id, _text(lines))
    doc = {"id": "cap-stat", "title": "帽测", "operator": "sequence",
           "severity": "low", "key_fields": ["src_ip", "path"],
           "steps": [{"field": "status", "in": ["401"]},
                     {"field": "status", "in": ["200"]}],
           "window_seconds": 300, "min_first_step_count": 3, "max_hits": 1}
    rulescustom.create_rule(conn, yaml.safe_dump(doc, allow_unicode=True))
    rulescustom.update_rule(conn, "cap-stat", status="enable")
    report = rules.run_rules(conn, case_id)
    hits = _hits(conn, case_id, "cap-stat")
    assert len(hits) == 1
    row = next(r for r in report["stats"]["per_rule"]
               if r["rule_id"] == "cap-stat")
    assert row["hits"] == 1 and row["truncated"] == 1
