"""M1 规则引擎 + 待审区测试(合成样本纪律,断言级焊死判断权)。

覆盖:
- 内置规则包全部可加载;schema 校验(坏规则/重复 id/未知字段/未知 severity);
- 合成攻击行(SQLi×2/XSS×2/穿越/命令执行/webshell/扫描 UA/敏感路径/TRACE)
  必命中对应规则,matched_field/matched_value 正确;
- 合成正常行零命中(误报门);
- run_rules 幂等(重跑 hits_new=0)、多源隔离;
- 判断权断言级:hits 初始恒 pending;accept 前 clues 为空;accept 后 clue
  锚点三件套 = hit 的源/行/哈希;reject 不产 clue;重复裁决 → 409;
- 单一检索层:scan_events 与 search(q=None) 数据源一致性。
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import query, rules
from backend.app.main import app

from conftest import register_confirm_parse

# ---- 合成攻击/正常样本(对通用攻击知识写,nginx combined 行式) ----
# 注意:nginx $request 三段式,目标内不能有空格,攻击载荷一律用编码形态。
_ATTACK = {
    "sqli-union-select":
        '93.184.216.34 - - [10/Oct/2000:13:55:36 +0300] "GET /search?q=1%27%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    "sqli-time-based":
        '93.184.216.34 - - [10/Oct/2000:13:55:37 +0300] "GET /item?id=1+AND+SLEEP(5) HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    "xss-script-handler":
        '93.184.216.34 - - [10/Oct/2000:13:55:38 +0300] "GET /c?x=<script>alert(1)</script> HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    "xss-javascript-protocol":
        '93.184.216.34 - - [10/Oct/2000:13:55:39 +0300] "GET /r?u=javascript:alert(document.cookie) HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    "path-traversal":
        '93.184.216.34 - - [10/Oct/2000:13:55:40 +0300] "GET /..%2f..%2fetc%2fpasswd HTTP/1.1" 404 10 "-" "Mozilla/5.0"',
    "cmd-exec-params":
        '93.184.216.34 - - [10/Oct/2000:13:55:41 +0300] "GET /app?cmd=cat%20/etc/passwd&x=system(id) HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    "webshell-filename":
        '93.184.216.34 - - [10/Oct/2000:13:55:42 +0300] "GET /upload/c99.php HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    "scanner-ua":
        '93.184.216.34 - - [10/Oct/2000:13:55:43 +0300] "GET / HTTP/1.1" 200 10 "-" "sqlmap/1.5.2#stable (https://sqlmap.org)"',
    "sensitive-path":
        '93.184.216.34 - - [10/Oct/2000:13:55:44 +0300] "GET /.git/config HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    "abnormal-method":
        '93.184.216.34 - - [10/Oct/2000:13:55:45 +0300] "TRACE / HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    "waf-checker-ua":
        '198.51.100.5 - - [10/Oct/2000:13:55:46 +0300] "GET / HTTP/1.1" 403 571 "-" "Mozilla/5.0 (Windows NT 6.1) QIANXIN CHECKER"',
}
_NORMAL = [
    '93.184.216.34 - - [10/Oct/2000:13:55:46 +0300] "GET /index.html HTTP/1.1" 200 1043 "http://example.com/" "Mozilla/5.0"',
    '192.168.1.10 - alice [10/Oct/2000:13:55:47 +0300] "POST /login?next=/admin HTTP/1.1" 302 680 "-" "curl/7.68.0"',
]
ATTACK_TEXT = "\n".join(_ATTACK.values()) + "\n" + "\n".join(_NORMAL) + "\n"

# 每条攻击行期望命中的 (规则 id, matched_field, matched_value 之一)
_EXPECT = {
    "sqli-union-select": ("sqli-union-select", "query", "union%20select"),
    "sqli-time-based": ("sqli-time-based", "query", "sleep("),
    "xss-script-handler": ("xss-script-handler", "query", "<script"),
    "xss-javascript-protocol": ("xss-javascript-protocol", "query", "javascript:"),
    "path-traversal": ("path-traversal", "raw", "..%2f"),
    "cmd-exec-params": ("cmd-exec-params", "query", "cmd="),
    "webshell-filename": ("webshell-filename", "path", "c99.php"),
    "scanner-ua": ("scanner-ua", "ua", "sqlmap"),
    "sensitive-path": ("sensitive-path", "path", "/.git/"),
    "abnormal-method": ("abnormal-method", "method", "trace"),
    "waf-checker-ua": ("waf-checker-ua", "ua", "qianxin checker"),
}


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def attack_case(conn, case_id):
    """合成攻击样本走真实 ingest 管线入库,返回 source_id。"""
    sid, _, report = register_confirm_parse(conn, case_id, ATTACK_TEXT,
                                            "nginx_combined")
    assert report["parsed"] == len(_ATTACK) + len(_NORMAL)
    return sid


# ==================== 规则包加载与 schema 校验 ====================

def test_builtin_rules_load():
    loaded = rules.list_rules()
    assert len(loaded) == 11
    ids = [r["id"] for r in loaded]
    assert len(ids) == len(set(ids))                     # id 唯一
    assert set(ids) == set(_EXPECT)                      # 与测试期望一一对应
    for r in loaded:
        assert r["severity"] in rules.SEVERITIES
        assert r["note"]                                 # 每条规则必带依据说明


def test_schema_rejects_bad_rules():
    base = {"id": "ok-rule", "title": "t", "severity": "high",
            "target": "web", "match": {"query": ["x"]}}
    # 未知 severity
    with pytest.raises(rules.RuleError):
        rules.validate_rule({**base, "severity": "critical"})
    # 未知 target
    with pytest.raises(rules.RuleError):
        rules.validate_rule({**base, "target": "host"})
    # 未知顶层字段
    with pytest.raises(rules.RuleError):
        rules.validate_rule({**base, "scope": "single_source"})
    # 未知 match 字段
    with pytest.raises(rules.RuleError):
        rules.validate_rule({**base, "match": {"body": ["x"]}})
    # 缺必填 / 空 match / 非列表子串 / 非法 id
    for bad in ({k: v for k, v in base.items() if k != "title"},
                {**base, "match": {}},
                {**base, "match": {"query": "x"}},
                {**base, "id": "Bad_ID"}):
        with pytest.raises(rules.RuleError):
            rules.validate_rule(bad)


def test_duplicate_rule_id_rejected(tmp_path):
    good = {"id": "dup-rule", "title": "a", "severity": "low",
            "target": "web", "match": {"raw": ["x"]}}
    import yaml
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(good), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(
        yaml.safe_dump({**good, "title": "b"}), encoding="utf-8")
    with pytest.raises(rules.RuleError, match="重复"):
        rules.load_rules(tmp_path)


# ==================== 扫描:攻击必命中 / 正常零命中 / 幂等 / 多源隔离 ====================

def test_attack_lines_hit_expected_rules(conn, case_id, attack_case):
    report = rules.run_rules(conn, case_id)
    assert report["scanned"] == len(_ATTACK) + len(_NORMAL)
    hits = rules.list_hits(conn, case_id, limit=1000)["items"]
    # 每条期望规则至少一条命中,且 matched_field/value 正确
    for key, (rid, field, value) in _EXPECT.items():
        line_no = list(_ATTACK).index(key) + 1
        got = [h for h in hits if h["rule_id"] == rid and h["line_no"] == line_no]
        assert got, f"{rid} 未命中第 {line_no} 行"
        assert got[0]["matched_field"] == field
        assert got[0]["matched_value"] == value
        assert got[0]["status"] == "pending"             # 恒 pending 起步
        assert got[0]["severity"] in rules.SEVERITIES
        assert len(got[0]["snippet"]) <= 300
    assert report["hits_new"] == report["hits_total"] == len(hits)


def test_normal_lines_zero_hits(conn, case_id, attack_case):
    rules.run_rules(conn, case_id)
    hits = rules.list_hits(conn, case_id, limit=1000)["items"]
    normal_linenos = set(range(len(_ATTACK) + 1,
                               len(_ATTACK) + len(_NORMAL) + 1))
    assert not [h for h in hits if h["line_no"] in normal_linenos]  # 误报门


def test_run_rules_idempotent(conn, case_id, attack_case):
    first = rules.run_rules(conn, case_id)
    second = rules.run_rules(conn, case_id)
    assert first["hits_new"] > 0
    assert second["hits_new"] == 0                       # 重跑幂等
    assert second["hits_total"] == first["hits_total"]


def test_multi_source_isolation(conn, case_id, attack_case):
    from conftest import NGINX_TEXT
    sid2, _, _ = register_confirm_parse(conn, case_id, NGINX_TEXT,
                                        "nginx_combined", name="other.log")
    report = rules.run_rules(conn, case_id, source_id=sid2)
    assert report["scanned"] == 3                        # 只扫指定源
    hits = rules.list_hits(conn, case_id, limit=1000)["items"]
    assert all(h["source_id"] == sid2 for h in hits)
    assert not [h for h in hits if h["source_id"] == attack_case]


# ==================== 判断权断言级:Hit → 人审 → Clue ====================

def _pending_hit(conn, case_id, rule_id="sqli-union-select"):
    rules.run_rules(conn, case_id)
    hits = rules.list_hits(conn, case_id, status="pending", limit=1000)["items"]
    return next(h for h in hits if h["rule_id"] == rule_id)


def test_accept_writes_clue_with_anchors(conn, case_id, attack_case):
    # accept 前:线索库为空(机器产物永不自动入库)
    assert rules.list_clues(conn, case_id)["total"] == 0
    hit = _pending_hit(conn, case_id)
    src = conn.execute("SELECT sha256 FROM log_sources WHERE id = ?",
                       (hit["source_id"],)).fetchone()
    res = rules.accept_hit(conn, hit["id"], note="确认是注入尝试")
    clue = res["clue"]
    # 锚点三件套 = hit 的源/行/哈希
    assert clue["anchor_source_id"] == hit["source_id"]
    assert clue["anchor_line_no"] == hit["line_no"]
    assert clue["anchor_sha256"] == src["sha256"]
    assert clue["title"] == "SQL 注入 UNION SELECT 特征"   # title 自动=规则 title
    assert hit["matched_value"] in clue["body"] and "注入" in clue["body"]
    assert clue["created_by"] == "system"   # M4:模块直调(无会话)恒 system
    # hit 状态流转 + 线索数=1
    assert rules.list_hits(conn, case_id, status="accepted")["total"] == 1
    assert rules.list_clues(conn, case_id)["total"] == 1
    # 审计留痕
    row = conn.execute(
        "SELECT action, actor FROM audit_log WHERE action = 'hit_accept'"
    ).fetchone()
    assert row is not None and row["actor"] == "system"


def test_reject_writes_no_clue(conn, case_id, attack_case):
    hit = _pending_hit(conn, case_id)
    res = rules.reject_hit(conn, hit["id"], note="误报:站内搜索")
    assert res["status"] == "rejected"
    assert rules.list_clues(conn, case_id)["total"] == 0   # reject 不产 clue
    row = conn.execute(
        "SELECT detail_json FROM audit_log WHERE action = 'hit_reject'"
    ).fetchone()
    assert row is not None and "误报" in row["detail_json"]


def test_double_review_conflict(conn, case_id, attack_case):
    hit = _pending_hit(conn, case_id)
    rules.accept_hit(conn, hit["id"])
    with pytest.raises(rules.RuleError) as e1:
        rules.accept_hit(conn, hit["id"])
    with pytest.raises(rules.RuleError) as e2:
        rules.reject_hit(conn, hit["id"])
    assert e1.value.status == e2.value.status == 409
    # rejected 之后也不能再 accept
    hit2 = next(h for h in rules.list_hits(
        conn, case_id, status="pending", limit=1000)["items"]
        if h["rule_id"] == "scanner-ua")
    rules.reject_hit(conn, hit2["id"])
    with pytest.raises(rules.RuleError) as e3:
        rules.accept_hit(conn, hit2["id"])
    assert e3.value.status == 409


# ==================== 单一检索层:scan_events 与 search 一致性 ====================

def test_scan_events_consistent_with_search(conn, case_id, attack_case):
    scanned = [(e["source_id"], e["line_no"]) for e in query.scan_events(case_id)]
    searched, offset = [], 0
    while True:  # search(q=None) 全量分页取尽
        page = query.search(case_id, limit=5, offset=offset)
        searched += [(i["source_id"], i["line_no"]) for i in page["items"]]
        offset += len(page["items"])
        if len(searched) >= page["total"]:
            break
    assert scanned == searched                             # 同序同集合
    assert list(query.scan_events(case_id, source_id="no-such")) == []


# ==================== API 契约 ====================

def test_rules_api(client, case_id):
    r = client.get(f"/cases/{case_id}/rules")
    assert r.status_code == 200 and len(r.json()["items"]) == 11
    assert client.get("/cases/nope/rules").status_code == 404


def test_full_review_flow_api(client):
    cid = client.post("/cases", json={"name": "M1 流程"}).json()["id"]
    up = client.post(f"/cases/{cid}/sources:upload",
                     files={"file": ("access.log", ATTACK_TEXT.encode(),
                                     "text/plain")})
    sid = up.json()["sources"][0]["source_id"]
    client.post(f"/sources/{sid}/confirm",
                json={"format_id": "nginx_combined",
                      "tz_declared": "Asia/Shanghai", "log_type": "web"})
    assert client.post(f"/sources/{sid}/parse").status_code == 200

    run = client.post(f"/cases/{cid}/rules:run", json={})
    assert run.status_code == 200
    assert run.json()["hits_new"] > 0

    hits = client.get(f"/cases/{cid}/hits", params={"status": "pending"})
    assert hits.status_code == 200 and hits.json()["total"] > 0
    # 非法过滤值如实 400
    assert client.get(f"/cases/{cid}/hits",
                      params={"status": "weird"}).status_code == 400

    assert client.get(f"/cases/{cid}/clues").json()["total"] == 0
    hit_id = hits.json()["items"][0]["id"]
    acc = client.post(f"/hits/{hit_id}:accept", json={"note": "看过,属实"})
    assert acc.status_code == 200
    assert acc.json()["clue"]["anchor_line_no"] == \
        hits.json()["items"][0]["line_no"]
    assert client.get(f"/cases/{cid}/clues").json()["total"] == 1
    # 重复裁决 → 409;不存在 → 404
    assert client.post(f"/hits/{hit_id}:reject", json={}).status_code == 409
    assert client.post("/hits/nope:accept", json={}).status_code == 404

    rej = client.post(f"/hits/{hits.json()['items'][1]['id']}:reject",
                      json={"note": "误报"})
    assert rej.status_code == 200
    assert client.get(f"/cases/{cid}/clues").json()["total"] == 1


def test_hits_search_q(conn, case_id):
    """待审区关键词搜索(2026-08-05 用户反馈刚需):rule_id/命中值/摘要/行号
    四域子串 OR;LIKE 通配符按字面量转义。"""
    from conftest import register_confirm_parse
    sid, _, _ = register_confirm_parse(conn, case_id, ATTACK_TEXT, "nginx_combined")
    rules.run_rules(conn, case_id, source_id=sid)
    # 按 rule_id 搜
    r = rules.list_hits(conn, case_id, q="scanner-ua")
    assert r["total"] >= 1 and all(h["rule_id"] == "scanner-ua"
                                   for h in r["items"])
    # 按命中值搜
    r2 = rules.list_hits(conn, case_id, q="sqlmap")
    assert r2["total"] >= 1
    # 按摘要内容搜(IP 出现在 snippet 里)
    r3 = rules.list_hits(conn, case_id, q="93.184.216.34")
    assert r3["total"] >= 1
    # 无命中词 → 0;通配符 % 按字面量(不当模式)
    assert rules.list_hits(conn, case_id, q="不存在的词")["total"] == 0
    # % 按字面量:只匹配摘要里真含 % 的(URL 编码),不等于全量
    total_all = rules.list_hits(conn, case_id)["total"]
    pct = rules.list_hits(conn, case_id, q="%")["total"]
    assert 0 < pct < total_all
    # 与 severity 过滤叠加
    r4 = rules.list_hits(conn, case_id, q="sqlmap", severity="high")
    assert all(h["severity"] == "high" for h in r4["items"])
