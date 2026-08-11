"""单一检索层契约(§4.6):模块直调 / 全量可达无盲区 / 降级路径 / 防串味闸。"""
from __future__ import annotations

import re

import pytest

from backend.app import duck, query

from conftest import IIS_TEXT, NGINX_TEXT, RAW_TEXT, register_confirm_parse


@pytest.fixture()
def web_case(conn, case_id):
    sid, _, _ = register_confirm_parse(conn, case_id, NGINX_TEXT, "nginx_combined")
    return case_id, sid


def _all_via_paging(case_id, page=2):
    """q=None 全量分页把案件内事件全捞出来(契约:任何事件可达)。"""
    seen, offset = [], 0
    while True:
        r = query.search(case_id, limit=page, offset=offset)
        seen.extend(r["items"])
        if len(seen) >= r["total"]:
            break
        offset += page
    return seen


def test_search_q_and_anchors(web_case):
    case_id, sid = web_case
    r = query.search(case_id, q="scannerbot")
    assert r["total"] == 1
    item = r["items"][0]
    # 锚点齐全:source_id + line_no + raw + norm + sha256
    assert item["source_id"] == sid and item["line_no"] == 3
    assert "scannerbot" in item["raw"]
    assert item["norm"]["status"] == 404
    assert re.fullmatch(r"[0-9a-f]{64}", item["sha256"])


def test_search_field_filters_and_source(web_case):
    case_id, sid = web_case
    r = query.search(case_id, field_filters={"status": "302"})
    assert r["total"] == 1 and r["items"][0]["norm"]["path"] == "/login"
    r = query.search(case_id, source_id=sid, field_filters={"method": "GET"})
    assert r["total"] == 2
    r = query.search(case_id, source_id="nonexistent-source")
    assert r["total"] == 0 and r["items"] == []


def test_search_time_window(web_case):
    """tz_declared=Asia/Shanghai:10/Oct/2000:13:55:36 +0800 → 05:55:36Z。"""
    case_id, sid = web_case
    r = query.search(case_id, ts_from="2000-10-10T05:56:00",
                     ts_to="2000-10-10T05:58:00")
    assert r["total"] == 2                             # 后两行落在窗内
    r = query.search(case_id, ts_from="2020-01-01T00:00:00")
    assert r["total"] == 0
    with pytest.raises(ValueError):
        query.search(case_id, ts_from="not-a-time")    # 非法参数如实抛


def test_no_fulltext_blind_spot(conn, case_id):
    """契约:任意已入库事件(含 raw_t0)必可被 search 检索到。

    - q=None 分页全量可达(两种检索模式下都成立);
    - q=行内 token 在 LIKE 降级模式下逐事件可达;
    - FTS 可得时同断言在 FTS 模式下再跑一遍。
    """
    sid_ng, _, _ = register_confirm_parse(conn, case_id, NGINX_TEXT, "nginx_combined")
    sid_raw, _, _ = register_confirm_parse(conn, case_id, RAW_TEXT, "raw",
                                           name="odd.log", log_type="unknown")

    all_events = _all_via_paging(case_id)
    assert len(all_events) == 6                        # 3 nginx + 3 raw_t0
    srcs = {e["source_id"] for e in all_events}
    assert srcs == {sid_ng, sid_raw}

    def assert_token_searchable():
        for e in all_events:
            tokens = re.findall(r"[A-Za-z0-9]{4,}", e["raw"])
            assert tokens, f"事件无可检索 token: {e['raw']!r}"
            r = query.search(case_id, q=tokens[0])
            assert any(i["id"] == e["id"] for i in r["items"]), \
                f"token {tokens[0]!r} 检索不到事件 {e['id']}"

    # LIKE 唯一全文路径(FTS 已实测否决,duck.py 头注):全事件可检索契约
    assert_token_searchable()
    r = query.search(case_id, q="oddsvc")
    assert r["total"] >= 1


def test_like_escaping(web_case):
    """q 里的 LIKE 通配符按字面量处理(转义,不变成模式)。"""
    case_id, _ = web_case
    assert query.search(case_id, q="%")["total"] == 0
    assert query.search(case_id, q="_")["total"] == 0


def test_stats(web_case):
    case_id, sid = web_case
    s = query.stats(case_id)
    assert sid in s["by_source"]
    entry = s["by_source"][sid]
    assert entry["events"] == 3
    assert entry["ts_min"] and entry["ts_max"]
    top_ips = {t["value"] for t in entry["top_src_ip"]}
    assert "93.184.216.34" in top_ips
    status = {t["value"]: t["count"] for t in entry["status_dist"]}
    assert status == {"200": 1, "302": 1, "404": 1}


def test_entity_cross_source_guard(conn, case_id):
    """防串味闸:cross_source 只允许 qualifier=global。

    93.184.216.34 是公网 IP(global,可跨源);192.168.1.10 是私网
    (host_scoped,跨源查询必须查不到)。
    """
    sid1, _, _ = register_confirm_parse(conn, case_id, NGINX_TEXT, "nginx_combined",
                                        name="a.log")
    sid2, _, _ = register_confirm_parse(conn, case_id, NGINX_TEXT, "nginx_combined",
                                        name="b.log")
    r = query.entity_lookup(case_id, "93.184.216.34", cross_source=True)
    assert {i["source_id"] for i in r["items"]} == {sid1, sid2}
    r = query.entity_lookup(case_id, "192.168.1.10", cross_source=True)
    assert r["items"] == []                            # host_scoped 不许跨源
    r = query.entity_lookup(case_id, "192.168.1.10")   # 案件内如实可查
    assert r["items"] and all(i["qualifier"] == "host_scoped" for i in r["items"])
    # 账户实体
    r = query.entity_lookup(case_id, "alice")
    assert r["items"] and r["items"][0]["entity_type"] == "account"


def test_read_window(web_case):
    case_id, sid = web_case
    w = query.read_window(sid, 2, 3)
    assert [l["line_no"] for l in w["lines"]] == [2, 3]
    assert w["lines"][0]["norm"]["method"] == "POST"
    assert "curl" in w["lines"][0]["raw"]


def test_field_filters_operators(web_case):
    """字段过滤两种算子:字符串=精确;{"contains": v}=子串(UA 场景);
    contains 的 LIKE 通配符按字面量转义。"""
    case_id, _ = web_case
    # 精确:UA 全等才命中(夹具含 Mozilla/5.0 (scannerbot))
    exact = query.search(case_id,
                         field_filters={"ua": "Mozilla/5.0 (scannerbot)"})
    assert exact["total"] == 1
    # 子串:UA 含 scanner 即命中
    part = query.search(case_id, field_filters={"ua": {"contains": "scanner"}})
    assert part["total"] == 1
    # 子串不命中
    miss = query.search(case_id, field_filters={"ua": {"contains": "nmap"}})
    assert miss["total"] == 0
    # contains 里的 % 是字面量不是通配符
    wc = query.search(case_id, field_filters={"ua": {"contains": "%"}})
    assert wc["total"] == 0
    # eq 显式形态与字符串形态同义
    eq = query.search(case_id, field_filters={"status": {"eq": "302"}})
    assert eq["total"] == query.search(case_id,
                                       field_filters={"status": "302"})["total"]
