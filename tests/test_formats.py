"""解析器契约测试:三格式正样本 + 负样本 + T0 兜底(对 spec 写,零静默)。"""
from __future__ import annotations

import pytest

from backend.app import formats
from backend.app.formats import apache_common, iis_w3c, nginx_combined, raw_t0

from conftest import (APACHE_TEXT, IIS_LINES, IIS_TEXT, NGINX_LINES,
                      NGINX_TEXT, RAW_TEXT)


def _collect(mod, text):
    return list(mod.parse(text.splitlines()))


# ------------------------------------------------------------- nginx combined

def test_nginx_positive_fields():
    outcomes = _collect(nginx_combined, NGINX_TEXT)
    events = [o for o in outcomes if o.kind == "event"]
    assert len(events) == 3 and not any(o.kind == "bad" for o in outcomes)

    e0 = events[0]
    assert e0.line_no == 1 and e0.raw == NGINX_LINES[0]
    assert e0.ts_raw == "10/Oct/2000:13:55:36 +0300"
    assert e0.dt_local is not None and e0.dt_local.year == 2000
    n = e0.norm
    assert n["src_ip"] == "93.184.216.34"
    assert n["method"] == "GET" and n["path"] == "/index.html"
    assert "query" not in n
    assert n["status"] == 200 and n["bytes"] == 1043
    assert n["ua"] == "Mozilla/5.0" and n["referer"] == "http://example.com/"
    # 行内时区如实抽进 extras 留证,归一不猜用
    assert n["extras"]["time_offset"] == "+0300"

    e1 = events[1]
    assert e1.norm["user"] == "alice"               # remote_user 非 "-" 抽出
    assert e1.norm["path"] == "/login" and e1.norm["query"] == "next=/admin"
    assert "referer" not in e1.norm                  # "-" 如实缺省

    e2 = events[2]
    assert e2.norm["status"] == 404 and e2.norm["ua"].endswith("(scannerbot)")


def test_nginx_negative_truncated_line():
    """截断行 → 坏行计数,其余行不受影响(零静默但不株连)。"""
    text = NGINX_LINES[0] + "\n" + \
        '93.184.216.34 - - [10/Oct/2000:13:55:36 +0300] "GET /b HTTP/1.1" 200\n'
    outcomes = _collect(nginx_combined, text)
    kinds = [o.kind for o in outcomes]
    assert kinds == ["event", "bad"]
    assert outcomes[1].line_no == 2 and outcomes[1].reason


def test_nginx_negative_bad_time():
    """时间解析失败 → 坏行,ts_raw 原样留证。"""
    text = NGINX_LINES[0] + "\n" + \
        '93.184.216.34 - - [99/Foo/2000:99:99:99 +0300] "GET /x HTTP/1.1" 200 1 "-" "-"\n'
    outcomes = _collect(nginx_combined, text)
    assert [o.kind for o in outcomes] == ["event", "bad"]
    assert outcomes[1].ts_raw == "99/Foo/2000:99:99:99 +0300"
    assert "time" in (outcomes[1].reason or "")


# ------------------------------------------------------------- apache common

def test_apache_positive():
    outcomes = _collect(apache_common, APACHE_TEXT)
    events = [o for o in outcomes if o.kind == "event"]
    assert len(events) == 2 and not any(o.kind == "bad" for o in outcomes)
    n0 = events[0].norm
    assert n0["src_ip"] == "93.184.216.34" and n0["path"] == "/apache_pb.gif"
    assert n0["status"] == 200 and n0["bytes"] == 2326
    assert "ua" not in n0 and "referer" not in n0    # common 格式无这两段
    assert events[1].norm["user"] == "frank" and events[1].norm["status"] == 403


def test_apache_rejects_combined_lines():
    """combined 行(多 referer/ua 两段)不匹配 common 行式 → 坏行(对 spec 写)。"""
    outcomes = _collect(apache_common, NGINX_TEXT)
    assert all(o.kind == "bad" for o in outcomes)


# ------------------------------------------------------------------ IIS W3C

def test_iis_positive_header_driven():
    outcomes = _collect(iis_w3c, IIS_TEXT)
    skips = [o for o in outcomes if o.kind == "skip"]
    events = [o for o in outcomes if o.kind == "event"]
    assert len(skips) == 4                            # 4 行 # 指令,跳过计数
    assert len(events) == 2 and not any(o.kind == "bad" for o in outcomes)
    n = events[0].norm
    assert n["src_ip"] == "93.184.216.34"             # c-ip 映射
    assert n["method"] == "GET" and n["path"] == "/Default.aspx"
    assert n["status"] == 200 and n["bytes"] == 431
    assert n["ua"] == "Mozilla/5.0"
    # 映射不上的字段进 extras,不丢数据
    assert n["extras"]["s-ip"] == "192.168.10.5" and n["extras"]["time-taken"] == "15"
    assert events[0].ts_raw == "2026-07-20 00:00:02"
    assert events[1].norm["user"] == "bob" and events[1].norm["query"] == "ReturnUrl=%2f"


def test_iis_fields_order_driven_not_hardcoded():
    """#Fields 换顺序/减字段,解析跟着头走(字段顺序以 #Fields 为准)。"""
    text = ("#Fields: time date c-ip sc-status cs-method cs-uri-stem\n"
            "01:02:03 2026-07-21 10.0.0.9 404 HEAD /x\n")
    outcomes = _collect(iis_w3c, text)
    events = [o for o in outcomes if o.kind == "event"]
    assert len(events) == 1
    n = events[0].norm
    assert n["src_ip"] == "10.0.0.9" and n["status"] == 404
    assert n["method"] == "HEAD" and n["path"] == "/x"
    assert events[0].ts_raw == "2026-07-21 01:02:03"


def test_iis_negative_field_count_mismatch():
    """字段数与 #Fields 不一致(截断)→ 坏行计数。"""
    text = IIS_TEXT + "2026-07-20 00:00:09 192.168.10.5 GET /truncated.aspx\n"
    outcomes = _collect(iis_w3c, text)
    bad = [o for o in outcomes if o.kind == "bad"]
    assert len(bad) == 1 and "字段数" in (bad[0].reason or "")
    assert bad[0].line_no == len(IIS_LINES) + 1


def test_iis_negative_data_before_fields():
    """无 #Fields 头就来数据行 → 坏行(无映射依据,不猜列序)。"""
    outcomes = _collect(iis_w3c, "2026-07-20 00:00:02 GET / 200\n")
    assert [o.kind for o in outcomes] == ["bad"]


# ------------------------------------------------------------------- raw_t0

def test_raw_t0_every_line_an_event():
    outcomes = _collect(raw_t0, RAW_TEXT)
    events = [o for o in outcomes if o.kind == "event"]
    assert len(events) == 3 and not any(o.kind == "bad" for o in outcomes)
    for o in events:
        assert o.norm == {}                            # 无归一字段
        assert o.ts_raw is None and o.dt_local is None  # 不猜时间
    assert events[0].raw.startswith("Jul 20 12:00:01")


def test_registry_lookup():
    assert formats.find_format("nginx_combined") is nginx_combined
    assert formats.find_format("apache_common") is apache_common
    assert formats.find_format("iis_w3c") is iis_w3c
    assert formats.find_format("raw") is raw_t0
    assert formats.find_format("nonexistent") is None  # 未知 → None 不猜
    ids = {f["format_id"] for f in formats.list_formats()}
    # desc:* 是治理资产(可被人审启用),不属于内置契约;内置五件套精确比对
    builtin = {i for i in ids if not i.startswith("desc:")}
    assert builtin == {"nginx_combined", "apache_common", "iis_w3c", "raw",
                       "evtx"}


# ------------------------------------------------ nginx combined 追加 XFF 段

def test_nginx_xff_trailing_extracted():
    """combined 后追加单引号段且形如 IP 列表 → norm.xff(实战案例:
    首列是 WAF 回源节点,真实客户端源在 XFF);多跳原样保留。
    样本 IP 一律 RFC 5737 文档段,不带真实案件地址。"""
    text = ('198.51.100.5 - - [10/Oct/2000:13:55:36 +0800] '
            '"GET / HTTP/1.1" 200 10146 "-" "Mozilla/5.0" "192.0.2.6"\n'
            '198.51.100.20 - - [10/Oct/2000:13:55:37 +0800] '
            '"POST /a/login HTTP/1.1" 200 1050610 "http://127.0.0.1/" '
            '"Mozilla/5.0" "203.0.113.201, 10.0.0.1"\n')
    events = [o for o in _collect(nginx_combined, text) if o.kind == "event"]
    assert len(events) == 2
    assert events[0].norm["xff"] == "192.0.2.6"
    assert events[0].norm["src_ip"] == "198.51.100.5"      # 回源节点如实保留
    assert "trailing" not in events[0].norm["extras"]
    assert events[1].norm["xff"] == "203.0.113.201, 10.0.0.1"   # 多跳不裁断


def test_nginx_non_ip_trailing_stays_extras():
    """追加段不是 IP 列表(自定义字段)→ 不抽 xff,照旧留 extras.trailing。"""
    text = ('93.184.216.34 - - [10/Oct/2000:13:55:36 +0300] '
            '"GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0" "0.123"\n'
            '93.184.216.34 - - [10/Oct/2000:13:55:37 +0300] '
            '"GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0" "-"\n')
    events = [o for o in _collect(nginx_combined, text) if o.kind == "event"]
    assert len(events) == 2
    assert "xff" not in events[0].norm
    assert events[0].norm["extras"]["trailing"] == '"0.123"'
    assert "xff" not in events[1].norm                   # "-" 不算真实源
    assert events[1].norm["extras"]["trailing"] == '"-"'
