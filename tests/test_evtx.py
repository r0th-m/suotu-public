"""evtx 二进制格式测试(M?:Windows 事件日志原生解析)。

夹具纪律(§16 同源):
- tests/fixtures/suotu_synthetic.evtx 是本机 PowerShell/wevtutil 合成的
  3 条记录(Application 通道,EventID 1001/1002/4625,合成消息文本,
  无真实案件数据;再生成脚本见 tests/fixtures/gen_suotu_synthetic.ps1);
  树庭的 Security.slice.evtx 是真实案件产物,不带入;
- evtx 无 Python 写库,合成夹具无法携带「命名 EventData 字段」
  (TargetUserName/IpAddress 需要 provider manifest)——命名映射与实体
  生成在记录级纯函数 _outcome_for_record + _extract_entities 上单测
  (合成 XML 记录),二进制全链路用夹具焊锚点/计数/查看器/指纹。
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from backend.app import duck, fingerprint, formats, ingest, viewer
from backend.app.formats import evtx_log
from backend.app.formats.base import ParseError

FIXTURE = Path(__file__).parent / "fixtures" / "suotu_synthetic.evtx"

# 合成 4625 记录 XML(命名 EventData 字段全,覆盖实体映射路径)
LOGIN_XML = """<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID Qualifiers="0">4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-07-23T23:51:55.627332Z"/>
    <EventRecordID>999001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DESKTOP-SYNTH01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetDomainName">WORKGROUP</Data>
    <Data Name="IpAddress">203.0.113.7</Data>
    <Data Name="IpPort">5150</Data>
    <Data Name="WorkstationName">TEST-WS</Data>
    <Data Name="ProcessName">C:\\Windows\\System32\\svchost.exe</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>"""


def _register_evtx(conn, case_id, data: bytes, name="Security.evtx"):
    reg = ingest.register_upload(conn, case_id, name, io.BytesIO(data))
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, "evtx", tz_declared=None,
                          log_type="audit")
    return sid, reg


# ---------------------------------------------------------------- 记录级解析

def test_parse_file_records_and_anchors():
    outcomes = list(evtx_log.parse_file(FIXTURE))
    assert len(outcomes) == 3
    assert [o.line_no for o in outcomes] == [1, 2, 3]   # 锚点=记录号
    assert all(o.kind == "event" for o in outcomes)
    assert all("<Event" in o.raw and "</Event>" in o.raw for o in outcomes)
    assert [o.norm["event_id"] for o in outcomes] == [1001, 1002, 4625]
    first = outcomes[0].norm
    assert first["channel"] == "Application"
    assert first["provider"] == "SuotuFx2026"
    assert first["level"] == 4                          # Information
    assert first["computer"]                            # 有则抽
    # ts:SystemTime 是 UTC 原生——直通 ts_utc,dt_local 恒 None(不重复换算)
    for o in outcomes:
        assert o.dt_local is None
        assert o.ts_utc is not None and o.ts_utc.tzinfo is not None
        assert o.ts_raw and o.ts_raw.endswith("Z")
    assert outcomes[0].ts_utc.isoformat().startswith("2026-08-14T12:45:17")


def test_record_named_fields_and_entities():
    """命名 EventData → norm 上提 + 实体白拿(合成 XML,见模块头注)。"""
    o = evtx_log._outcome_for_record({"data": LOGIN_XML}, 7)
    assert o.kind == "event" and o.line_no == 7
    norm = o.norm
    assert norm["channel"] == "Security" and norm["event_id"] == 4625
    assert norm["provider"] == "Microsoft-Windows-Security-Auditing"
    assert norm["src_ip"] == "203.0.113.7"              # → 实体 ip
    assert norm["user"] == "bob"                        # → 实体 account
    assert norm["ipport"] == "5150"
    assert norm["workstationname"] == "TEST-WS"
    assert norm["processname"].endswith("svchost.exe")
    # EventData 全量平铺留证(不丢数据),含未上提的 LogonType
    assert norm["extras"]["event_data"]["LogonType"] == "3"
    assert norm["extras"]["event_record_id"] == "999001"
    # 实体抽取白拿(src_ip/user 填了就有)
    ents = ingest._extract_entities("src-x", 7, o.ts_utc, norm)
    keys = {(e[2], e[0]) for e in ents}
    assert ("ip", "203.0.113.7") in keys
    assert ("account", "bob") in keys


def test_record_placeholder_ip_not_entity():
    """「无地址」占位(-/0.0.0.0/环回)不抽 src_ip(树庭实战口径)。"""
    xml = LOGIN_XML.replace(">203.0.113.7</Data>", ">-</Data>")
    o = evtx_log._outcome_for_record({"data": xml}, 1)
    assert o.kind == "event"
    assert "src_ip" not in o.norm
    xml2 = LOGIN_XML.replace(">203.0.113.7</Data>", ">0.0.0.0</Data>")
    assert "src_ip" not in evtx_log._outcome_for_record({"data": xml2}, 1).norm


def test_record_bad_xml_counted():
    """单条 XML 坏 → bad(零静默),原因如实,不拖垮其他记录。"""
    o = evtx_log._outcome_for_record({"data": "<Event><System>"}, 5)
    assert o.kind == "bad" and o.line_no == 5
    assert "XML 解析失败" in (o.reason or "")
    no_eid = LOGIN_XML.replace("<EventID Qualifiers=\"0\">4625</EventID>",
                               "<EventID>not-a-number</EventID>")
    o2 = evtx_log._outcome_for_record({"data": no_eid}, 6)
    assert o2.kind == "bad" and "EventID" in (o2.reason or "")


# ------------------------------------------------------------------- 全链路

def test_full_pipeline(conn, case_id):
    sid, _ = _register_evtx(conn, case_id, FIXTURE.read_bytes())
    rep = ingest.parse_source(conn, sid)
    assert rep["status"] == "parsed"
    assert rep["events"] == 3 and rep["total_lines"] == 3
    assert rep["bad_lines"] == 0
    assert rep["time_range"] is not None                # ts_utc 直通 → 有时间范围
    rows = duck.get_conn().execute(
        "SELECT line_no, ts_raw, ts_utc, norm_json, raw FROM log_events"
        " WHERE source_id = ? ORDER BY line_no", (sid,)).fetchall()
    assert [r[0] for r in rows] == [1, 2, 3]            # 锚点=记录号
    assert all(r[2] is not None for r in rows)          # ts_utc 直通非空
    assert all("<Event" in r[4] for r in rows)          # 原文=记录 XML
    norm0 = json.loads(rows[0][3])
    assert norm0["event_id"] == 1001 and norm0["channel"] == "Application"
    # 夹具 EventData 为无名 Data(合成限制,见头注)→ 无 src_ip/user,
    # 实体为 0 是如实结果(命名映射路径在上面的单测里焊死)
    n_ent = duck.get_conn().execute(
        "SELECT COUNT(*) FROM entities WHERE source_id = ?", (sid,)).fetchone()[0]
    assert n_ent == 0
    # 重解析幂等
    rep2 = ingest.parse_source(conn, sid)
    assert rep2["status"] == "parsed" and rep2["events"] == 3


def test_viewer_by_record_number(conn, case_id):
    sid, _ = _register_evtx(conn, case_id, FIXTURE.read_bytes())
    ingest.parse_source(conn, sid)
    page = viewer.read_lines(conn, sid, offset=1, limit=1)
    assert page["total_lines"] == 3
    assert len(page["lines"]) == 1
    assert page["lines"][0]["line_no"] == 2             # 记录号锚点
    assert "1002" in page["lines"][0]["text"]           # 第 2 条记录 XML 原文
    page_all = viewer.read_lines(conn, sid, offset=0, limit=200)
    assert [l["line_no"] for l in page_all["lines"]] == [1, 2, 3]


def test_corrupt_container_failed(conn, case_id):
    """垃圾字节冒名 evtx → ParseError 收口,status=failed 如实,不猜。"""
    sid, _ = _register_evtx(conn, case_id, b"not an evtx" * 100)
    rep = ingest.parse_source(conn, sid)
    assert rep["status"] == "failed" and rep["error"]
    assert "evtx" in rep["error"].lower()
    n = duck.get_conn().execute(
        "SELECT COUNT(*) FROM log_events WHERE source_id = ?", (sid,)).fetchone()[0]
    assert n == 0                                       # 失败不残留派生行


def test_empty_file_failed(conn, case_id, tmp_path):
    """空文件/0 记录 → ParseError(与非空 0 命中同语义)。"""
    empty = tmp_path / "empty.evtx"
    empty.write_bytes(b"")
    with pytest.raises(ParseError):
        list(evtx_log.parse_file(empty))
    sid, _ = _register_evtx(conn, case_id, b"")
    rep = ingest.parse_source(conn, sid)
    assert rep["status"] == "failed" and rep["error"]


# --------------------------------------------------------------------- 指纹

def test_fingerprint_suggests_evtx():
    res = fingerprint.detect(FIXTURE)
    assert res["verdict"] == "ok"
    top = res["suggestions"][0]
    assert top["format_id"] == "evtx"
    assert top["header_hit"] is True                    # ElfFile\0 魔数
    assert top["confidence"] == 1.0                     # 真实解析器试解析全中
    assert top["sample_preview"][0]["norm"]["event_id"] == 1001


def test_fingerprint_register_path(conn, case_id):
    """入库三段式第①步:register 即带 evtx 建议(只建议不确认)。"""
    _, reg = _register_evtx(conn, case_id, FIXTURE.read_bytes())
    fp = reg["sources"][0]["fingerprint"]
    assert fp["suggestions"][0]["format_id"] == "evtx"


def test_text_file_not_suggested_as_evtx(conn, case_id):
    """负样本:nginx 文本不得被建议成 evtx(魔数不命中,试解析 0)。"""
    from conftest import NGINX_TEXT
    reg = ingest.register_upload(conn, case_id, "access.log",
                                 io.BytesIO(NGINX_TEXT.encode()))
    fids = [s["format_id"] for s in reg["sources"][0]["fingerprint"]["suggestions"]]
    assert "evtx" not in fids
    assert fids[0] == "nginx_combined"


# ----------------------------------------------------------------- 注册表面

def test_list_formats_binary_flag():
    lst = {f["format_id"]: f for f in formats.list_formats()}
    assert lst["evtx"]["binary"] is True
    assert lst["nginx_combined"]["binary"] is False
    mod = formats.find_format("evtx")
    assert mod.BINARY is True and callable(mod.parse_file)
