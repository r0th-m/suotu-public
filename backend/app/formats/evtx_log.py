"""Windows evtx 事件日志(二进制)解析器(对 spec 写)。

spec 依据:EVTX 二进制容器(「ElfFile\\x00」魔数 + 64KB chunk,记录为
BinXML);解析引擎用 PyPI `evtx` 包(Rust PyEvtxParser,流式逐记录,
不整读)。记录渲染 XML 的形态见 MSDN 事件 schema(System + EventData/
UserData)。

格式契约(BINARY 通道,见 formats/base.py 头注):
- BINARY = True:走 parse_file(path) 文件通道,不经文本行;
- line_no = 记录号(1 起,锚点语义=「第 N 条记录」),与事件日志自身
  EventRecordID 区分(后者如实进 extras.event_record_id);
- raw = 该记录的 XML 原文(record["data"],查看器按记录号取回);
- 时间:SystemTime 是 UTC 原生(MSDN/EVTX spec 恒定),不经
  「本地时间+声明时区」换算——dt_local 传 None,aware UTC 直接进
  LineOutcome.ts_utc 直通(normalize.resolve_ts_utc),tz_declared 对
  本格式无意义(confirm 可不给);SystemTime 缺失/畸形 → ts 留 None
  如实标注,记录本身仍成事件(时间是证据但不是事件的全部);
- norm:System 层 channel/event_id/provider/computer/level + EventData
  平铺进 extras.event_data(不丢数据);常见命名字段有则上提
  (IpAddress→src_ip、TargetUserName→user——实体白拿,
  IpPort/WorkstationName/ProcessName/TargetDomainName 同名进 norm),
  无则 NULL 不猜;IpAddress 的「-/0.0.0.0/::/环回」是「无地址」占位
  不是源(树庭实战口径),不抽 src_ip;
- 单条记录 XML 解析失败 → bad 计数(零静默),不拖垮整文件;
  文件头/chunk 级损坏(PyEvtxParser 抛错)→ ParseError,调用方置
  failed(容器级损坏无法逐条恢复,残块不猜);
- 空文件/0 记录 → ParseError(与非空 0 行命中同语义,不静默成功)。

并行:二进制容器有内部 chunk 状态,非逐行无状态——不声明 LINE_SAFE,
parallel.line_safe 拿不准一律留串行(本格式恒串行,刻意收窄)。
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree

from .base import LineOutcome, ParseError

FORMAT_ID = "evtx"
BINARY = True  # 二进制文件通道:parse_file(path),不经文本行(base.py 契约)
NAME = "Windows evtx 事件日志(二进制)"

# 「无地址」占位值:出现在 IpAddress 里表示本机/无源,不是真实来源(不抽)
_SKIP_IPS = {"-", "", "0.0.0.0", "127.0.0.1", "::1", "::"}
# EventData 常见命名字段 → norm 同名键(有则抽,无则 NULL 不猜)
_LIFT_FIELDS = ("IpPort", "WorkstationName", "ProcessName", "TargetDomainName")


def _local(tag: str) -> str:
    """剥 XML 命名空间(事件 schema 恒有默认 ns,按 local-name 匹配)。"""
    return tag.rsplit("}", 1)[-1]


def _child(parent: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for el in parent:
        if _local(el.tag) == name:
            return el
    return None


def _flatten_data(node: ElementTree.Element | None,
                  fields: dict, unnamed: list[str]) -> None:
    """EventData/UserData → 平铺 fields(Data@Name 命名) + unnamed(无名 Data)。

    对 spec 容忍变体:命名 Data 重名保留首值(畸形留证在 raw,不猜取舍);
    UserData 的直接子元素按标签名平铺(嵌套层取其文本,结构仍在 raw 原文)。
    """
    if node is None:
        return
    for el in node:
        tag = _local(el.tag)
        if tag == "Data":
            text = (el.text or "").strip()
            name = el.get("Name")
            if name:
                fields.setdefault(name, text)
            elif text:
                unnamed.append(text)
        elif node.tag and _local(node.tag) == "UserData":
            text = (el.text or "").strip()
            if text:
                fields.setdefault(tag, text)


def _outcome_for_record(rec: dict, line_no: int) -> LineOutcome:
    """单条 evtx 记录 dict(PyEvtxParser 产物)→ LineOutcome(纯函数,可单测)。

    rec 形态:{event_record_id, timestamp, data=XML 原文};XML 解析失败
    → bad(零静默),EventID 缺失/非整数 → bad(事件没有身份不成事件)。
    """
    raw = rec.get("data")
    if not isinstance(raw, str) or not raw.strip():
        return LineOutcome(line_no, str(raw or ""), "bad", reason="记录无 XML 原文")
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as e:
        return LineOutcome(line_no, raw, "bad", reason=f"记录 XML 解析失败: {e}")
    system = _child(root, "System")
    if system is None:
        return LineOutcome(line_no, raw, "bad", reason="记录缺 System 段")

    # EventID(容忍 Qualifiers 属性变体;缺失/非整数 → bad,事件没有身份)
    eid_el = _child(system, "EventID")
    try:
        event_id = int((eid_el.text or "").strip()) if eid_el is not None else None
    except ValueError:
        event_id = None
    if event_id is None:
        return LineOutcome(line_no, raw, "bad",
                           reason="EventID 缺失或非整数")

    # SystemTime 是 UTC 原生(spec 恒定):直通 ts_utc,不再做时区换算
    ts_raw = None
    ts_utc = None
    tc_el = _child(system, "TimeCreated")
    if tc_el is not None:
        ts_raw = tc_el.get("SystemTime")
        if ts_raw:
            try:
                ts_utc = datetime.fromisoformat(
                    ts_raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                ts_utc = None             # 畸形时间:ts_raw 留证,ts_utc 如实空

    norm: dict = {"channel": (_child(system, "Channel").text or "").strip()
                  if _child(system, "Channel") is not None else None,
                  "event_id": event_id}
    provider_el = _child(system, "Provider")
    if provider_el is not None and provider_el.get("Name"):
        norm["provider"] = provider_el.get("Name")
    computer_el = _child(system, "Computer")
    if computer_el is not None and (computer_el.text or "").strip():
        norm["computer"] = computer_el.text.strip()
    level_el = _child(system, "Level")
    if level_el is not None:
        try:
            norm["level"] = int((level_el.text or "").strip())
        except ValueError:
            pass                          # Level 畸形:留 NULL 不猜

    fields: dict = {}
    unnamed: list[str] = []
    _flatten_data(_child(root, "EventData"), fields, unnamed)
    _flatten_data(_child(root, "UserData"), fields, unnamed)

    # 常见命名字段上提(有则抽,无则不造);src_ip/user 进实体白拿
    ip = fields.get("IpAddress")
    if isinstance(ip, str) and ip.strip() not in _SKIP_IPS:
        norm["src_ip"] = ip.strip()
    user = fields.get("TargetUserName")
    if isinstance(user, str) and user.strip() and user.strip() != "-":
        norm["user"] = user.strip()
    for key in _LIFT_FIELDS:
        v = fields.get(key)
        if isinstance(v, str) and v.strip():
            norm[key.lower()] = v.strip()

    extras = norm.setdefault("extras", {})
    if fields:
        extras["event_data"] = fields    # EventData 全量平铺留证(不丢数据)
    if unnamed:
        extras["event_data_unnamed"] = unnamed
    rec_id_el = _child(system, "EventRecordID")
    if rec_id_el is not None and (rec_id_el.text or "").strip():
        extras["event_record_id"] = rec_id_el.text.strip()
    if not extras:
        norm.pop("extras")
    return LineOutcome(line_no, raw, "event",
                       ts_raw=ts_raw, ts_utc=ts_utc, norm=norm)


def parse_file(path: Path | str) -> Iterator[LineOutcome]:
    """流式逐记录解析 evtx 二进制 → LineOutcome(记录号锚点)。

    容器级损坏(头/chunk,PyEvtxParser 抛错)→ ParseError;空文件/
    0 记录 → ParseError(与非空 0 命中同语义);单条 XML 坏 → bad。
    """
    try:
        from evtx import PyEvtxParser
    except ImportError as e:                     # 依赖缺失:如实 ParseError
        raise ParseError(f"evtx 解析依赖未安装: {e}") from e

    count = 0
    try:
        records = PyEvtxParser(str(path)).records()
        for rec in records:
            count += 1
            yield _outcome_for_record(rec, count)
    except ParseError:
        raise
    except Exception as e:
        # 头/chunk 级损坏无法逐条恢复:如实 ParseError,残块不猜
        raise ParseError(
            f"evtx 容器解析失败(已出 {count} 条记录后中断): "
            f"{type(e).__name__}: {e}") from e
    if count == 0:
        raise ParseError("evtx 空文件/无记录(0 命中,不猜)")
