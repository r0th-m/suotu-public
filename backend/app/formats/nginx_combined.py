"""nginx combined 格式解析器(对 spec 写)。

spec 依据:nginx 默认 LogFormat combined——
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
  "$http_referer" "$http_user_agent"
time_local 形如 10/Oct/2000:13:55:36 +0300。

诚实边界:
- 行内时区段(+0300)如实抽进 extras.time_offset 留证,归一不猜用——
  归一只按源声明时区 tz_declared 走(见 normalize.py 头注);
- $request 拆不出「方法 路径 协议」三段时(如 "-"),不判坏行:
  原文进 extras.request,method/path 留 NULL(nginx 对畸形请求就是这么记的);
- status 非三位数字、time_local 解析失败 → 坏行计数,零静默;
- combined 之后若有追加字段(站点自定义 $request_time 等),进 extras.trailing;
- 追加字段若恰好是单个引号段且内容形如 IP 列表(常见 `$http_x_forwarded_for`
  追加法),抽为 norm.xff 留真实客户端源——首列 src_ip 可能是 WAF/代理回源
  节点(实战案例:奇安信云防线回源,真实源全在 XFF);多跳原样保留不裁断。
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator

from .base import LineOutcome

FORMAT_ID = "nginx_combined"
LINE_SAFE = True  # 逐行无状态,可进程池并行(parallel.py)
NAME = "nginx combined access log"

_LINE_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ (?P<user>\S+)'
    r' \[(?P<time>[^\]]+)\]'
    r' "(?P<request>[^"]*)"'
    r' (?P<status>\d{3}) (?P<bytes>\S+)'
    r' "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
    r'(?P<trailing>.*)$')

_TIME_RE = re.compile(r'^(?P<local>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})'
                      r' (?P<offset>[+-]\d{4})$')
_TIME_FMT = "%d/%b/%Y:%H:%M:%S"
_REQUEST_RE = re.compile(r'^(?P<method>\S+) (?P<target>\S+)(?: (?P<protocol>\S+))?$')

# trailing 里的 XFF 形态:单个引号段 + IP 列表(多跳逗号分隔)。
# 只对得上形态才抽 norm.xff;其他自定义追加字段照旧留 extras.trailing。
_XFF_TRAILING_RE = re.compile(r'^"(?P<xff>[^"]*)"$')
_IP_LIST_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}(?:\s*,\s*\d{1,3}(?:\.\d{1,3}){3})*$')


def parse_time_local(text: str):
    """time_local → (naive 本地时间, 行内时区段);失败返回 (None, None)。"""
    m = _TIME_RE.match(text.strip())
    if not m:
        return None, None
    try:
        return datetime.strptime(m.group("local"), _TIME_FMT), m.group("offset")
    except ValueError:
        return None, None


def split_request(request: str) -> dict:
    """$request → method/path(+query)/protocol;拆不出 → 原文进 extras.request。"""
    m = _REQUEST_RE.match(request)
    if not m:
        return {"extras": {"request": request}} if request else {}
    out: dict = {"method": m.group("method")}
    target = m.group("target")
    if "?" in target:
        out["path"], out["query"] = target.split("?", 1)
    else:
        out["path"] = target
    if m.group("protocol"):
        out.setdefault("extras", {})["protocol"] = m.group("protocol")
    return out


def parse(lines: Iterable[str]) -> Iterator[LineOutcome]:
    for line_no, raw in enumerate(lines, 1):
        raw = raw.rstrip("\r\n")
        if not raw.strip():
            yield LineOutcome(line_no, raw, "skip", reason="空行")
            continue
        m = _LINE_RE.match(raw)
        if not m:
            yield LineOutcome(line_no, raw, "bad", reason="不匹配 combined 行式")
            continue
        dt_local, tz_seg = parse_time_local(m.group("time"))
        if dt_local is None:
            yield LineOutcome(line_no, raw, "bad",
                              ts_raw=m.group("time"),
                              reason="time_local 解析失败")
            continue
        norm: dict = {"src_ip": m.group("src_ip")}
        user = m.group("user")
        if user and user != "-":
            norm["user"] = user
        norm.update(split_request(m.group("request")))
        norm["status"] = int(m.group("status"))
        b = m.group("bytes")
        if b != "-":
            norm["bytes"] = int(b)
        ref, ua = m.group("referer"), m.group("ua")
        if ref and ref != "-":
            norm["referer"] = ref
        if ua and ua != "-":
            norm["ua"] = ua
        extras = norm.setdefault("extras", {})
        extras["time_offset"] = tz_seg            # 行内时区如实留证,不猜用
        trailing = (m.group("trailing") or "").strip()
        if trailing:
            xm = _XFF_TRAILING_RE.match(trailing)
            if xm and _IP_LIST_RE.match(xm.group("xff").strip()):
                norm["xff"] = xm.group("xff").strip()   # 真实客户端源(多跳原样)
            else:
                extras["trailing"] = trailing
        if not extras:
            norm.pop("extras")
        yield LineOutcome(line_no, raw, "event",
                          ts_raw=m.group("time"), dt_local=dt_local, norm=norm)
