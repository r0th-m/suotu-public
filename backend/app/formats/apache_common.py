"""Apache common 格式解析器(对 spec 写)。

spec 依据:Apache LogFormat common(CLF)——
  %h %l %u %t \"%r\" %>s %b
即 remote_host ident authuser [date] "request" status bytes,
无 referer/ua(那是 combined 格式,见 nginx_combined.py)。
date 形如 10/Oct/2000:13:55:36 -0700,时区段同 nginx 纪律:
如实抽进 extras.time_offset,归一按源声明时区走。
"""
from __future__ import annotations

from typing import Iterable, Iterator

from .base import LineOutcome
from .nginx_combined import parse_time_local, split_request

import re

FORMAT_ID = "apache_common"
LINE_SAFE = True  # 逐行无状态,可进程池并行(parallel.py)
NAME = "apache common access log (CLF)"

_LINE_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ (?P<user>\S+)'
    r' \[(?P<time>[^\]]+)\]'
    r' "(?P<request>[^"]*)"'
    r' (?P<status>\d{3}) (?P<bytes>\S+)'
    r'\s*$')   # common 格式到 bytes 为止;行尾多段(如 combined 的
               # referer/ua)→ 不匹配走坏行,两格式必须可区分(对 spec 写)


def parse(lines: Iterable[str]) -> Iterator[LineOutcome]:
    for line_no, raw in enumerate(lines, 1):
        raw = raw.rstrip("\r\n")
        if not raw.strip():
            yield LineOutcome(line_no, raw, "skip", reason="空行")
            continue
        m = _LINE_RE.match(raw)
        if not m:
            yield LineOutcome(line_no, raw, "bad", reason="不匹配 common 行式")
            continue
        dt_local, tz_seg = parse_time_local(m.group("time"))
        if dt_local is None:
            yield LineOutcome(line_no, raw, "bad",
                              ts_raw=m.group("time"),
                              reason="时间解析失败")
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
        extras = norm.setdefault("extras", {})
        extras["time_offset"] = tz_seg
        if not extras:
            norm.pop("extras")
        yield LineOutcome(line_no, raw, "event",
                          ts_raw=m.group("time"), dt_local=dt_local, norm=norm)
