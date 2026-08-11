"""IIS W3C 扩展日志格式解析器(对 spec 写)。

spec 依据:Microsoft IIS 的 W3C Extended Log File Format——
- 文件头为 # 开头的指令行:#Software / #Version / #Date / #Fields;
- #Fields 行列出后续数据行的字段清单与顺序,字段映射以 #Fields 为准,
  绝不硬编码字段顺序(不同站点/版本字段集不同);
- 数据行字段空格分隔,缺值以 "-" 占位;
- date time 两字段合成行内时间(ts_raw = "date time")。

诚实边界:
- IIS 按 spec 默认以 UTC 记录,但本解析器不据此自作主张:归一仍按
  源声明时区 tz_declared 走(与全格式同一纪律),无时区声明 → ts_utc=None;
- # 注释/指令行跳过并单独计数(skipped),不算坏行;
- 无 #Fields 头就遇到数据行 → 坏行(无字段映射依据,不猜列序);
- 字段数与 #Fields 不一致 → 坏行(截断/错乱如实计数)。
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable, Iterator

from .base import LineOutcome

FORMAT_ID = "iis_w3c"
NAME = "IIS W3C extended log"

_TIME_FMT = "%Y-%m-%d %H:%M:%S"

# W3C 字段名 → mini-ECS 归一字段;未收录的进 extras(原字段名,不丢数据)
_FIELD_MAP = {
    "c-ip": "src_ip",
    "cs-method": "method",
    "cs-uri-stem": "path",
    "cs-uri-query": "query",
    "sc-status": "status",
    "sc-bytes": "bytes",
    "cs(User-Agent)": "ua",
    "cs(Referer)": "referer",
    "cs(Referrer)": "referer",
    "cs-username": "user",
}
_INT_FIELDS = {"status", "bytes"}


def parse(lines: Iterable[str]) -> Iterator[LineOutcome]:
    fields: list[str] | None = None   # #Fields 驱动的字段顺序(不硬编码)
    for line_no, raw in enumerate(lines, 1):
        raw = raw.rstrip("\r\n")
        if not raw.strip():
            yield LineOutcome(line_no, raw, "skip", reason="空行")
            continue
        if raw.startswith("#"):
            if raw.lower().startswith("#fields:"):
                fields = raw.split(":", 1)[1].split()
            yield LineOutcome(line_no, raw, "skip", reason="指令/注释行")
            continue
        if fields is None:
            yield LineOutcome(line_no, raw, "bad",
                              reason="无 #Fields 头,无字段映射依据")
            continue
        parts = raw.split(" ")
        if len(parts) != len(fields):
            yield LineOutcome(line_no, raw, "bad",
                              reason=f"字段数 {len(parts)} 与 #Fields {len(fields)} 不一致")
            continue
        row = dict(zip(fields, parts))
        date, time_ = row.get("date"), row.get("time")
        ts_raw = f"{date} {time_}" if date and time_ else None
        dt_local = None
        if ts_raw:
            try:
                dt_local = datetime.strptime(ts_raw, _TIME_FMT)
            except ValueError:
                yield LineOutcome(line_no, raw, "bad", ts_raw=ts_raw,
                                  reason="date/time 解析失败")
                continue
        norm: dict = {}
        extras: dict = {}
        for fname, value in row.items():
            if fname in ("date", "time") or value == "-":
                continue
            key = _FIELD_MAP.get(fname)
            if key is None:
                extras[fname] = value
                continue
            if key in _INT_FIELDS:
                try:
                    norm[key] = int(value)
                except ValueError:
                    extras[fname] = value   # 非数字如实留 extras,不判坏不猜 0
                continue
            norm[key] = value
        if extras:
            norm["extras"] = extras
        yield LineOutcome(line_no, raw, "event",
                          ts_raw=ts_raw, dt_local=dt_local, norm=norm)
