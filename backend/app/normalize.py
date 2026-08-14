"""时间归一三层(SUOTU_DESIGN §5,简化平移主机取证平台 §9.3)。

- ts_raw 原样保留(解析器负责,本模块不碰);
- 源声明时区(tz_declared,IANA 名)已知 → 行内本地时间归一为 ts_utc;
- 无时区声明 → ts_utc=None 如实标注,不硬归一、不猜;
- 行内自带的时区偏移(如 nginx time_local 的 +0300)由解析器如实抽进
  extras 留证,归一只按源声明时区走——两个时区不一致是源登记问题,
  不是解析器该 silently 裁决的事。
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

# 小型 IANA → 标准时偏移兜底表(分钟):Windows 常无 tzdata,zoneinfo 查不到
# 时按标准时偏移归一(夏令时误差如实归属「时区声明归一」的语义内,不伪造精确)。
_IANA_STD_OFFSET_MINUTES = {
    "asia/shanghai": 480, "asia/beijing": 480, "asia/chongqing": 480,
    "asia/hong_kong": 480, "asia/taipei": 480, "asia/singapore": 480,
    "asia/tokyo": 540, "asia/seoul": 540, "asia/kolkata": 330,
    "europe/london": 0, "europe/paris": 60, "europe/berlin": 60,
    "america/new_york": -300, "america/chicago": -360,
    "america/los_angeles": -480,
    "utc": 0, "etc/utc": 0, "etc/gmt": 0,
}
_UTC_LITERAL_RE = re.compile(r"^(?:UTC|GMT)?([+-])(\d{1,2})(?::?(\d{2}))?$", re.I)

# tzinfo 缓存(2026-08-05 压测实测:ZoneInfo 逐行构造 ~270µs/行,
# 1000 万行×两趟 = 90 分钟级灾难;按声明名缓存后归一近乎免费——
# 同一时区名的 tzinfo 不可变,缓存无语义变化)
_TZ_CACHE: dict[str, timezone | None] = {}


def tz_offset(tz_declared: str | None) -> timezone | None:
    """声明时区 → tzinfo;识别不了 → None(时区未知,不硬归一)。

    识别顺序(全部确定性):zoneinfo(带 DST,最准)→ 兜底表(标准时)
    → UTC±x 字面量 → None。
    """
    if not tz_declared or not tz_declared.strip():
        return None
    name = tz_declared.strip()
    if name in _TZ_CACHE:
        return _TZ_CACHE[name]
    tz: timezone | None
    try:
        from zoneinfo import ZoneInfo  # stdlib;无 tzdata 的环境抛 ZoneInfoNotFoundError
        tz = ZoneInfo(name)  # type: ignore[assignment]
    except Exception:
        lower = name.lower()
        if lower in _IANA_STD_OFFSET_MINUTES:
            tz = timezone(timedelta(minutes=_IANA_STD_OFFSET_MINUTES[lower]))
        else:
            m = _UTC_LITERAL_RE.match(name)
            if m:
                sign = 1 if m.group(1) == "+" else -1
                minutes = int(m.group(2)) * 60 + int(m.group(3) or 0)
                tz = timezone(sign * timedelta(minutes=minutes))
            else:
                tz = None
    _TZ_CACHE[name] = tz
    return tz


def to_utc(dt_local: datetime | None, tz_declared: str | None) -> datetime | None:
    """行内本地时间(naive)→ UTC;时区未知 → None 如实(不硬归一)。"""
    if dt_local is None:
        return None
    tz = tz_offset(tz_declared)
    if tz is None:
        return None
    return dt_local.replace(tzinfo=tz).astimezone(timezone.utc)


def resolve_ts_utc(dt_local: datetime | None, tz_declared: str | None,
                   ts_utc_direct: datetime | None = None) -> datetime | None:
    """LineOutcome 三要素 → ts_utc 的统一裁决(ingest 串/并行同一入口)。

    优先级:ts_utc_direct(UTC 原生格式直通,如 evtx SystemTime)>
    dt_local + 声明时区归一 > None 如实(时区未知不硬归一)。
    直通值须为 aware UTC(解析器契约);naive 直通值按声明时区语义
    会错,故这里只做 astimezone(UTC) 幂等换算,不替解析器猜时区。
    """
    if ts_utc_direct is not None:
        if ts_utc_direct.tzinfo is None:
            return None                     # 直通给 naive 是契约违规,如实不猜
        return ts_utc_direct.astimezone(timezone.utc)
    return to_utc(dt_local, tz_declared)
