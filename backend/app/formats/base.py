"""解析器公共件:行级产物类型、解析报告、零静默纪律。

- 解析器对 spec 写不对值写;坏行(不匹配/时间解析失败)逐行计数进
  解析报告,零静默;解析器永不下判断;
- 非空文件 0 行命中 → 调用方(ingest)报错置 failed,不猜;
- 多行合并框架 M0 不实现(web 三格式皆单行),但 line_no 语义是
  「原文物理行号(1 起)」,后续多行块以起始行号为锚,语义已留好;
- 归一字段 web 族(mini-ECS):src_ip/method/path/query/status/bytes/ua/referer;
  映射不上的字段进 norm["extras"],不丢数据。
- 二进制格式(2026-08-14,evtx 首开):模块声明 BINARY = True 并提供
  parse_file(path) -> Iterator[LineOutcome],走文件通道不经文本行;
  line_no 语义=记录号(「第 N 条记录」锚点),raw=该记录原文(如 XML)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


class ParseError(Exception):
    """解析失败的明确原因(回写 log_sources.error,零静默缺口)。"""


@dataclass
class LineOutcome:
    """一行原文的解析产物。

    kind: event(成事件) | bad(坏行,计数进报告) | skip(注释/空行,单独计数)。
    dt_local 是行内本地时间(naive);归一成 ts_utc 由 ingest 统一走
    normalize.to_utc(dt_local, tz_declared),解析器不做时区裁决。
    """
    line_no: int
    raw: str
    kind: str                          # event | bad | skip
    ts_raw: str | None = None
    dt_local: datetime | None = None
    # UTC 原生格式(evtx 的 SystemTime)直通:解析器已持 UTC aware 时间,
    # 不再走「本地时间+声明时区」换算(重复换算是错 twice,不是归一);
    # ingest 归一优先级:ts_utc 直通 > dt_local+tz_declared > None 如实。
    ts_utc: datetime | None = None
    norm: dict = field(default_factory=dict)
    reason: str | None = None          # bad 行的失败原因
    # M4 描述文件引擎:多行合并的续行数(0 = 单行事件);raw 含续行全文,
    # line_no 锚起始物理行号。内置单行格式恒 0,不填。
    continuation_lines: int = 0


@dataclass
class ParseReport:
    """解析报告:总/成/坏/跳,坏行样本留证(如实披露,不藏)。"""
    total_lines: int = 0
    parsed: int = 0
    bad_lines: int = 0
    skipped_lines: int = 0
    bad_samples: list[str] = field(default_factory=list)

    def note_bad(self, o: LineOutcome, max_samples: int = 10) -> None:
        self.bad_lines += 1
        if len(self.bad_samples) < max_samples:
            self.bad_samples.append(f"L{o.line_no}: {o.reason or '不匹配'}")

    def as_dict(self) -> dict:
        return {
            "total_lines": self.total_lines,
            "parsed": self.parsed,
            "bad_lines": self.bad_lines,
            "skipped_lines": self.skipped_lines,
            "bad_samples": self.bad_samples,
        }
