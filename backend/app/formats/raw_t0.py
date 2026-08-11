"""raw_t0 兜底格式:任意文本,每行一事件,无归一字段(norm_json={})。

T0 原文档的意义(§4.5):蛮荒日志「入了库但搜不到」的盲区不存在——
raw 字段进 FTS/LIKE 全文检索面,锚点(source_id+行号+sha256)齐全。
ts_raw/ts_utc 一律 None(行内时间不做任何猜测,诚实标注)。
"""
from __future__ import annotations

from typing import Iterable, Iterator

from .base import LineOutcome

FORMAT_ID = "raw"
LINE_SAFE = True  # 逐行无状态,可进程池并行(parallel.py)
NAME = "raw T0 原文兜底(每行一事件)"


def parse(lines: Iterable[str]) -> Iterator[LineOutcome]:
    for line_no, raw in enumerate(lines, 1):
        raw = raw.rstrip("\r\n")
        if not raw.strip():
            yield LineOutcome(line_no, raw, "skip", reason="空行")
            continue
        yield LineOutcome(line_no, raw, "event", norm={})
