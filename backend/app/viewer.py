"""金库原文查看器:带行号读取(offset/limit),读前哈希校验。

- 任何读取先过 vault.verify(哈希失配抛 VaultIntegrityError,带病不读);
- 流式逐行,不整文件读入内存;
- total_lines:已解析源取 log_sources.line_count(权威),未解析源如实 None。
"""
from __future__ import annotations

import sqlite3

from . import vault


class ViewerError(Exception):
    """查看器的明确失败原因(源不存在等)。"""


def read_lines(conn: sqlite3.Connection, source_id: str,
               offset: int = 0, limit: int = 200) -> dict:
    """带行号读原文段。offset=跳过行数(0 起),limit=返回行数。"""
    row = conn.execute("SELECT * FROM log_sources WHERE id = ?",
                       (source_id,)).fetchone()
    if row is None:
        raise ViewerError(f"日志源不存在: {source_id}")
    path = vault.verify(row["vault_path"], row["sha256"])  # 读前校验
    lines: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, text in enumerate(f, 1):
            if line_no <= offset:
                continue
            if len(lines) >= limit:
                break
            lines.append({"line_no": line_no, "text": text.rstrip("\r\n")})
    return {
        "source_id": source_id,
        "name": row["name"],
        "sha256": row["sha256"],
        "offset": offset,
        "limit": limit,
        "total_lines": row["line_count"],  # 未解析为 None,如实
        "lines": lines,
    }
