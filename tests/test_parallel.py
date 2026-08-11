"""并行化等价性契约(2026-08-10,平移主机取证平台一期;SUOTU_PARALLEL_WORKERS)。

口径(诚实边界):事件 id 是 uuid4(串行也随机),不比;其余全列集合相等
(顺序无关);line_no 锚点不变式(恒原文物理行号)逐条比对。
"""
from __future__ import annotations

import io

import pytest

from backend.app import duck, ingest, parallel
from backend.app.formats import apache_common, nginx_combined, raw_t0

from conftest import NGINX_LINES, register_confirm_parse

_EVENTS_SQL = ("SELECT source_id, line_no, ts_raw, ts_utc, norm_json, raw,"
               " sha256 FROM log_events")
_ENTITIES_SQL = ("SELECT raw_value, canonical_key, entity_type, qualifier,"
                 " source_id, line_no, ts_utc FROM entities")


def _snap():
    dconn = duck.get_conn()
    return (sorted(dconn.execute(_EVENTS_SQL).fetchall(), key=repr),
            sorted(dconn.execute(_ENTITIES_SQL).fetchall(), key=repr))


def _big_nginx(lines_target: int = 9000) -> str:
    """超并行阈值的合成 nginx 日志(monkeypatch 阈值后 9k 行足够)。"""
    out = []
    for i in range(lines_target):
        _head, rest = NGINX_LINES[i % 3].split(" ", 1)   # 只换首列 IP
        out.append(f"10.9.{i % 250}.{i % 251} {rest}")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- 环境/判安

def test_workers_env(monkeypatch):
    monkeypatch.delenv("SUOTU_PARALLEL_WORKERS", raising=False)
    assert parallel.workers_from_env() >= 2
    monkeypatch.setenv("SUOTU_PARALLEL_WORKERS", "1")
    assert parallel.workers_from_env() == 1
    monkeypatch.setenv("SUOTU_PARALLEL_WORKERS", "abc")
    assert parallel.workers_from_env() == 1


def test_line_safe_matrix():
    assert parallel.line_safe(nginx_combined, "nginx_combined") is True
    assert parallel.line_safe(apache_common, "apache_common") is True
    assert parallel.line_safe(raw_t0, "raw") is True

    class _FakeDesc:
        kind = "regex"
        _start_re = None
    assert parallel.line_safe(_FakeDesc, "desc:app-x") is True
    _FakeDesc.kind = "csv"
    assert parallel.line_safe(_FakeDesc, "desc:app-csv") is False   # 表头状态
    _FakeDesc.kind = "regex"
    _FakeDesc._start_re = object()                                  # 续行状态
    assert parallel.line_safe(_FakeDesc, "desc:app-ml") is False

    class _NoAttr:
        pass
    assert parallel.line_safe(_NoAttr, "iis_w3c") is False          # #Fields 头状态


def test_line_index_offsets(tmp_path):
    """行索引:档距处 (行号, 字节偏移) 精确;偏移寻址读出的恰是该行。"""
    lines = [f"line-{i} x{i % 7}\n" for i in range(1, 101)]
    p = tmp_path / "t.log"
    p.write_text("".join(lines), encoding="utf-8", newline="")  # 不换行符转换
    idx = parallel.build_line_index(p, chunk_lines=10)
    assert idx[0] == (1, 0)
    for line_no, off in idx[1:]:
        assert (line_no - 1) % 10 == 0
        with p.open("rb") as f:
            f.seek(off)
            got = f.readline().decode().rstrip("\r\n")
        assert got == lines[line_no - 1].rstrip("\r\n")  # 偏移直跳=该行原文


# ---------------------------------------------------------------- 解析等价

def test_parse_parallel_equivalent(conn, case_id, monkeypatch, tmp_path):
    monkeypatch.setattr(parallel, "MIN_PARALLEL_BYTES", 1024)  # 小样本也走并行
    text = _big_nginx()
    # 串行基准
    sid1, _, rep_s = register_confirm_parse(conn, case_id, text, "nginx_combined")
    snap_s = _snap()
    assert rep_s["events"] > 0
    # 并行(重解析同一源:幂等先清再建)
    rep_p = ingest.parse_source(conn, sid1, workers=2)
    snap_p = _snap()
    assert snap_s == snap_p                     # 除 id 全列集合相等(含 line_no 锚点)
    assert rep_s["events"] == rep_p["events"]
    assert rep_s["entities"] == rep_p["entities"]
    assert rep_s["parsed"] == rep_p["parsed"]
    assert rep_s["total_lines"] == rep_p["total_lines"]
    assert rep_s["bad_lines"] == rep_p["bad_lines"]
    assert rep_s["time_range"] == rep_p["time_range"]


def test_parse_parallel_bad_lines_merge(conn, case_id, monkeypatch):
    """坏行/跳行计数与样本跨区间合并,与串行一致(零静默)。"""
    monkeypatch.setattr(parallel, "MIN_PARALLEL_BYTES", 1024)
    good = NGINX_LINES[0]
    text = "\n".join([good, "garbage-line", "", good[::-1][:30], good] * 400) + "\n"
    sid, _, rep_s = register_confirm_parse(conn, case_id, text, "nginx_combined")
    rep_p = ingest.parse_source(conn, sid, workers=2)
    for k in ("parsed", "bad_lines", "skipped_lines", "total_lines", "events"):
        assert rep_s[k] == rep_p[k], (k, rep_s[k], rep_p[k])
    assert rep_s["bad_lines"] > 0 and rep_s["skipped_lines"] > 0


def test_zero_hit_parallel_also_fails(conn, case_id, monkeypatch):
    """非空 0 命中:并行同样置 failed 不猜(与串行同一道闸)。"""
    monkeypatch.setattr(parallel, "MIN_PARALLEL_BYTES", 1024)
    text = "totally not a log line\n" * 3000
    reg = ingest.register_upload(conn, case_id, "weird.log",
                                 io.BytesIO(text.encode()))
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, "nginx_combined")
    rep = ingest.parse_source(conn, sid, workers=2)
    assert rep["status"] == "failed" and "0 行命中" in rep["error"]
