"""入库三段式管线(SUOTU_DESIGN §4):register → confirm → parse。

① register_source:文件字节/zip → 只读金库 + SHA256 + 指纹探测建议
   (status=registered,只给建议不确认);
② confirm_source:人确认 format_id + tz_declared + log_type
   (status=confirmed)——解析配置永远有人确认,不静默猜;
③ parse_source:解析 → log_events + entities + line_count/time_range/status
   更新 + 解析报告(总/成/坏/跳,零静默);非空文件 0 行命中 → failed 不猜。

zip 上传:逐文件展开成多个 source(单层,不递归嵌套压缩包,嵌套 zip
跳过并如实记进报告)。每步写审计哈希链。
"""
from __future__ import annotations

import io
import ipaddress
import json
import sqlite3
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from . import db, duck, fingerprint, formats, logging_setup, normalize, vault


class IngestError(Exception):
    """入库管线的明确失败原因(状态流转违规/格式未知/0 行命中等)。

    status 为对外 HTTP 语义:默认 400;desc:<name> 描述文件未启用
    (draft/review)用 422 如实区分「未启用」与「未知格式」(§4.3)。
    """
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _new_id() -> str:
    return uuid.uuid4().hex


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- ① register

EVIDENCE_KINDS = ("log", "supplementary")


def _register_one(conn: sqlite3.Connection, case_id: str, stream: BinaryIO,
                  name: str, system: str | None,
                  source_note: str | None, actor: str,
                  evidence_kind: str = "log") -> dict:
    """单文件:金库 + SHA256 + 登记 + 指纹建议。

    evidence_kind:'supplementary'=人补充的证据材料(runlog/目录导出/会话
    录屏等,实战案例工作方式),打标留痕、与日志源同管线可检索。
    """
    if evidence_kind not in EVIDENCE_KINDS:
        raise IngestError(f"evidence_kind 须为 {list(EVIDENCE_KINDS)} 之一: "
                          f"{evidence_kind!r}")
    sha, vault_rel = vault.store(stream)
    source_id = _new_id()
    with conn:
        conn.execute(
            "INSERT INTO log_sources (id, case_id, name, system, log_type,"
            " format_id, tz_declared, time_range, source_note, evidence_kind,"
            " sha256, vault_path, line_count, status, error, created_at)"
            " VALUES (?,?,?,?,'unknown',NULL,NULL,NULL,?,?,?,?,NULL,'registered',NULL,?)",
            (source_id, case_id, name, system, source_note, evidence_kind,
             sha, vault_rel, _now()))
        db.append_audit(conn, case_id, action="source_register", scope=source_id,
                        actor=actor,
                        detail={"name": name, "system": system,
                                "source_note": source_note, "sha256": sha,
                                "evidence_kind": evidence_kind})
    suggestions = fingerprint.detect(vault.locate(vault_rel))
    return {"source_id": source_id, "name": name, "sha256": sha,
            "status": "registered", "evidence_kind": evidence_kind,
            "fingerprint": suggestions}


def register_upload(conn: sqlite3.Connection, case_id: str, filename: str,
                    stream: BinaryIO, system: str | None = None,
                    source_note: str | None = None,
                    actor: str = "system",
                    evidence_kind: str = "log") -> dict:
    """上传入口:单文件或 zip(zip 单层逐文件展开成多个 source,不递归)。

    actor:M4 审计锚真人,API 入口传会话用户名;模块直调恒 system。
    evidence_kind:supplementary=补充证据材料,打标随管线可检索。
    """
    if evidence_kind not in EVIDENCE_KINDS:
        raise IngestError(f"evidence_kind 须为 {list(EVIDENCE_KINDS)} 之一: "
                          f"{evidence_kind!r}")
    head = stream.read(4)
    stream.seek(0)
    if head[:4] == b"PK\x03\x04":
        data = stream.read()
        sources: list[dict] = []
        skipped: list[str] = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                inner = info.filename
                if inner.lower().endswith(".zip"):
                    skipped.append(f"{inner}(嵌套压缩包不递归,跳过)")
                    continue
                with zf.open(info) as inner_stream:
                    sources.append(_register_one(
                        conn, case_id, inner_stream,
                        name=Path(inner).name or inner, system=system,
                        source_note=source_note, actor=actor,
                        evidence_kind=evidence_kind))
        with conn:
            db.append_audit(conn, case_id, action="zip_register", scope=None,
                            actor=actor,
                            detail={"zip": filename, "members": len(sources),
                                    "skipped": skipped,
                                    "evidence_kind": evidence_kind})
        # 运行日志摘要(摄取落点;与审计并行,各记各的)
        logging_setup.app_logger().info(
            "摄取登记 zip=%s 成员=%d 跳过=%d kind=%s actor=%s",
            filename, len(sources), len(skipped), evidence_kind, actor)
        return {"kind": "zip", "zip": filename, "sources": sources,
                "skipped": skipped}
    result = {"kind": "file",
              "sources": [_register_one(conn, case_id, stream, name=filename,
                                        system=system, source_note=source_note,
                                        actor=actor,
                                        evidence_kind=evidence_kind)],
              "skipped": []}
    logging_setup.app_logger().info(
        "摄取登记 file=%s source=%s sha256=%s… actor=%s",
        filename, result["sources"][0]["source_id"],
        result["sources"][0]["sha256"][:12], actor)
    return result


# ----------------------------------------------------------------- ② confirm

def confirm_source(conn: sqlite3.Connection, source_id: str, format_id: str,
                   tz_declared: str | None = None,
                   log_type: str = "unknown",
                   actor: str = "system") -> dict:
    """人确认格式/时区/类型。指纹建议不自动生效,必须走这一步。"""
    row = conn.execute("SELECT * FROM log_sources WHERE id = ?",
                       (source_id,)).fetchone()
    if row is None:
        raise IngestError(f"日志源不存在: {source_id}")
    try:
        mod = formats.find_format(format_id)
    except formats.FormatDescError as e:
        raise IngestError(f"格式描述文件损坏,不带病解析: {e}", status=422)
    if mod is None:
        if format_id.startswith(formats.DESC_PREFIX):
            st = formats.desc_status(format_id[len(formats.DESC_PREFIX):])
            if st in ("draft", "review"):
                raise IngestError(
                    f"格式描述文件 {format_id} 状态为 {st},未启用——"
                    "人审 :transition 至 enable 后才可用于解析(判断权归人)",
                    status=422)
        raise IngestError(f"未知格式: {format_id}(可选见 formats.list_formats())")
    if log_type not in ("web", "middleware", "audit", "unknown"):
        raise IngestError(f"未知日志类型: {log_type}")
    with conn:
        conn.execute(
            "UPDATE log_sources SET format_id = ?, tz_declared = ?, log_type = ?,"
            " status = 'confirmed', error = NULL WHERE id = ?",
            (format_id, tz_declared, log_type, source_id))
        db.append_audit(conn, row["case_id"], action="source_confirm",
                        scope=source_id, actor=actor,
                        detail={"format_id": format_id, "tz_declared": tz_declared,
                                "log_type": log_type})
    logging_setup.app_logger().info(
        "格式确认 source=%s format=%s log_type=%s actor=%s",
        source_id, format_id, log_type, actor)
    return {"source_id": source_id, "status": "confirmed",
            "format_id": format_id, "tz_declared": tz_declared,
            "log_type": log_type}


# ------------------------------------------------------------------- ③ parse

def _extract_entities(source_id: str, line_no: int, ts_utc, norm: dict) -> list[tuple]:
    """从归一字段抽实体(只抽已有字段,不猜)。

    canonical_key 规则:公网 IP → ip 原文 + qualifier=global(允许跨源聚合);
    私网/保留段 → host_scoped;账户 → account。FQDN(domain)本期 web 归一
    字段里没有来源,不造。
    """
    out: list[tuple] = []
    src_ip = norm.get("src_ip")
    if isinstance(src_ip, str):
        try:
            qualifier = "global" if ipaddress.ip_address(src_ip).is_global \
                else "host_scoped"
            out.append((src_ip, f"ip:{src_ip}", "ip", qualifier,
                        source_id, line_no, ts_utc))
        except ValueError:
            pass  # src_ip 不是合法 IP(畸形值),如实不抽,不猜
    for key in ("actor", "user"):
        v = norm.get(key)
        if isinstance(v, str) and v:
            out.append((v, f"account:{v}", "account", "host_scoped",
                        source_id, line_no, ts_utc))
    return out


def parse_source(conn: sqlite3.Connection, source_id: str,
                 actor: str = "system", workers: int | None = None) -> dict:
    """解析已确认的日志源 → log_events + entities + 解析报告。

    失败(状态违规/格式未知/金库失配/非空文件 0 行命中)→ status=failed
    + error 列 + 审计,不猜不瞒。重解析幂等(先清该源派生行)。
    workers:None → SUOTU_PARALLEL_WORKERS(缺省 min(cpu,8));>1 且文件
    ≥16MB 且格式逐行安全 → 进程池按行区间并行(parallel.py,锚点不变式:
    line_no 恒为原文物理行号);否则串行原路径。
    """
    row = conn.execute("SELECT * FROM log_sources WHERE id = ?",
                       (source_id,)).fetchone()
    if row is None:
        raise IngestError(f"日志源不存在: {source_id}")
    if row["status"] not in ("confirmed", "failed", "parsed"):
        raise IngestError(
            f"日志源状态为 {row['status']},须先 confirm 再 parse")
    t0 = time.monotonic()
    try:
        mod = formats.find_format(row["format_id"] or "")
    except formats.FormatDescError as e:
        raise IngestError(f"格式描述文件损坏,不带病解析: {e}")
    if mod is None:
        fmt = row["format_id"] or ""
        if fmt.startswith(formats.DESC_PREFIX):
            raise IngestError(
                f"格式描述文件 {fmt} 已未启用/删除(confirm 后被 disable "
                "或移除),请重新确认格式,不猜")
        raise IngestError(f"未知格式: {row['format_id']}")

    def _fail(msg: str) -> dict:
        return _fail_source(conn, row, source_id, actor, msg)

    try:
        path = vault.verify(row["vault_path"], row["sha256"])  # 读前校验
    except vault.VaultIntegrityError as e:
        return _fail(str(e))

    if workers is None:
        from . import parallel as _par
        workers = _par.workers_from_env()
    # 描述文件可声明源编码(GBK 业务日志);内置格式无该属性 → utf-8
    enc = getattr(mod, "encoding", None) or "utf-8"
    # 二进制格式(BINARY=True,如 evtx)走 parse_file 文件通道;
    # 二进制容器非逐行无状态,永不进并行(line_safe 拿不准一律 False,
    # 这里再显性闸一道,双保险)
    binary = bool(getattr(mod, "BINARY", False))
    if workers > 1 and not binary:
        from . import parallel as _par
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if size >= _par.MIN_PARALLEL_BYTES and \
                _par.line_safe(mod, row["format_id"] or ""):
            return _parse_source_parallel(conn, row, path, enc, actor,
                                          workers, t0)

    report = formats.ParseReport()
    dconn = duck.get_conn()
    duck.delete_source(dconn, source_id)  # 重解析幂等

    def _outcomes():
        # BINARY 走文件通道(parse_file),文本走行通道(parse);锚点语义
        # 一致:line_no 恒为「第 N 条」(物理行号 / 记录号)
        if binary:
            yield from mod.parse_file(path)
        else:
            yield from mod.parse(_iter_lines(path, enc))

    def _event_rows():
        for o in _outcomes():
            report.total_lines += 1
            if o.kind == "skip":
                report.skipped_lines += 1
                continue
            if o.kind == "bad":
                report.note_bad(o)
                continue
            report.parsed += 1
            ts_utc = normalize.resolve_ts_utc(o.dt_local, row["tz_declared"],
                                              o.ts_utc)
            norm_json = json.dumps(o.norm, ensure_ascii=False)
            yield (_new_id(), source_id, o.line_no, o.ts_raw, ts_utc,
                   norm_json, o.raw, row["sha256"])

    def _entity_rows():
        # 第二趟流式重扫(文件在金库,IO 便宜):事件与实体分两趟走,
        # 换取内存恒定——事件流式 COPY 入库,实体不攒全量。
        for o in _outcomes():
            if o.kind != "event":
                continue
            ts_utc = normalize.resolve_ts_utc(o.dt_local, row["tz_declared"],
                                              o.ts_utc)
            yield from _extract_entities(source_id, o.line_no, ts_utc, o.norm)

    # 非空文件 0 行命中 → 报错不猜(此时还没有任何事件插入,无需回滚)
    # ParseError(如 evtx 容器损坏/0 记录):解析器明确拒绝,清掉半成品
    # 派生行后置 failed(零静默,残块不猜)
    try:
        n_events = duck.insert_events(dconn, _event_rows())
    except formats.ParseError as e:
        duck.delete_source(dconn, source_id)
        return _fail(str(e))
    data_lines = report.parsed + report.bad_lines
    if data_lines > 0 and report.parsed == 0:
        return _fail(f"非空文件 {data_lines} 行数据 0 行命中"
                     f"(格式 {row['format_id']} 可能选错),不猜")
    n_entities = duck.insert_entities(dconn, _entity_rows())
    return _finalize_parse(conn, row, dconn, report, n_events, n_entities,
                           actor, t0)


def _fail_source(conn: sqlite3.Connection, row, source_id: str,
                 actor: str, msg: str) -> dict:
    """解析失败落痕(串/并行共用):status=failed + error + 审计 + 运行日志。"""
    with conn:
        conn.execute("UPDATE log_sources SET status = 'failed', error = ?"
                     " WHERE id = ?", (msg, source_id))
        db.append_audit(conn, row["case_id"], action="source_parse",
                        scope=source_id, actor=actor,
                        detail={"status": "failed", "error": msg})
    # 解析失败是业务失败(非异常):app.log 记 warning,如实带原因
    logging_setup.app_logger().warning(
        "解析失败 source=%s format=%s actor=%s: %s",
        source_id, row["format_id"], actor, msg)
    return {"source_id": source_id, "status": "failed", "error": msg}


def _finalize_parse(conn: sqlite3.Connection, row, dconn,
                    report: "formats.ParseReport", n_events: int,
                    n_entities: int, actor: str, t0: float) -> dict:
    """解析收尾(串/并行共用):时间范围 + 状态回写 + 审计 + 运行日志。"""
    source_id = row["id"]
    # 时间范围(有 ts_utc 才出,全 NULL 则如实空)
    tr = dconn.execute(
        "SELECT MIN(ts_utc), MAX(ts_utc) FROM log_events WHERE source_id = ?",
        (source_id,)).fetchone()
    time_range = None
    if tr and tr[0] is not None:
        time_range = json.dumps(
            {"from": tr[0].isoformat(), "to": tr[1].isoformat()})

    with conn:
        conn.execute(
            "UPDATE log_sources SET status = 'parsed', error = NULL,"
            " line_count = ?, time_range = ? WHERE id = ?",
            (report.parsed, time_range, source_id))
        db.append_audit(conn, row["case_id"], action="source_parse",
                        scope=source_id, actor=actor,
                        detail={"status": "parsed",
                                "format_id": row["format_id"],
                                "events": n_events, "entities": n_entities,
                                **report.as_dict()})
    logging_setup.app_logger().info(
        "解析完成 source=%s format=%s 行=%d 事件=%d 实体=%d 坏行=%d %dms actor=%s",
        source_id, row["format_id"], report.total_lines, n_events, n_entities,
        report.bad_lines, int((time.monotonic() - t0) * 1000), actor)
    return {"source_id": source_id, "status": "parsed",
            "format_id": row["format_id"], "events": n_events,
            "entities": n_entities, "time_range": time_range,
            **report.as_dict()}


def _parse_source_parallel(conn: sqlite3.Connection, row, path: Path,
                           enc: str, actor: str, workers: int,
                           t0: float) -> dict:
    """并行解析(2026-08-10):主进程预扫行索引 → worker 按行区间纯解析
    产 CSV → 主进程 copy_csv_file 直灌(对账+回滚)。

    与串行的语义边界:事件/实体内容逐条一致(uuid 例外);报告计数合并;
    0 命中检查/时间范围/状态回写/审计与串行同一收尾(_finalize_parse)。
    """
    from . import parallel as _par

    source_id = row["id"]
    report = formats.ParseReport()
    dconn = duck.get_conn()
    duck.delete_source(dconn, source_id)  # 重解析幂等
    index = _par.build_line_index(path)
    tmp_dir = _par.make_tmp_dir()
    tasks = []
    for i, (start_line, off) in enumerate(index):
        end_line = index[i + 1][0] if i + 1 < len(index) else None
        tasks.append({"path": str(path), "encoding": enc,
                      "format_id": row["format_id"], "source_id": source_id,
                      "sha256": row["sha256"], "tz_declared": row["tz_declared"],
                      "start_line": start_line, "end_line": end_line,
                      "byte_offset": off, "tmp_dir": str(tmp_dir),
                      "tag": f"{source_id[:12]}_{i}"})
    try:
        n_events = 0
        n_entities = 0
        for res in _par.run_parse_tasks(tasks, workers):
            if res["error"]:
                raise IngestError(
                    f"并行 worker 解析失败(区间 L{res.get('start_line', '?')}): "
                    f"{res['error']}", status=500)
            # 空 CSV(0 行)跳过直灌:read_csv 对空文件嗅探报错,0 行无可入
            if res["events"]:
                duck.copy_csv_file(dconn, "log_events",
                                   Path(res["csvs"]["events"]),
                                   duck._EVENT_COLS, duck._EVENT_TYPES,
                                   expect_rows=res["events"])
            if res["entities"]:
                duck.copy_csv_file(dconn, "entities",
                                   Path(res["csvs"]["entities"]),
                                   duck._ENTITY_COLS, duck._ENTITY_TYPES,
                                   expect_rows=res["entities"])
            n_events += res["events"]
            n_entities += res["entities"]
            report.total_lines += res["total_lines"]
            report.parsed += res["parsed"]
            report.bad_lines += res["bad_lines"]
            report.skipped_lines += res["skipped_lines"]
            for s in res["bad_samples"]:
                if len(report.bad_samples) < 10:
                    report.bad_samples.append(s)
    finally:
        _par.cleanup_tmp_dir(tmp_dir)
    data_lines = report.parsed + report.bad_lines
    if data_lines > 0 and report.parsed == 0:
        return _fail_source(conn, row, source_id, actor,
                            f"非空文件 {data_lines} 行数据 0 行命中"
                            f"(格式 {row['format_id']} 可能选错),不猜")
    return _finalize_parse(conn, row, dconn, report, n_events, n_entities,
                           actor, t0)


def _iter_lines(path: Path, encoding: str = "utf-8"):
    with path.open("r", encoding=encoding, errors="replace") as f:
        yield from f


def latest_parse_report(conn: sqlite3.Connection, source_id: str) -> dict | None:
    """最近一次解析的审计明细(解析报告随审计留痕,不另开存储)。"""
    row = conn.execute(
        "SELECT detail_json FROM audit_log WHERE scope = ?"
        " AND action = 'source_parse' ORDER BY id DESC LIMIT 1",
        (source_id,)).fetchone()
    return json.loads(row["detail_json"]) if row else None
