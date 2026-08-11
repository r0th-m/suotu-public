"""案件封存导出(M4,SUOTU_DESIGN §1「一案可封存」)。

封存包 = 单个 zip(data/exports/<case_id>_<UTC>.zip):
① case.db —— 案件库快照,**仅本案件行**(cases 该行 + log_sources/hits/
   clues/analysis_runs/audit_log 按 case_id 过滤;权威载体,凡人的产物全在);
② vault/<sha[:2]>/<sha> —— 本案件全部日志源原文副本(按内容寻址路径归置);
③ manifest.json —— 案件/源/事件数/审计链状态/打包时间/平台版本 总清单;
④ audit_chain.json —— 本案件审计链逐条(独立校验读它,不必懂 sqlite);
⑤ VERIFY.md —— 人类可读的校验说明。

纪律:
- 封存是**只读动作,不锁案件**——继续分析请重新打包(响应 note 如实标注);
- 封存后 cases.sealed_at 留痕(列表可见);同一案件可多次封存(文件名带 UTC 时间戳);
- DuckDB 事件层**不随包**(机器派生物,可由 vault/ 原文重新解析重建),
  manifest.sources[].events 仅作参照计数;
- verify_seal_bytes 是**纯函数**:不连平台数据库/金库/配置,只读 zip 字节
  (哈希公式引 db._entry_hash 纯代码,无数据依赖)——脱离平台也能验。
"""
from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import config, db, duck, logging_setup

# 平台版本标识(与 main.py FastAPI version 保持一致,手动同步)
PLATFORM = {"product": "索图", "version": "M4"}


class SealError(Exception):
    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# 快照内按 case_id 过滤的表(cases 单独按 id 取)
_SNAPSHOT_TABLES = ("log_sources", "hits", "clues", "analysis_runs", "audit_log")

_VERIFY_MD = """# 封存包校验说明(VERIFY)

本包是案件「{case_name}」({case_id})于 {sealed_at} 的封存包(索图 {version})。

## 内容
- `case.db` —— 案件库快照(仅本案件行:源登记/候选/线索/分析台账/审计链)
- `manifest.json` —— 总清单:案件/源(含事件数参照)/审计链状态/打包时间/平台版本
- `audit_chain.json` —— 本案件审计链逐条(校验入口,不必懂 sqlite)
- `vault/` —— 本案件全部日志源原文副本(按内容寻址路径,只读)
- `VERIFY.md` —— 本说明

## 校验方法
平台内:`POST /seal/verify` 上传本 zip;
平台外:`backend.app.seal.verify_seal_bytes(<zip 字节>)` —— 纯函数,
不连平台数据库,仅用 Python 标准库。

校验内容:
1. manifest.json 存在且可解析;
2. 重算 `case.db` 快照 SHA256,与 manifest 比对;快照内案件行与 manifest 一致;
3. `audit_chain.json` 逐条重算 entry_hash(防篡改),并核 prev_hash 链:
   链内连续即续;指向包外条目(其它案件/system 域审计未随包)如实记
   「外部锚定」,不算失败;条数与末 hash 与 manifest 比对;
4. 按 manifest.sources[] 逐源重算 `vault/` 原文 SHA256 对账——
   任何原文篡改/缺失即失败。

任一失败即整体 ok:false,failures 逐条列明。

## 诚实边界
- 封存**不冻结**案件:封存后继续分析的产物不在本包,交接前请重新打包;
- DuckDB 事件层(归一化事件/实体)不随包——机器派生物,
  导入方可用 vault/ 原文经平台重新解析重建;
- 审计链仅含本案件条目:跨案件/system 域(认证、描述文件治理)审计
  在平台 case.db,不随单案封存包。
"""


def _snapshot_case_db(case: sqlite3.Row, conn: sqlite3.Connection,
                      case_id: str) -> bytes:
    """生成仅含本案件行的 case.db 快照,返回字节。"""
    tmp = Path(tempfile.gettempdir()) / f"suotu_seal_{case_id}.db"
    tmp.unlink(missing_ok=True)
    try:
        snap = sqlite3.connect(str(tmp))
        try:
            snap.executescript(db.SCHEMA)
            snap.execute("INSERT INTO cases (id, name, created_at, sealed_at)"
                         " VALUES (?,?,?,?)",
                         (case["id"], case["name"], case["created_at"],
                          case["sealed_at"] if "sealed_at" in case.keys() else None))
            for table in _SNAPSHOT_TABLES:
                cols = [r[1] for r in snap.execute(f"PRAGMA table_info({table})")]
                rows = conn.execute(
                    f"SELECT {', '.join(cols)} FROM {table}"
                    f" WHERE case_id = ?", (case_id,)).fetchall()
                snap.executemany(
                    f"INSERT INTO {table} ({', '.join(cols)})"
                    f" VALUES ({', '.join('?' * len(cols))})",
                    [tuple(r) for r in rows])
            snap.commit()
        finally:
            snap.close()
        return tmp.read_bytes()
    finally:
        tmp.unlink(missing_ok=True)


def seal_case(conn: sqlite3.Connection, case_id: str,
              actor: str = "system") -> dict:
    """封存案件:快照 + 原文 + manifest + 审计链 → data/exports/<case>_<ts>.zip。

    只读动作:不写案件内容,仅更新 sealed_at 留痕 + 审计;不锁案件。
    """
    case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if case is None:
        raise SealError(f"案件不存在: {case_id}", status=404)

    sealed_at = datetime.now(timezone.utc)
    stamp = sealed_at.strftime("%Y%m%dT%H%M%SZ")
    export_dir = config.exports_dir()
    export_dir.mkdir(parents=True, exist_ok=True)
    zip_path = export_dir / f"{case_id}_{stamp}.zip"

    sources = conn.execute(
        "SELECT * FROM log_sources WHERE case_id = ? ORDER BY created_at",
        (case_id,)).fetchall()
    audit_rows = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_log WHERE case_id = ? ORDER BY id", (case_id,))]
    chain_ok, chain_msg = db.verify_audit(conn)

    # 事件数参照(DuckDB 派生层,不随包;读不到如实 None)
    try:
        dconn = duck.get_conn()
        event_counts = {
            r[0]: r[1] for r in dconn.execute(
                "SELECT source_id, COUNT(*) FROM log_events GROUP BY source_id"
            ).fetchall()}
    except Exception:
        event_counts = {}

    snap_bytes = _snapshot_case_db(case, conn, case_id)
    snap_sha = _sha256_bytes(snap_bytes)

    vault_root = config.vault_dir()
    manifest_sources, vault_files, vault_missing = [], [], []
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("case.db", snap_bytes)
        for s in sources:
            src = vault_root / s["vault_path"]
            if src.is_file():
                arc = f"vault/{s['vault_path']}"
                zf.write(src, arc)
                vault_files.append(arc)
            else:
                vault_missing.append(s["vault_path"])   # 缺失零静默
            manifest_sources.append({
                "source_id": s["id"], "name": s["name"], "system": s["system"],
                "log_type": s["log_type"], "format_id": s["format_id"],
                "sha256": s["sha256"], "vault_path": s["vault_path"],
                "line_count": s["line_count"],
                "events": event_counts.get(s["id"]),
            })
        manifest = {
            "case_id": case_id,
            "case_name": case["name"],
            "sealed_at": sealed_at.isoformat(),
            "platform": PLATFORM,
            "case_db": {"file": "case.db", "sha256": snap_sha},
            "sources": manifest_sources,
            "audit": {
                "count": len(audit_rows),
                "last_hash": audit_rows[-1]["entry_hash"] if audit_rows else None,
                "chain_ok_at_seal": chain_ok,
                "chain_message_at_seal": chain_msg,
                "scope": "仅本案件条目(case_id 过滤);跨案件/system 域不随包",
            },
            "vault_copied": len(vault_files),
            "vault_missing": vault_missing,
            "note": "封存不冻结:案件可继续分析,继续分析后请重新打包;"
                    "DuckDB 事件层不随包(机器派生物,可由 vault/ 原文重建)",
        }
        zf.writestr("manifest.json",
                    json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.writestr("audit_chain.json",
                    json.dumps(audit_rows, ensure_ascii=False, indent=2))
        zf.writestr("VERIFY.md", _VERIFY_MD.format(
            case_name=case["name"], case_id=case_id,
            sealed_at=sealed_at.isoformat(), version=PLATFORM["version"]))

    with conn:
        conn.execute("UPDATE cases SET sealed_at = ? WHERE id = ?",
                     (sealed_at.isoformat(), case_id))
        db.append_audit(conn, case_id, actor=actor, action="case_seal",
                        scope=case_id, detail={
                            "export_file": str(zip_path),
                            "case_db_sha256": snap_sha,
                            "sources": len(sources),
                            "vault_copied": len(vault_files),
                            "vault_missing": len(vault_missing),
                            "audit_count": len(audit_rows),
                            "chain_ok_at_seal": chain_ok})
    # 运行日志摘要(封存落点;与审计并行,各记各的)
    logging_setup.app_logger().info(
        "案件封存 case=%s 导出=%s 源=%d 金库=%d 缺失=%d 审计=%d 链=%s actor=%s",
        case_id, zip_path.name, len(sources), len(vault_files),
        len(vault_missing), len(audit_rows), chain_ok, actor)
    return {"export_file": str(zip_path), "sealed_at": sealed_at.isoformat(),
            "case_db_sha256": snap_sha, "sources": len(sources),
            "vault_copied": len(vault_files), "vault_missing": vault_missing,
            "audit": manifest["audit"],
            "note": manifest["note"]}


# ==================== 独立校验(纯函数,不依赖平台数据库) ====================

def verify_seal_bytes(data: bytes) -> dict:
    """校验封存包 zip 字节 → {ok, checks:[{name, ok, detail}], failures:[...]}。

    纯函数:不连平台数据库/金库/配置;zip 不可读抛 SealError(422)。
    """
    checks: list[dict] = []
    failures: list[str] = []

    def _check(name: str, ok: bool, detail: str) -> bool:
        checks.append({"name": name, "ok": ok, "detail": detail})
        if not ok:
            failures.append(f"{name}: {detail}")
        return ok

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise SealError("不是可读的 zip 封存包", status=422)
    with zf:
        names = set(zf.namelist())

        # ① manifest 存在且可解析(后续一切检查的前提,缺了直接整体失败)
        if "manifest.json" not in names:
            _check("manifest", False, "包内无 manifest.json")
            return {"ok": False, "checks": checks, "failures": failures}
        try:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            _check("manifest", False, f"manifest.json 解析失败: {e}")
            return {"ok": False, "checks": checks, "failures": failures}
        _check("manifest", True,
               f"案件 {manifest.get('case_name')} ({manifest.get('case_id')}),"
               f"封存于 {manifest.get('sealed_at')}")

        # ② case.db 快照:SHA256 对账 + 案件行一致
        if "case.db" not in names:
            _check("case_db", False, "包内无 case.db 快照")
        else:
            snap = zf.read("case.db")
            actual = _sha256_bytes(snap)
            expect = (manifest.get("case_db") or {}).get("sha256")
            if _check("case_db_sha256", actual == expect,
                      f"manifest 登记 {str(expect)[:12]}… 实测 {actual[:12]}…"
                      + ("一致" if actual == expect else "不一致(快照被篡改)")):
                tmp = Path(tempfile.gettempdir()) / f"suotu_verify_{actual[:16]}.db"
                try:
                    tmp.write_bytes(snap)
                    sconn = sqlite3.connect(str(tmp))
                    try:
                        row = sconn.execute(
                            "SELECT id, name FROM cases").fetchone()
                        ok = row is not None and row[0] == manifest.get("case_id")
                        _check("case_db_case_row", ok,
                               f"快照内案件行 id={row[0] if row else None}"
                               + ("" if ok else ",与 manifest 不一致"))
                    finally:
                        sconn.close()
                except sqlite3.Error as e:
                    _check("case_db_case_row", False, f"快照不可打开: {e}")
                finally:
                    tmp.unlink(missing_ok=True)

        # ③ 审计链逐条:entry_hash 重算(防篡改) + prev_hash 链核 + 对账 manifest
        if "audit_chain.json" not in names:
            _check("audit_chain", False, "包内无 audit_chain.json")
        else:
            try:
                entries = json.loads(zf.read("audit_chain.json").decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                entries = None
                _check("audit_chain", False, f"audit_chain.json 解析失败: {e}")
            if entries is not None:
                bad, external = [], 0
                prev_exported = None
                for e in entries:
                    expect = db._entry_hash(
                        e["id"], e["case_id"], e["ts"], e["actor"], e["action"],
                        e["scope"], e["detail_json"], e["prev_hash"])
                    if expect != e["entry_hash"]:
                        bad.append(e["id"])          # 行内容被篡改
                    if prev_exported is None:
                        if e["prev_hash"] != db.GENESIS:
                            external += 1            # 首条锚到包外(平台历史)
                    elif e["prev_hash"] != prev_exported:
                        external += 1                # 中间隔着未随包的其它案件条目
                    prev_exported = e["entry_hash"]
                _check("audit_entry_hash", not bad,
                       f"{len(entries)} 条逐条重算"
                       + ("全部一致" if not bad else f",id={bad} 被篡改"))
                _check("audit_chain_link", True,
                       f"链核完成:外部锚定 {external} 处(包外条目,如实记,不算失败)")
                ma = manifest.get("audit") or {}
                _check("audit_count",
                       ma.get("count") == len(entries),
                       f"manifest 记 {ma.get('count')} 条,包内 {len(entries)} 条")
                last = entries[-1]["entry_hash"] if entries else None
                _check("audit_last_hash", ma.get("last_hash") == last,
                       f"末 hash {'一致' if ma.get('last_hash') == last else '不一致'}")

        # ④ 金库原文逐源对账:重算 SHA256 vs manifest.sources[].sha256
        for s in manifest.get("sources") or []:
            arc = f"vault/{s['vault_path']}"
            label = f"vault:{s.get('name') or s['vault_path']}"
            if arc not in names:
                _check(label, False, f"包内缺原文 {arc}")
                continue
            actual = _sha256_bytes(zf.read(arc))
            _check(label, actual == s["sha256"],
                   f"登记 {s['sha256'][:12]}… 实测 {actual[:12]}…"
                   + ("一致" if actual == s["sha256"] else "不一致(原文被篡改)"))

    return {"ok": not failures, "checks": checks, "failures": failures}


__all__ = ["seal_case", "verify_seal_bytes", "SealError", "PLATFORM"]
