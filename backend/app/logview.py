"""日志查看 API + 一键诊断包(移植自主机取证平台 v1.2.0,适配索图)。

- GET /logs?file=app|error|operation&lines=N&q=关键字:按行反向读文件尾部
  (8KB 块从尾向前,大文件不全读),再按关键字过滤;file 白名单,非法名 400
  (防目录穿越——文件名永不进路径拼接);
- GET /logs/files:三个日志文件的大小/修改时间;
- POST /diagnostics/bundle:zip 下载——三个日志尾部(各 ≤500 行)+ 版本信息
  (git/python/OS)+ 脱敏配置(AI provider/model、SUOTU_* 与 AI_* 环境变量,
  key/口令只报「已配置/未配置」,永不带值)+ 错误统计(近 100 行 error.log
  异常类型计数)+ 审计链状态;**生成动作写审计哈希链**(人的排障动作留痕,
  日志文件本身仍与审计严格分离)。

全部端点走 main.py 全局认证闸(白名单外一律 require_user)。
"""
from __future__ import annotations

import io
import os
import platform
import re
import subprocess
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from . import ai, auth, config, db, logging_setup

router = APIRouter(tags=["logs"])

_TAIL_CHUNK = 8192                       # 反向读块大小
_BUNDLE_TAIL = 500                       # 诊断包每个日志文件最多带多少行
_ERROR_STAT_LINES = 100                  # 错误统计看 error.log 尾部多少行
# 敏感环境变量名特征:名字命中即只报打码值,真值一律不出
_SENSITIVE_NAME = re.compile(r"(?i)key|password|passwd|token|secret|cookie")
# 异常类型提取(error.log 行内)
_EXC_TYPE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception))\b")
_MASKED = "***"


def tail_lines(path: Path, n: int) -> list[str]:
    """按行反向读文件尾部 n 行(8KB 块,大文件不全读);返回时间正序行清单。

    文件不存在 → 空清单;行内换行已剥掉;解码错误替换(不炸)。
    """
    if not path.is_file() or n <= 0:
        return []
    data = bytearray()
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        # 反向读块,直到凑够 n+1 个换行或读到文件头
        while pos > 0 and data.count(b"\n") <= n:
            step = min(_TAIL_CHUNK, pos)
            pos -= step
            f.seek(pos)
            data = bytearray(f.read(step)) + data
    lines = bytes(data).decode("utf-8", errors="replace").splitlines()
    return lines[-n:]


def list_log_files() -> list[dict]:
    """三个日志文件的大小/修改时间(文件未生成时如实 exists=False)。"""
    out = []
    for kind, filename in logging_setup.LOG_FILES.items():
        p = logging_setup.log_path(kind)
        if p.is_file():
            st = p.stat()
            out.append({"file": kind, "name": filename, "exists": True,
                        "size": st.st_size,
                        "mtime": datetime.fromtimestamp(
                            st.st_mtime, tz=timezone.utc).isoformat()})
        else:
            out.append({"file": kind, "name": filename, "exists": False,
                        "size": 0, "mtime": None})
    return out


@router.get("/logs")
def read_log(file: str = Query(description="app | error | operation"),
             lines: int = Query(default=200, ge=1, le=2000),
             q: str | None = Query(default=None, description="关键字(大小写不敏感子串)")):
    """读日志文件尾部(先取 lines 行,再按关键字过滤);全部端点走全局认证闸。"""
    if file not in logging_setup.LOG_FILES:
        # 白名单:非法名直接 400,文件名永不拼进路径(防目录穿越)
        raise HTTPException(400, f"file 须为 {sorted(logging_setup.LOG_FILES)} 之一")
    tail = tail_lines(logging_setup.log_path(file), lines)
    matched = len(tail)
    if q and q.strip():
        needle = q.strip().lower()
        tail = [ln for ln in tail if needle in ln.lower()]
        matched = len(tail)
    return {"file": file, "requested": lines, "matched": matched, "lines": tail}


@router.get("/logs/files")
def log_files():
    """三个日志文件的大小/修改时间(日志页概览用)。"""
    return {"files": list_log_files()}


# ==================== 一键诊断包 ====================

def _version_info() -> str:
    """版本信息:git 描述(拿不到如实写)、python、OS、数据目录。"""
    try:
        git = subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty"],
            cwd=config.REPO_ROOT, capture_output=True, text=True, timeout=5)
        git_ver = git.stdout.strip() or f"(git 无输出: {git.stderr.strip()[:100]})"
    except Exception as e:                            # 无 git/超时都如实写
        git_ver = f"(不可用: {type(e).__name__})"
    from .main import app                             # 延迟导入,避免环
    return (f"app_version: {app.version}\n"
            f"git: {git_ver}\n"
            f"python: {platform.python_version()}\n"
            f"os: {platform.platform()}\n"
            f"data_dir: {config.data_dir()}\n")


def _sanitized_config() -> str:
    """脱敏配置:AI provider/model/base_url + key 只报配置与否;
    SUOTU_* 与 AI_* 环境变量,名字带 key/口令/token 特征的一律打码。"""
    snap = ai.config_snapshot()
    lines = [
        f"AI_PROVIDER: {snap['provider']}",
        f"AI_BASE_URL: {snap['base_url']}",
        f"AI_MODEL: {snap['model']}",
        f"AI_API_KEY: {'已配置(值不出)' if snap['key_configured'] else '未配置'}",
        "",
        "# 环境变量(SUOTU_*/AI_*;敏感名一律打码)",
    ]
    for name in sorted(os.environ):
        if not (name.startswith("SUOTU_") or name.startswith("AI_")):
            continue
        value = _MASKED if _SENSITIVE_NAME.search(name) else os.environ[name]
        lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def _error_stats() -> str:
    """错误统计:近 100 行 error.log 的异常类型计数(无错误如实写)。"""
    lines = tail_lines(logging_setup.log_path("error"), _ERROR_STAT_LINES)
    counts: Counter[str] = Counter()
    for ln in lines:
        for m in _EXC_TYPE.finditer(ln):
            counts[m.group(1)] += 1
    out = [f"error.log 近 {len(lines)} 行异常类型计数:"]
    if counts:
        out += [f"  {name}: {cnt}" for name, cnt in counts.most_common()]
    else:
        out.append("  (无异常记录)")
    return "\n".join(out) + "\n"


def _audit_status() -> str:
    """审计链状态:全链校验结果 + 最新 entry_hash(证据链完整性一眼可见)。"""
    conn = db.connect()
    try:
        ok, msg = db.verify_audit(conn)
        last = conn.execute(
            "SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    out = [f"chain_ok: {ok}", f"verify: {msg}"]
    if last:
        out.append(f"last_id: {last['id']}")
        out.append(f"last_entry_hash: {last['entry_hash']}")
    return "\n".join(out) + "\n"


def build_bundle(actor: str) -> bytes:
    """组装诊断包 zip(内存,≤500 行/文件,体积可控),并把生成动作写审计。

    actor:下载人登录用户名(审计锚人)。返回 zip 字节。
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for kind, filename in logging_setup.LOG_FILES.items():
            lines = tail_lines(logging_setup.log_path(kind), _BUNDLE_TAIL)
            z.writestr(f"logs/{filename}", "\n".join(lines) + "\n")
        z.writestr("version.txt", _version_info())
        z.writestr("config_sanitized.txt", _sanitized_config())
        z.writestr("error_stats.txt", _error_stats())
        z.writestr("audit_status.txt", _audit_status())
    payload = buf.getvalue()

    # 生成动作写审计哈希链(case_id='system',与 auth 审计同惯例);
    # detail 只记事实(谁、包大小),不含日志内容
    conn = db.connect()
    try:
        with conn:
            db.append_audit(conn, "system", actor=actor,
                            action="diagnostics_bundle", scope="system",
                            detail={"size_bytes": len(payload),
                                    "log_tail_lines": _BUNDLE_TAIL})
    finally:
        conn.close()
    logging_setup.app_logger().info(
        "诊断包已生成 actor=%s size=%dB", actor, len(payload))
    return payload


@router.post("/diagnostics/bundle")
def diagnostics_bundle(actor: str = Depends(auth.current_username)):
    """一键诊断包:日志尾部 + 版本 + 脱敏配置 + 错误统计 + 审计链状态(zip)。

    key/口令一律打码(只报「已配置/未配置」);生成动作写审计哈希链。
    """
    payload = build_bundle(actor)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=payload, media_type="application/zip",
        headers={"Content-Disposition":
                 f'attachment; filename="suotu_diagnostics_{ts}.zip"'})
