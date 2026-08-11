"""格式注册表:find_format / list_formats / detect(指纹探测建议)。

解析器是代码(对 spec 写),指纹库是数据(backend/kb/fingerprints.yaml);
detect 只给建议,永不静默确认(§4 入库三段式:人确认或手选才生效)。

M4:format_id = "desc:<name>" 走描述文件引擎(descriptor.py)——
仅 status==enable 的描述文件放行;draft/review → None(判断权归人,
confirm 路径会如实区分「未启用」与「未知」,见 ingest.confirm_source)。
指纹探测本期不掺和描述文件(探测只建议内置格式,描述文件人选手动)。
"""
from __future__ import annotations

from pathlib import Path

from . import apache_common, descriptor, iis_w3c, nginx_combined, raw_t0
from .base import LineOutcome, ParseError, ParseReport  # noqa: F401(再导出)
from .descriptor import FormatDescError  # noqa: F401(再导出)

_MODULES = {
    m.FORMAT_ID: m
    for m in (nginx_combined, apache_common, iis_w3c, raw_t0)
}

DESC_PREFIX = "desc:"


def find_format(format_id: str):
    """按 format_id 取解析器(模块或 CompiledDesc);未知/未启用 → None(不猜)。

    desc:<name> 的描述文件损坏时抛 FormatDescError(加载即校验,不带病解析)。
    """
    if format_id.startswith(DESC_PREFIX):
        return descriptor.find_enabled(format_id[len(DESC_PREFIX):])
    return _MODULES.get(format_id)


def desc_status(name: str) -> str | None:
    """desc:<name> 的治理状态(draft/review/enable/broken/None=不存在)。

    confirm 用它区分「描述文件未启用」(422 如实)与「未知格式」(400)。
    """
    return descriptor.desc_status(name)


def list_formats() -> list[dict]:
    """可选格式清单(人确认/手选界面用):内置 + enable 状态的描述文件。"""
    return ([{"format_id": m.FORMAT_ID, "name": m.NAME}
             for m in _MODULES.values()]
            + descriptor.list_enabled())


def detect(path: Path, sample_lines: int = 50) -> dict:
    """指纹探测(数据驱动,见 fingerprint.py);只给建议不确认。"""
    from .. import fingerprint  # 延迟导入,避免环
    return fingerprint.detect(path, sample_lines=sample_lines)
