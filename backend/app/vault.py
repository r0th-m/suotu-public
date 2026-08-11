"""原文只读金库(data/vault/<sha256前2位>/<sha256>)。

铁律落点:
- 单趟流式:1MB 块边算 SHA256 边写临时文件,算完按内容寻址路径落位,
  内存峰值恒定,与文件大小无关;
- 入库后置只读位;同哈希内容寻址去重;
- 读前校验:任何消费方读金库前必须 verify() 重算哈希,失配抛
  VaultIntegrityError,绝不带病读取。
"""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import BinaryIO

from . import config

_CHUNK = 1024 * 1024  # 1MB 流式块


class VaultIntegrityError(Exception):
    """金库读前校验失败:实测哈希与登记哈希失配(文件被篡改/损坏)。"""


def store(stream: BinaryIO, vault_root: Path | None = None) -> tuple[str, str]:
    """流式写入金库,返回 (sha256, vault相对路径)。同哈希去重。"""
    root = vault_root or config.vault_dir()
    root.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    tmp = root / ".incoming" / uuid.uuid4().hex
    tmp.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tmp.open("wb") as fout:
            while chunk := stream.read(_CHUNK):
                h.update(chunk)
                fout.write(chunk)
        sha = h.hexdigest()
        rel = f"{sha[:2]}/{sha}"
        dst = root / rel
        if dst.exists():
            return sha, rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, dst)
        os.chmod(dst, 0o444)  # 只读化(Windows 上置只读属性)
        return sha, rel
    finally:
        tmp.unlink(missing_ok=True)


def locate(vault_rel: str, vault_root: Path | None = None) -> Path:
    return (vault_root or config.vault_dir()) / vault_rel


def verify(vault_rel: str, sha256: str,
           vault_root: Path | None = None) -> Path:
    """读前校验:流式重算 SHA256 与登记值比对,失配抛错;通过则返回文件路径。"""
    path = locate(vault_rel, vault_root)
    if not path.is_file():
        raise VaultIntegrityError(f"金库文件缺失: {vault_rel}")
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    if h.hexdigest() != sha256:
        raise VaultIntegrityError(
            f"金库哈希失配: {vault_rel} 登记 {sha256[:12]}… 实测 {h.hexdigest()[:12]}…")
    return path
