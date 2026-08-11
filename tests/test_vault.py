"""金库契约:单趟流式入库、内容寻址、读前校验(篡改 → 抛错)。"""
from __future__ import annotations

import hashlib
import io
import os

import pytest

from backend.app import vault


def test_store_and_verify(data_dir):
    payload = b"hello suotu\n" * 1000
    sha, rel = vault.store(io.BytesIO(payload))
    assert sha == hashlib.sha256(payload).hexdigest()
    assert rel == f"{sha[:2]}/{sha}"
    assert vault.verify(rel, sha).is_file()
    # 入库置只读位
    mode = os.stat(vault.locate(rel)).st_mode
    assert not (mode & 0o200)


def test_store_dedup(data_dir):
    payload = b"same content"
    sha1, rel1 = vault.store(io.BytesIO(payload))
    sha2, rel2 = vault.store(io.BytesIO(payload))
    assert (sha1, rel1) == (sha2, rel2)              # 内容寻址去重


def test_verify_tampered_raises(data_dir):
    """篡改金库文件 → 读前校验哈希失配 → VaultIntegrityError,带病不读。"""
    sha, rel = vault.store(io.BytesIO(b"original bytes"))
    path = vault.locate(rel)
    os.chmod(path, 0o666)                            # 解除只读位再篡改
    path.write_bytes(b"tampered bytes!")
    with pytest.raises(vault.VaultIntegrityError):
        vault.verify(rel, sha)


def test_verify_missing_raises(data_dir):
    with pytest.raises(vault.VaultIntegrityError):
        vault.verify("ab/" + "0" * 64, "0" * 64)


def test_store_streaming_constant_memory(data_dir):
    """大于 1MB 块的流也能单趟入库(抽查流式通道,内存恒定在实现层保证)。"""
    payload = os.urandom(3 * 1024 * 1024 + 7)        # 3MB+,跨多个 1MB 块
    sha, rel = vault.store(io.BytesIO(payload))
    assert sha == hashlib.sha256(payload).hexdigest()
    assert vault.locate(rel).stat().st_size == len(payload)
