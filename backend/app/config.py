"""索图全局配置:数据目录定位与 DuckDB 资源上限。

- 数据目录由环境变量 SUOTU_DATA_DIR 指定,默认 <仓库根>/data;
  测试用 monkeypatch 该环境变量做目录隔离(见 tests/conftest.py);
- 配置全部走函数实时读取,不做模块级缓存——测试改环境变量立即生效;
- DuckDB memory_limit 默认 1GB(SUOTU_DUCK_MEMORY_LIMIT 可覆盖),硬上限防 OOM。
"""
from __future__ import annotations

import os
from pathlib import Path

# 仓库根 = backend/app/config.py 向上三级
REPO_ROOT = Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    """案件数据根目录(case.db / log.duckdb / vault/ 都在其下)。"""
    return Path(os.environ.get("SUOTU_DATA_DIR", str(REPO_ROOT / "data")))


def case_db_path() -> Path:
    return data_dir() / "case.db"


def duck_path() -> Path:
    return data_dir() / "log.duckdb"


def vault_dir() -> Path:
    return data_dir() / "vault"


def auth_db_path() -> Path:
    """账号库(M4 认证):用户跨案件,独立文件,不随案件封存/删除走。"""
    return data_dir() / "auth.db"


def exports_dir() -> Path:
    """封存包出口(M4):data/exports/<case_id>_<UTC>.zip。"""
    return data_dir() / "exports"


def kb_dir() -> Path:
    """知识库目录(指纹库等,数据驱动内容,随仓库走不随数据目录走)。"""
    return Path(__file__).resolve().parents[1] / "kb"


def duck_memory_limit() -> str:
    return os.environ.get("SUOTU_DUCK_MEMORY_LIMIT", "1GB")


def fingerprint_threshold() -> float:
    """指纹探测置信度阈值;低于阈值如实报 unknown 并建议 raw_t0。"""
    return float(os.environ.get("SUOTU_FP_THRESHOLD", "0.5"))
