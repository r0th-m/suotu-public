"""运行日志系统(排障用,移植自主机取证平台 v1.2.0)——与审计哈希链严格分离。

设计红线:
- 审计哈希链(audit_log)记**人的判断**,是证据链;本模块记**系统心跳**,是排障日志。
  两者互不混入:运行日志绝不写 audit_log,审计也绝不落到这三个文件;
- 三类日志分文件落 data/logs/:
    app.log       —— 运行:启动/关闭、摄取/解析/规则扫描/封存摘要、AI 调用摘要、
                      认证事件(登录成功/失败/锁定);
    error.log     —— 错误:异常 + 完整堆栈 + 请求上下文(path/user);
    operation.log —— 请求级操作:方法/路径/用户名/状态码/耗时(main.py 中间件统一记);
- 标准库 logging + RotatingFileHandler(默认 10MB×5),级别 SUOTU_LOG_LEVEL(默认 INFO),
  UTF-8,格式含时间戳/级别/模块;
- 敏感信息红线:key/口令/token **永不进日志**——SensitiveFormatter 对格式化后的
  整行统一打码(Authorization/Cookie/api_key/password/token/Bearer/sk-* 值),
  异常堆栈文本同样过打码;
- AI 调用日志只记元信息(模型/tokens/耗时/调用者),**不记 prompt/回答内容**
  (可能含案件敏感)。

测试适配:setup_logging() 幂等可重入——重复调用先摘旧 handler 再按当前
config.data_dir() 重新绑定(SUOTU_DATA_DIR 改了再调一次即指向新目录)。
"""
from __future__ import annotations

import logging
import os
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import config

# 三个专用 logger 名(与 audit 审计链无关,propagate=False 不混入 root/uvicorn)
APP_LOG = "suotu.app"
ERROR_LOG = "suotu.error"
OP_LOG = "suotu.operation"

LOG_FILES = {"app": "app.log", "error": "error.log", "operation": "operation.log"}

_DEFAULT_MAX_BYTES = 10 * 1024 * 1024     # 10MB
_DEFAULT_BACKUP_COUNT = 5

# ---- 敏感值打码模式(对格式化后的整行生效,堆栈文本一并覆盖) ----
_MASK = "***"
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # HTTP Bearer 头值(先打:否则 authorization: Bearer xxx 的 key=value
    # 模式会把 Bearer 当值吃掉,把真 token 留在后面)
    (re.compile(r"(?i)\bBearer\s+\S+"), f"Bearer {_MASK}"),
    # key=value / key: value 形式的敏感字段(引号可选)
    (re.compile(
        r"(?i)\b(authorization|cookie|set-cookie|api[_-]?key|password|passwd"
        r"|token|secret)(\s*[:=]\s*)([\"']?)[^\s,\"'\]]+"),
     lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_MASK}"),
    # sk- 开头的 API key 形态(DeepSeek/OpenAI 等)
    (re.compile(r"(?i)\bsk-[A-Za-z0-9_\-]{6,}"), f"sk-{_MASK}"),
]


def _redact(text: str) -> str:
    """对一行日志文本做敏感值打码(幂等,普通文本原样返回)。"""
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


class SensitiveFormatter(logging.Formatter):
    """在格式化结果上统一打码:消息、参数、异常堆栈一律过 _redact。"""

    def format(self, record: logging.LogRecord) -> str:
        return _redact(super().format(record))


def log_dir() -> Path:
    """日志目录:data/logs/(随 SUOTU_DATA_DIR 动态定位)。"""
    return config.data_dir() / "logs"


def log_path(kind: str) -> Path:
    """三类日志文件路径;kind 须为 app|error|operation。"""
    if kind not in LOG_FILES:
        raise ValueError(f"未知日志类别: {kind}(须为 {sorted(LOG_FILES)} 之一)")
    return log_dir() / LOG_FILES[kind]


def _level() -> int:
    return getattr(logging, os.environ.get("SUOTU_LOG_LEVEL", "INFO").upper(),
                   logging.INFO)


def setup_logging(max_bytes: int = _DEFAULT_MAX_BYTES,
                  backup_count: int = _DEFAULT_BACKUP_COUNT) -> Path:
    """绑定三个文件 handler(幂等可重入:先摘旧 handler 再按当前数据目录重绑)。

    max_bytes/backup_count 可覆盖(测试用小值验证轮转);默认 10MB×5。
    返回日志目录。
    """
    out = log_dir()
    out.mkdir(parents=True, exist_ok=True)
    fmt = SensitiveFormatter(
        "%(asctime)s %(levelname)s %(name)s %(module)s: %(message)s")
    for name, filename in ((APP_LOG, LOG_FILES["app"]),
                           (ERROR_LOG, LOG_FILES["error"]),
                           (OP_LOG, LOG_FILES["operation"])):
        logger = logging.getLogger(name)
        for h in list(logger.handlers):          # 重入:摘掉指向旧目录的 handler
            logger.removeHandler(h)
            h.close()
        handler = RotatingFileHandler(out / filename, maxBytes=max_bytes,
                                      backupCount=backup_count, encoding="utf-8")
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        logger.setLevel(_level())
        logger.propagate = False                 # 不混入 root/uvicorn 日志
    return out


def app_logger() -> logging.Logger:
    return logging.getLogger(APP_LOG)


def error_logger() -> logging.Logger:
    return logging.getLogger(ERROR_LOG)


def op_logger() -> logging.Logger:
    return logging.getLogger(OP_LOG)
