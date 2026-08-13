"""MCP 调用链的属主传递(contextvars;网关层绑定,工具层读取)。"""
from __future__ import annotations

import contextvars

_user: contextvars.ContextVar[str] = contextvars.ContextVar(
    "mcp_user", default="unknown")


def bind_user(username: str):
    return _user.set(username)


def unbind(token) -> None:
    _user.reset(token)


def current_user() -> str:
    return _user.get()
