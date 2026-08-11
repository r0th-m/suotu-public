"""主机取证平台实体互查(M4,SUOTU_DESIGN §9 实体桥 v2,**只读**)。

索图侧持有主机取证平台凭据(env/.env:TREE_COURT_URL / TREE_COURT_USER /
TREE_COURT_PASS——**跨平台凭据,值不进 git**,.env 已 gitignore),
调主机取证平台 API:登录 → 逐案件实体检索(raw_value 子串,q 参数)按主机聚合。

诚实边界:
- 主机取证平台不可达/未配置凭据/认证失败 → available=false + reason 如实,
  绝不报错页,绝不装「查无结果」;
- 只读互查:对主机取证平台只有 login + GET,不写任何东西;
- 走 stdlib urllib(零新依赖);检索用 q 子串而非 canonical_key 精确——
  两端 canonical 规则虽同源,子串匹配对值形态差异更稳,命中数少时
  人可一眼甄别(响应逐条带 raw_value/canonical_key 供人对)。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from . import ai as _ai   # 复用 .env 读取(key 唯一落点),不引第二份解析器

_TIMEOUT = 5.0
_PER_CASE_LIMIT = 200


def _conf(key: str, default: str | None = None) -> str | None:
    """配置读取:环境变量优先,.env 兜底(每次现读,测试可 monkeypatch)。"""
    import os
    val = os.environ.get(key)
    if val:
        return val
    return _ai._read_env_file().get(key, default)


def _http(req: urllib.request.Request) -> tuple[dict, str | None]:
    """发请求 → (JSON body, Set-Cookie)。网络/协议异常原样上抛给调用方分类。"""
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        return body, resp.headers.get("Set-Cookie")


def _get(base: str, path: str, cookie: str) -> dict:
    req = urllib.request.Request(base + path, method="GET")
    req.add_header("Cookie", cookie)
    body, _ = _http(req)
    return body


def query_entities(value: str) -> dict:
    """按值互查主机取证平台实体 → {available, source_platform, results|reason}。

    results 逐条 {case, case_id, host, host_id, entity, canonical_key, count}
    (同案件同主机同值的出现记录聚合计数)。
    """
    base = (_conf("TREE_COURT_URL", "http://127.0.0.1:8000") or "").rstrip("/")
    user, pwd = _conf("TREE_COURT_USER"), _conf("TREE_COURT_PASS")
    out: dict = {"available": False, "source_platform": "treecourt",
                 "results": []}
    if not user or not pwd:
        out["reason"] = ("未配置主机取证平台凭据(TREE_COURT_USER/TREE_COURT_PASS),"
                         "互查不可用;配置在 .env(跨平台凭据,值不进 git)")
        return out

    try:
        # ① 登录拿会话 Cookie(主机取证平台有认证,全局认证闸覆盖业务端点)
        req = urllib.request.Request(
            base + "/auth/login", method="POST",
            data=json.dumps({"username": user, "password": pwd}).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        _, set_cookie = _http(req)
        if not set_cookie:
            out["reason"] = "主机取证平台登录响应无会话 Cookie(版本不符?)"
            return out
        cookie = set_cookie.split(";", 1)[0]

        # ② 逐案件实体检索(raw_value 子串)按 (案件, 主机, 值) 聚合
        cases = _get(base, "/cases", cookie).get("cases", [])
        q = urllib.parse.quote(value, safe="")
        for c in cases:
            cid, cname = c.get("id"), c.get("name")
            hosts = {h["id"]: h.get("hostname") or h["id"]
                     for h in _get(base, f"/cases/{cid}/hosts", cookie
                                   ).get("hosts", [])}
            res = _get(base, f"/cases/{cid}/entities/search"
                             f"?q={q}&limit={_PER_CASE_LIMIT}", cookie)
            groups: dict[tuple, dict] = {}
            for item in res.get("items", []):
                key = (cid, item.get("host_id"), item.get("raw_value"))
                g = groups.setdefault(key, {
                    "case": cname, "case_id": cid,
                    "host": hosts.get(item.get("host_id"),
                                      item.get("host_id") or "未知主机"),
                    "host_id": item.get("host_id"),
                    "entity": item.get("raw_value"),
                    "canonical_key": item.get("canonical_key"),
                    "count": 0})
                g["count"] += 1
            out["results"].extend(groups.values())
        out["available"] = True
        out.pop("reason", None)
        return out
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            out["reason"] = f"主机取证平台认证失败(HTTP {e.code}):凭据错或会话被拒"
        else:
            out["reason"] = f"主机取证平台响应异常(HTTP {e.code})"
        return out
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        out["reason"] = f"主机取证平台不可达({base}): {getattr(e, 'reason', e)}"
        return out
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError) as e:
        out["reason"] = f"主机取证平台响应解析失败(版本不符?): {e}"
        return out


__all__ = ["query_entities"]
