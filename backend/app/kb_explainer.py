"""KB 解释器(M3,§8):常见 path/UA/状态码的确定性解释,长尾才给 AI。

纪律(同主机取证平台 KB 纪律):
- 数据文件 backend/kb/web_explain.yaml,人可编辑;**加载即校验**——
  坏 YAML/坏结构加载即 KBError 暴露,不静默跳过;
- 命中 → {covered:true, text};未覆盖 → {covered:false},**不硬解释**
  (宁缺勿滥:编一个看似合理的解释比没有解释更糟);
- path/ua 匹配语义:值小写化后子串包含(与 common_uas.yaml 同一实测结论);
  status 为精确三位数字等值。
"""
from __future__ import annotations

from pathlib import Path

import yaml

KB_FILE = Path(__file__).resolve().parents[1] / "kb" / "web_explain.yaml"

KINDS = {"path", "ua", "status"}


class KBError(Exception):
    """KB 加载/查询失败,message 直给调用方。"""


def load_explain_kb(path: Path | None = None) -> dict:
    """加载并校验解释 KB;任何损坏 → KBError(加载即暴露,不静默)。

    结构:{id, title, paths:[{match,text}], uas:[{match,text}],
    statuses:{三位数字: text}};三段至少一段非空。
    """
    path = path or KB_FILE
    if not path.is_file():
        raise KBError(f"KB 不存在: {path.name}")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise KBError(f"{path.name}: YAML 解析失败: {e}")
    if not isinstance(doc, dict):
        raise KBError(f"{path.name}: KB 须为 YAML 映射")
    errors: list[str] = []
    for f in ("id", "title"):
        if not isinstance(doc.get(f), str) or not doc[f].strip():
            errors.append(f"缺必填字段 {f}(非空字符串)")
    out: dict = {"id": doc.get("id"), "title": doc.get("title"),
                 "paths": [], "uas": [], "statuses": {}}
    for section, key in (("paths", "paths"), ("uas", "uas")):
        entries = doc.get(key) or []
        if not isinstance(entries, list):
            errors.append(f"{key} 须为列表")
            continue
        for i, e in enumerate(entries):
            if not isinstance(e, dict) or \
                    not isinstance(e.get("match"), str) or not e["match"].strip() or \
                    not isinstance(e.get("text"), str) or not e["text"].strip():
                errors.append(f"{key}[{i}] 须含非空 match 与 text")
                continue
            out[section].append({"match": e["match"].strip().lower(),
                                 "text": e["text"].strip()})
    statuses = doc.get("statuses") or {}
    if not isinstance(statuses, dict):
        errors.append("statuses 须为映射(三位数字 → 解释)")
    else:
        for k, v in statuses.items():
            ks = str(k)
            if len(ks) != 3 or not ks.isdigit():
                errors.append(f"statuses 键须为三位数字: {k!r}")
                continue
            if not isinstance(v, str) or not v.strip():
                errors.append(f"statuses.{ks} 解释须为非空字符串")
                continue
            out["statuses"][ks] = v.strip()
    if errors:
        raise KBError(f"{path.name}: " + ";".join(errors))
    if not out["paths"] and not out["uas"] and not out["statuses"]:
        raise KBError(f"{path.name}: paths/uas/statuses 三段全空,KB 无内容")
    return out


def explain(kind: str, value: str) -> dict:
    """确定性解释:命中 → {covered:true,text};未覆盖 → {covered:false}。

    kind 须为 path|ua|status;value 空串如实未覆盖。每次实时加载
    (改 YAML 即生效),KB 损坏 → KBError 暴露。
    """
    if kind not in KINDS:
        raise KBError(f"未知 kind: {kind!r}(允许: {sorted(KINDS)})")
    value = (value or "").strip()
    if not value:
        return {"kind": kind, "value": value, "covered": False}
    kb = load_explain_kb()
    if kind == "status":
        text = kb["statuses"].get(value)
        return {"kind": kind, "value": value,
                "covered": text is not None, "text": text}
    section = "paths" if kind == "path" else "uas"
    low = value.lower()
    for entry in kb[section]:
        if entry["match"] in low:
            return {"kind": kind, "value": value, "covered": True,
                    "text": entry["text"]}
    return {"kind": kind, "value": value, "covered": False}
