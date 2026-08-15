"""自定义规则治理(data/rules_custom/*.yaml,随 SUOTU_DATA_DIR;§1 判断权归人)。

治理链照 formatdesc 模式落地(简化版):
- 状态:draft/review/enable;**只有 enable 进扫描**,draft/review 在规则
  清单里如实标状态但不参与扫描;
- 创建恒 draft(外部内容永不自动启用);状态切换/内容更新/删除全留审计;
- 内置规则(backend/rules/)永只读:自定义 id 撞内置一律 409 拒绝,
  删除只许删自定义(内置 id 不在本目录,自然 404);
- 保存即校验:签名/统计两类同一 schema 闸(rules.validate_rule /
  validate_stat_rule),坏 YAML/坏参数一律 422 如实报错,不静默落盘;
- 写盘走 yaml.safe_dump 规范化(原文注释不保留,如实说明);
- 审计 case_id 恒 "rules_custom"——规则是全局数据资产,不属于单个案件。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import yaml

from . import config, db, rules
from .rules import RuleError  # noqa: F401(再导出,API 层统一捕获)

# 审计落点:规则是全局资产,无案件归属;case_id 用固定串占位(审计
# 哈希链照走,verify_audit 可全链校验)——同 formatdesc.AUDIT_CASE 纪律。
AUDIT_CASE = "rules_custom"

RULE_STATUSES = {"draft", "review", "enable"}
_KINDS = {"signature", "stat"}


def custom_dir() -> Path:
    """自定义规则目录:data/rules_custom/(随 SUOTU_DATA_DIR,测试隔离)。"""
    return config.data_dir() / "rules_custom"


def _file(rule_id: str) -> Path:
    return custom_dir() / f"{rule_id}.yaml"


def _parse(yaml_text: str, *, src_name: str = "<custom>") -> tuple[str, str, dict]:
    """YAML 全文 → (kind, status, 已校验规则 dict);坏输入一律 422。

    类型判定:含 operator 键 → 统计规则;含 match 键 → 签名规则;都没有 →
    422 如实说明。status 同级字段先剥掉再过 schema(rules schema 不含它)。
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise RuleError(f"{src_name}: YAML 解析失败: {e}", status=422)
    if not isinstance(doc, dict):
        raise RuleError(f"{src_name}: 规则须为 YAML 映射", status=422)
    status = doc.get("status", "draft")
    if status not in RULE_STATUSES:
        raise RuleError(
            f"{src_name}: status 须为 {sorted(RULE_STATUSES)} 之一", status=422)
    body = {k: v for k, v in doc.items() if k != "status"}
    try:
        if "operator" in body:
            return "stat", status, rules.validate_stat_rule(
                body, src_name=src_name)
        if "match" in body:
            return "signature", status, rules.validate_rule(
                body, src_name=src_name)
    except RuleError as e:
        raise RuleError(str(e), status=422) from e
    raise RuleError(
        f"{src_name}: 无法判定规则类型——含 operator 为统计规则,"
        "含 match 为签名规则", status=422)


def _write(rule_id: str, doc: dict) -> None:
    """规范化落盘(safe_dump,allow_unicode;原文注释不保留,如实说明)。"""
    custom_dir().mkdir(parents=True, exist_ok=True)
    _file(rule_id).write_text(
        yaml.safe_dump(doc, allow_unicode=True, sort_keys=False),
        encoding="utf-8")


# ------------------------------------------------------------------ CRUD + 状态

def create_rule(conn: sqlite3.Connection, yaml_text: str,
                actor: str = "system") -> dict:
    """新建自定义规则:schema 校验 → 恒 draft 落盘(永不自动启用)。

    撞内置 id → 409(内置永只读,不可被同名覆盖);撞已有自定义 id → 409。
    """
    kind, status, rule = _parse(yaml_text)
    rid = rule["id"]
    if rules.find_rule(rid) is not None:
        raise RuleError(f"规则 id 与内置规则冲突: {rid}"
                        "(内置规则永只读,不可覆盖)", status=409)
    if _file(rid).is_file():
        raise RuleError(f"自定义规则已存在(撞 id): {rid}", status=409)
    doc = yaml.safe_load(yaml_text)
    doc["status"] = "draft"                          # 创建恒 draft,不商量
    _write(rid, doc)
    with conn:
        db.append_audit(conn, AUDIT_CASE, action="rule_custom_create",
                        scope=rid, actor=actor,
                        detail={"id": rid, "kind": kind,
                                "forced_draft": status != "draft"})
    return {"id": rid, "kind": kind, "status": "draft",
            "note": "创建即 draft:状态转 enable 后才进扫描(判断权归人)"}


def list_custom() -> list[dict]:
    """自定义规则清单(含状态);坏文件如实标 status=broken(零静默)。"""
    out: list[dict] = []
    d = custom_dir()
    if not d.is_dir():
        return out
    for path in sorted(d.glob("*.yaml")):
        try:
            kind, status, rule = _parse(path.read_text(encoding="utf-8"),
                                        src_name=path.name)
            out.append({"id": rule["id"], "kind": kind,
                        "title": rule["title"], "severity": rule["severity"],
                        "status": status,
                        "operator": rule.get("operator"),
                        "note": rule.get("note")})
        except RuleError as e:
            out.append({"id": path.stem, "kind": None, "status": "broken",
                        "error": str(e)})
    return out


def get_rule(rule_id: str) -> dict:
    """单个自定义规则详情(校验后视图 + 落盘 YAML 原文)。"""
    path = _file(rule_id)
    if not path.is_file():
        raise RuleError(f"自定义规则不存在: {rule_id}", status=404)
    kind, status, rule = _parse(path.read_text(encoding="utf-8"),
                                src_name=path.name)
    return {**rule, "kind": kind, "status": status,
            "yaml_text": path.read_text(encoding="utf-8")}


def update_rule(conn: sqlite3.Connection, rule_id: str,
                yaml_text: str | None = None, status: str | None = None,
                actor: str = "system") -> dict:
    """更新自定义规则:内容(yaml_text,重过 schema 闸)和/或状态(status)。

    规则 id 不可变(要换 id 请删除后新建);状态只许 draft/review/enable
    三值(如实切换,不限制方向——内容每次变更都已过 schema 闸)。
    """
    path = _file(rule_id)
    if not path.is_file():
        raise RuleError(f"自定义规则不存在: {rule_id}", status=404)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    cur_status = doc.get("status", "draft")
    changed: dict = {"id": rule_id}
    if yaml_text is not None:
        kind, _, rule = _parse(yaml_text)
        if rule["id"] != rule_id:
            raise RuleError(f"规则 id 不可变({rule_id} → {rule['id']});"
                            "要换 id 请删除后新建", status=422)
        doc = yaml.safe_load(yaml_text)
        changed["content"] = True
        changed["kind"] = kind
    if status is not None:
        if status not in RULE_STATUSES:
            raise RuleError(f"status 须为 {sorted(RULE_STATUSES)} 之一",
                            status=422)
        changed["status"] = f"{cur_status} → {status}"
        doc["status"] = status
    else:
        doc["status"] = cur_status                   # 内容更新不动状态
    _write(rule_id, doc)
    with conn:
        db.append_audit(conn, AUDIT_CASE, action="rule_custom_update",
                        scope=rule_id, actor=actor, detail=changed)
    return {"id": rule_id, "status": doc["status"]}


def delete_rule(conn: sqlite3.Connection, rule_id: str,
                actor: str = "system") -> dict:
    """删除:只许删自定义(内置 id 不在本目录 → 404);留痕。"""
    path = _file(rule_id)
    if not path.is_file():
        raise RuleError(f"自定义规则不存在: {rule_id}"
                        "(内置规则只读,不可删除)", status=404)
    path.unlink()
    with conn:
        db.append_audit(conn, AUDIT_CASE, action="rule_custom_delete",
                        scope=rule_id, actor=actor, detail={"id": rule_id})
    return {"id": rule_id, "deleted": True}


# ------------------------------------------------------------------ 扫描侧加载

def load_enabled() -> tuple[list[dict], list[dict]]:
    """enable 状态的自定义规则 → (签名, 统计) 已校验列表(run_rules 调用)。

    与内置规则同一纪律:加载即校验,enable 的坏文件 RuleError 不静默
    (draft/review 不进扫描,坏了也不拦扫描,清单里如实标 broken)。
    统计规则的排除 KB 同步加载校验,token 挂 _tokens(同 load_stat_rules)。
    """
    sig: list[dict] = []
    stat: list[dict] = []
    d = custom_dir()
    if not d.is_dir():
        return sig, stat
    for path in sorted(d.glob("*.yaml")):
        kind, status, rule = _parse(path.read_text(encoding="utf-8"),
                                    src_name=path.name)
        if status != "enable":
            continue
        if kind == "stat":
            if rule.get("exclude_kb"):
                rule["_tokens"] = rules.load_kb(rule["exclude_kb"])["tokens"]
            else:
                rule["_tokens"] = []
            stat.append(rule)
        else:
            sig.append(rule)
    return sig, stat
