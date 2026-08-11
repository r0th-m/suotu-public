"""格式描述文件治理链 + AI 辅助起草(SUOTU_DESIGN §4.3/§4.4,判断权归人)。

状态机:draft → review → enable(只允许向前);enable 可 disable 回
draft(留痕)。**外部导入一律 draft,永不自动启用**——社区导入与
AI 起草同此,人审走 :transition 才生效。仅 draft 可删。

AI 辅助起草(§4.4):从金库抽头 N 行 → AI 提议 kind/line_regex/field_map/
ts_formats → 系统按 schema 校验 AI 输出(不合格如实报 ai_invalid,不落盘)
→ 返回草稿 YAML **文本**(不落盘!人审编辑后走 :import 进治理链)。
AI 草稿 ≠ 可用格式,文案写死「人审后才生效」。

存储:backend/formats/desc/*.yaml(SUOTU_FORMATDESC_DIR 可覆盖,测试隔离);
写盘走 yaml.safe_dump 规范化落盘(导入原文的注释不保留,如实说明)。
全写操作(import/transition/delete)与 AI 起草(成功/失败)写审计哈希链;
审计 case_id 恒 "formatdesc"——描述文件是全局数据资产,不属于单个案件。
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import ai, db, vault
from .formats import descriptor
from .formats.descriptor import FormatDescError  # noqa: F401(再导出)

# 审计落点:描述文件是全局资产,无案件归属;case_id 用固定串占位(审计
# 哈希链照走,verify_audit 可全链校验)。
AUDIT_CASE = "formatdesc"

# 状态机:只允许向前;enable 可 disable 回 draft(留痕)。
_TRANSITIONS = {("draft", "review"), ("review", "enable"), ("enable", "draft")}

# AI 起草的系统提示纪律(§4.4:AI 干体力活,判断权归人)
SYSTEM_PROMPT_DRAFT = (
    "你是日志格式描述文件的起草助手。用户会给你一份日志的头若干行样本"
    "(带行号),请推断其行结构并输出一个格式描述 JSON。\n"
    "纪律(必须严格遵守):\n"
    "1. 只输出一个 JSON 对象,不要任何其他文字、不要代码围栏:\n"
    '{"kind":"regex|json|csv","line_regex":"...","csv":{"delimiter":",",'
    '"header":true},"field_map":{"源字段":"归一字段"},'
    '"ts_formats":["%Y-%m-%d %H:%M:%S"],"multiline":{"start_regex":"..."}}\n'
    "2. kind=regex 时 line_regex 必填:命名分组 (?P<名>...) 必须覆盖每行"
    "完整结构(从头锚到尾),不许只匹配行首一段。\n"
    "3. field_map 的值只能用词表内归一字段:src_ip/method/path/query/"
    "status/bytes/ua/referer(web 族)、actor/action/object/result/detail"
    "(审计族)、level/logger/message/exception(通用族);行内时间字段"
    "映射到保留值 ts_raw,且必须有且仅有一个。\n"
    "4. 不许编造样本中不存在的字段;样本里看不清的字段不要映射"
    "(未映射字段系统会自动进 extras,不丢数据)。\n"
    "5. 样本若含多行块(如异常堆栈),给 multiline.start_regex(事件起始行"
    "特征);纯单行日志不要给 multiline。\n"
    "6. ts_formats 给能解析样本时间串的 strptime 格式;不确定就给候选多个。"
)

# 草稿 YAML 的头注释(诚实边界写死:AI 草稿≠可用格式,人审后才生效)
_DRAFT_HEADER = (
    "# AI 起草草稿——AI 草稿≠可用格式,人审编辑后才生效(§4.4 判断权归人)\n"
    "# 使用前:① name 改为唯一小写连字符名;② 逐字段核对 field_map/line_regex;\n"
    "# ③ 走 POST /formatdesc:import 导入(恒 draft);④ 人审 :transition 至 enable\n"
)


class GovernanceError(Exception):
    """治理链业务校验失败(状态机违规/撞名/越权删除等),status 为 HTTP 语义。"""
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------ 读写底层

def _write_desc(spec: dict) -> Path:
    """规范化落盘(safe_dump,allow_unicode;导入原文的注释不保留)。"""
    d = descriptor.desc_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = descriptor.desc_path(spec["name"])
    path.write_text(yaml.safe_dump(spec, allow_unicode=True, sort_keys=False),
                    encoding="utf-8")
    return path


def _read_spec(name: str) -> dict:
    """读 spec(不存在 → GovernanceError 404;坏 → FormatDescError)。"""
    path = descriptor.desc_path(name)
    if not path.is_file():
        raise GovernanceError(f"描述文件不存在: {name}", status=404)
    return descriptor.load_desc_text(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ CRUD + 状态机

def import_desc(conn: sqlite3.Connection, yaml_text: str,
                actor: str = "system") -> dict:
    """导入 YAML 全文 → 恒 draft(外部导入永不自动启用,§4.3)。

    撞 name → 409;schema 不过 → FormatDescError(400);写盘 + 审计。
    """
    spec = descriptor.load_desc_text(yaml_text)      # 加载即校验
    name = spec["name"]
    if descriptor.desc_path(name).is_file():
        raise GovernanceError(f"描述文件已存在(撞 name): {name}", status=409)
    original_status = spec.get("status", "draft")
    spec["status"] = "draft"                          # 一律 draft,不商量
    spec.setdefault("title", name)
    _write_desc(spec)
    with conn:
        db.append_audit(conn, AUDIT_CASE, action="formatdesc_import",
                        scope=name, actor=actor,
                        detail={"name": name, "kind": spec["kind"],
                                "forced_draft": original_status != "draft"})
    return {"name": name, "format_id": f"desc:{name}", "status": "draft",
            "note": "导入即 draft:人审 :transition 至 enable 后才可用于解析"}


def list_descs() -> list[dict]:
    """描述文件清单(含状态);坏文件如实标 status=broken(零静默)。"""
    out: list[dict] = []
    d = descriptor.desc_dir()
    if not d.is_dir():
        return out
    for path in sorted(d.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            out.append({"name": path.stem, "status": "broken",
                        "error": f"YAML 解析失败: {e}"})
            continue
        if not isinstance(data, dict):
            out.append({"name": path.stem, "status": "broken",
                        "error": "顶层非映射"})
            continue
        out.append({
            "name": data.get("name") or path.stem,
            "format_id": f"desc:{data.get('name') or path.stem}",
            "title": data.get("title"),
            "kind": data.get("kind"),
            "status": data.get("status", "draft"),
            "note": data.get("note"),
        })
    return out


def get_desc(name: str) -> dict:
    """单个描述文件详情(spec + 落盘 YAML 原文)。"""
    spec = _read_spec(name)
    return {**spec, "format_id": f"desc:{name}",
            "yaml_text": descriptor.desc_path(name).read_text(encoding="utf-8")}


def export_desc(name: str) -> str:
    """导出落盘 YAML 原文(人可带走/社区交换)。"""
    path = descriptor.desc_path(name)
    if not path.is_file():
        raise GovernanceError(f"描述文件不存在: {name}", status=404)
    return path.read_text(encoding="utf-8")


def transition(conn: sqlite3.Connection, name: str, to: str,
               actor: str = "system") -> dict:
    """状态机流转:draft→review→enable 只许向前;enable→draft 为 disable。

    非法流转 → 409(如实说明当前状态与允许去向);全程审计留痕。
    """
    if to not in descriptor.STATUSES:
        raise GovernanceError(
            f"未知目标状态: {to!r}(允许: {sorted(descriptor.STATUSES)})")
    spec = _read_spec(name)
    current = spec.get("status", "draft")
    if (current, to) not in _TRANSITIONS:
        raise GovernanceError(
            f"非法流转: {current} → {to}(只允许 draft→review→enable 向前,"
            "或 enable→draft 禁用留痕)", status=409)
    spec["status"] = to
    _write_desc(spec)
    with conn:
        db.append_audit(conn, AUDIT_CASE, action="formatdesc_transition",
                        scope=name, actor=actor,
                        detail={"name": name, "from": current, "to": to})
    return {"name": name, "format_id": f"desc:{name}",
            "from": current, "status": to}


def delete_desc(conn: sqlite3.Connection, name: str,
                actor: str = "system") -> dict:
    """删除:仅 draft 可删(review/enable 须先退回 draft);留痕。"""
    spec = _read_spec(name)
    current = spec.get("status", "draft")
    if current != "draft":
        raise GovernanceError(
            f"仅 draft 可删(当前 {current};enable 可先 disable 回 draft)",
            status=409)
    descriptor.desc_path(name).unlink()
    with conn:
        db.append_audit(conn, AUDIT_CASE, action="formatdesc_delete",
                        scope=name, actor=actor, detail={"name": name})
    return {"name": name, "deleted": True}


# ------------------------------------------------------------------ 校验 + 试解析预览

def validate_text(yaml_text: str,
                  sample_lines: list[str] | None = None) -> dict:
    """YAML 全文 → schema 校验 + 抽样试解析预览;不写盘。

    返回 {ok, errors?, spec?, preview?};preview 复用真实引擎跑样本,
    坏行样本如实列出(与入库解析同一语义,不另搞一套)。
    """
    try:
        spec = descriptor.load_desc_text(yaml_text)
    except FormatDescError as e:
        return {"ok": False, "errors": [str(e)]}
    out: dict = {"ok": True,
                 "spec": {"name": spec["name"], "kind": spec["kind"],
                          "status": spec.get("status", "draft"),
                          "fields": sorted(set(spec["field_map"].values()))}}
    if sample_lines:
        engine = descriptor.CompiledDesc(spec)
        total = parsed = bad = skipped = 0
        events: list[dict] = []
        bad_samples: list[str] = []
        for o in engine.parse(sample_lines):
            total += 1
            if o.kind == "skip":
                skipped += 1
            elif o.kind == "bad":
                bad += 1
                if len(bad_samples) < 5:
                    bad_samples.append(f"L{o.line_no}: {o.reason or '不匹配'}")
            else:
                parsed += 1
                if len(events) < 5:
                    events.append({"line_no": o.line_no, "ts_raw": o.ts_raw,
                                   "norm": o.norm,
                                   "continuation_lines": o.continuation_lines})
        out["preview"] = {"total_lines": total, "parsed": parsed,
                          "bad_lines": bad, "skipped_lines": skipped,
                          "events": events, "bad_samples": bad_samples}
        if parsed == 0 and bad > 0:
            out["preview"]["warning"] = "样本 0 行命中(格式可能不对)"
    return out


# ------------------------------------------------------------------ AI 辅助起草

def _sample_vault_head(row, sample_lines: int) -> list[str]:
    """从金库抽头 N 行(读前哈希校验;跳过空行,样本紧凑些)。"""
    path = vault.verify(row["vault_path"], row["sha256"])
    out: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            text = line.rstrip("\r\n")
            if text.strip():
                out.append(text)
            if len(out) >= sample_lines:
                break
    return out


def _audit_draft(conn: sqlite3.Connection, source_id: str, case_id: str,
                 model: str | None, *, ok: bool, usage: dict | None = None,
                 error: str | None = None) -> None:
    """AI 起草逐次审计(actor=ai,成功/失败都留痕;usage 记账进 detail)。"""
    with conn:
        db.append_audit(conn, case_id, actor="ai",
                        action="formatdesc_ai_draft", scope=source_id,
                        detail={"source_id": source_id, "model": model,
                                "ok": ok, "usage": usage, "error": error})


def draft_format_ai(conn: sqlite3.Connection, source_id: str,
                    sample_lines: int = 30) -> dict:
    """AI 辅助起草描述文件(§4.4):抽样 → AI 提议 → schema 校验 → 草稿 YAML。

    纪律:
    - 返回的是草稿 YAML **文本**,不落盘、不进治理链;人审编辑后走
      :import(恒 draft)→ :transition 才生效——AI 草稿≠可用格式;
    - AI 输出坏 JSON → GovernanceError(502, ai_bad_json);
      不合 schema → GovernanceError(502, ai_invalid,问题逐条列出);
    - offline_lite(无 key)→ AIError(kind=offline),API 层如实 503;
    - 成功/失败都写审计(actor=ai)并记 usage。
    """
    row = conn.execute("SELECT * FROM log_sources WHERE id = ?",
                       (source_id,)).fetchone()
    if row is None:
        raise GovernanceError(f"日志源不存在: {source_id}", status=404)
    lines = _sample_vault_head(row, max(1, min(int(sample_lines), 200)))
    if not lines:
        raise GovernanceError("日志源为空(无样本可起草)", status=422)
    numbered = "\n".join(f"{i + 1}: {t}" for i, t in enumerate(lines))
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_DRAFT},
        {"role": "user", "content":
         f"以下是日志源「{row['name']}」的头 {len(lines)} 行样本,"
         "请按系统提示输出格式描述 JSON:\n" + numbered},
    ]
    try:
        result = ai.chat(messages)             # offline → AIError(offline)
    except ai.AIError as e:
        _audit_draft(conn, source_id, row["case_id"], None, ok=False,
                     error=f"ai_{e.kind}")
        raise
    content = (result.get("content") or "").strip()
    # 宽容剥代码围栏(AI 被明令只输出 JSON;围栏出现即剥,剥不动按坏 JSON 报)
    if content.startswith("```"):
        content = content.strip("`")
        if content.startswith("json"):
            content = content[4:]
        content = content.strip()
    try:
        proposal = json.loads(content)
    except json.JSONDecodeError:
        _audit_draft(conn, source_id, row["case_id"], result.get("model"),
                     ok=False, usage=result.get("usage"),
                     error="ai_bad_json")
        raise GovernanceError(
            "AI 输出不是合法 JSON(ai_bad_json),不落盘;可重试或人工起草",
            status=502)
    if not isinstance(proposal, dict):
        _audit_draft(conn, source_id, row["case_id"], result.get("model"),
                     ok=False, usage=result.get("usage"),
                     error="ai_bad_json")
        raise GovernanceError(
            "AI 输出非 JSON 对象(ai_bad_json),不落盘", status=502)

    # AI 提议 → 描述文件 dict;ts_field 由 field_map 中 ts_raw 映射推出
    field_map = proposal.get("field_map") if isinstance(
        proposal.get("field_map"), dict) else {}
    ts_keys = [k for k, v in field_map.items() if v == descriptor.TS_NORM]
    spec: dict = {
        "name": "todo-rename-me",              # 占位名,人审必改(撞名即知)
        "title": f"AI 起草({row['name']})",
        "kind": proposal.get("kind"),
        "field_map": field_map,
        "ts_field": ts_keys[0] if len(ts_keys) == 1 else None,
        "ts_formats": proposal.get("ts_formats"),
        "status": "draft",
        "note": "AI 起草·人审后才生效(AI 草稿≠可用格式,§4.4)",
    }
    if proposal.get("kind") == "regex":
        spec["line_regex"] = proposal.get("line_regex")
    if proposal.get("kind") == "csv" and isinstance(proposal.get("csv"), dict):
        spec["csv"] = proposal["csv"]
    if isinstance(proposal.get("multiline"), dict):
        spec["multiline"] = proposal["multiline"]
    spec = {k: v for k, v in spec.items() if v is not None}
    try:
        descriptor.validate_desc(spec)
    except FormatDescError as e:
        _audit_draft(conn, source_id, row["case_id"], result.get("model"),
                     ok=False, usage=result.get("usage"),
                     error="ai_invalid")
        raise GovernanceError(
            f"AI 输出不合描述文件 schema(ai_invalid),不落盘: {e}",
            status=502) from e

    draft_yaml = _DRAFT_HEADER + yaml.safe_dump(
        spec, allow_unicode=True, sort_keys=False)
    _audit_draft(conn, source_id, row["case_id"], result.get("model"),
                 ok=True, usage=result.get("usage"))
    return {
        "source_id": source_id,
        "sampled_lines": len(lines),
        "model": result.get("model"),
        "usage": result.get("usage"),
        "draft_yaml": draft_yaml,
        "note": "AI 草稿≠可用格式,人审后才生效:人审编辑后 :import 导入"
                "(恒 draft),review→enable 后才可用于解析;本草稿未落盘",
    }
