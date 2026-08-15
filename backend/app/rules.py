"""L1 规则引擎(SUOTU_DESIGN §8):签名规则 + M2 统计规则(键值比对算子族)
+ 跨源联动扫描,命中一律进待审区。

铁律落点:
- §1 判断权归人:命中只写 hits 待审区(status 恒 pending 起步),**永不自动
  写 clues**;clues 表唯一写入路径 = 人 accept_hit;reject 只改状态不产线索;
- §4.6 单一检索层:签名逐事件扫描经 query.scan_events;统计聚合/跨源/互证
  取数经 query 的 agg_*/cross_source_global_entities/corroborate_events,
  本模块不写一行 SQL 查事件层;hits/clues 是人的登记层(case.db),与事件层
  (DuckDB)分离;
- 加载即校验:签名规则与统计规则同一治理(schema 校验/重复 id/未知字段/
  未知算子/坏参数一律 RuleError;统计规则引用的排除 KB 同样在加载时校验,
  KB 损坏加载即暴露),不静默跳过;
- 签名匹配语义:match 字段条件 AND、字段内子串列表 OR、大小写不敏感;
  M1 只做子串(不做正则),保持确定性可审计;
- 去重幂等:UNIQUE(source_id, line_no, rule_id),重跑 hits_new=0;
  统计命中的 line_no 用组内代表行(组内最小行号)并在 detail_json 如实标注。

诚实边界(写进命中文案):
- 分化≠异常、突刺≠攻击、疑似同源聚簇是概率性弱信号——统计命中只描述
  分布事实,结论交人复核,文案严禁定论;
- rate_spike 基线只计有事件的时间桶(空桶不补零);ts_utc 全 NULL 的源
  时序算子(rate_spike/sequence/periodicity)如实跳过,报告 skipped 段注明;
- sequence(链式 motif)/periodicity(周期信标)同样是弱信号:命中≠成功
  入侵、周期≠恶意,文案写死交人复核;
- 命中预算帽:每规则每案最多新增 max_hits 条(签名默认 500/统计默认 50,
  YAML 可选覆盖),超出停止该规则插入,报告 per_rule 如实标 truncated;
- 自定义规则(data/rules_custom/,治理见 rulescustom.py)只有 enable 状态
  进扫描,与内置规则同一 schema 闸;内置规则永只读,id 冲突拒绝;
- target 语义本期只实现 web/any:web 规则只套 log_type=web 的源,any 规则
  套全部源(raw 兜底);middleware/audit 在 schema 里合法但无对应归一字段,
  套到源上自然零命中,不额外拦;
- 多字段 AND 的规则若多个字段都命中,matched_field/matched_value 只记
  按 match 声明顺序的第一个命中字段(列是单值,完整判定依据在规则 YAML);
- 子串匹配对高度混淆载荷(分段/双重编码/注释穿插)天然有盲区——这是
  确定性内核的既定取舍,长尾归 L3 AI 精读(§6 四层漏斗)。
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import db, logging_setup, query

# 内置规则目录:签名 backend/rules/builtin/*.yaml,统计 backend/rules/stats/*.yaml
BUILTIN_DIR = Path(__file__).resolve().parents[1] / "rules" / "builtin"
STATS_DIR = Path(__file__).resolve().parents[1] / "rules" / "stats"
# 排除清单 KB 目录(backend/kb/*.yaml,数据文件,人可编辑)
KB_DIR = Path(__file__).resolve().parents[1] / "kb"

SEVERITIES = {"info", "low", "medium", "high"}
TARGETS = {"web", "middleware", "audit", "any"}
MATCH_FIELDS = {"path", "query", "ua", "method", "status", "raw"}
HIT_STATUS = {"pending", "accepted", "rejected"}
# schema 允许的顶层键(未知字段一律报错)
RULE_KEYS = {"id", "title", "severity", "target", "match", "note", "max_hits"}

# ---- M2 统计规则(键值比对算子族 + 链式/周期时序算子) ----
STAT_OPERATORS = {"same_key_divergence", "cross_key_same_value", "rate_spike",
                  "size_outlier", "sequence", "periodicity"}
# 统计规则允许的顶层键(全集;各算子必填子集见 _STAT_REQUIRED)
STAT_RULE_KEYS = {
    "id", "title", "operator", "severity", "note",
    "key_fields", "diverge_field", "metric", "min_group_events", "diverge_ratio",
    "value_field", "min_keys", "max_value_freq", "exclude_kb",
    "bucket_seconds", "zscore", "min_bucket_count",
    "deviate_ratio", "max_outliers",
    "steps", "window_seconds", "min_first_step_count",
    "min_events", "max_cv", "min_span_seconds",
    "max_hits",
}
_STAT_REQUIRED = {
    "same_key_divergence": {"key_fields", "diverge_field", "metric",
                            "min_group_events", "diverge_ratio"},
    "cross_key_same_value": {"value_field", "key_fields", "min_keys",
                             "max_value_freq"},
    "rate_spike": {"key_fields", "bucket_seconds", "zscore",
                   "min_bucket_count"},
    "size_outlier": {"key_fields", "metric", "min_group_events",
                     "deviate_ratio"},
    "sequence": {"key_fields", "steps", "window_seconds"},
    "periodicity": {"key_fields"},
}
# 依赖 ts_utc 的时序算子:ts_utc 全 NULL 的源整源跳过,报告如实标注
_TS_OPERATORS = {"rate_spike", "sequence", "periodicity"}
# 命中预算帽默认值(每规则每案最多新增条数;规则 YAML max_hits 可覆盖)
SIG_MAX_HITS = 500
STAT_MAX_HITS = 50
# 归一字段白名单(mini-ECS,§5):统计规则的键/值/分化字段必须落在其中
NORM_FIELDS = {
    "src_ip", "method", "path", "query", "status", "bytes", "ua", "referer",
    "trace_id", "session_id", "user",
    "level", "logger", "message",
    "actor", "action", "object", "result",
}
STAT_METRICS = {"bytes", "status"}
_KB_NAME_RE = re.compile(r"^[a-z0-9_]+$")

# 跨源联动是算子外的内置固定步骤(非 YAML 算子),规则条目常量以便清单/
# 审核 title 查找走同一条路。
CROSS_SOURCE_RULE = {
    "id": "cross-source-entity",
    "title": "跨源 global 实体联动(同一实体出现在 ≥2 个源)",
    "severity": "high",
    "operator": "cross_source_entity",
    "note": "qualifier=global 的实体(公网 IP)出现在 ≥2 个源 → 联动锚点;"
            "私网/账户等 host_scoped 实体永不跨源(防张冠李戴闸);"
            "同值未必同人,交人复核。",
}

_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")  # 小写连字符
_SNIPPET_MAX = 300                                # 命中留证截断长度


class RuleError(Exception):
    """规则 schema / 扫描 / 审核的业务校验失败,message 直给调用方。"""
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ==================== schema 校验(加载即校验,坏规则报错不静默) ====================

def validate_rule(doc, *, src_name: str = "<yaml>") -> dict:
    """校验一份规则 YAML;通过则返回归一化 dict,否则 RuleError。"""
    if not isinstance(doc, dict):
        raise RuleError(f"{src_name}: 规则须为 YAML 映射,收到 {type(doc).__name__}")
    errors: list[str] = []
    unknown = set(doc) - RULE_KEYS
    if unknown:
        errors.append(f"未知字段 {sorted(unknown)}(允许: {sorted(RULE_KEYS)})")
    for f in ("id", "title", "severity", "target", "match"):
        if f not in doc:
            errors.append(f"缺必填字段 {f}")
    if errors:
        raise RuleError(f"{src_name}: " + ";".join(errors))

    rid, sev, target, match = doc["id"], doc["severity"], doc["target"], doc["match"]
    if not isinstance(rid, str) or not _ID_RE.match(rid):
        errors.append("id 须为小写连字符格式(如 sqli-union-select)")
    if not isinstance(doc["title"], str) or not doc["title"].strip():
        errors.append("title 须为非空字符串")
    if sev not in SEVERITIES:
        errors.append(f"severity 须为 {sorted(SEVERITIES)} 之一")
    if target not in TARGETS:
        errors.append(f"target 须为 {sorted(TARGETS)} 之一")
    if "note" in doc and not isinstance(doc["note"], str):
        errors.append("note 须为字符串(规则依据说明)")
    if not isinstance(match, dict) or not match:
        errors.append("match 须为非空映射(字段条件 AND,字段内子串列表 OR)")
    else:
        for k, v in match.items():
            if k not in MATCH_FIELDS:
                errors.append(f"match.{k}: 未知匹配字段(允许: {sorted(MATCH_FIELDS)})")
                continue
            if not isinstance(v, list) or not v or \
                    not all(isinstance(x, str) and x for x in v):
                errors.append(f"match.{k}: 须为非空子串列表(OR 语义)")
    max_hits = _validate_number(doc["max_hits"], "max_hits", errors,
                                integer=True, gt=0) if "max_hits" in doc else None
    if errors:
        raise RuleError(f"{src_name}: " + ";".join(errors))

    rule = {
        "id": rid, "title": doc["title"].strip(), "severity": sev,
        "target": target,
        # 子串统一预转小写(匹配大小写不敏感,加载时一次做好)
        "match": {k: [x.lower() for x in v] for k, v in match.items()},
        "note": doc.get("note"),
    }
    if max_hits is not None:
        rule["max_hits"] = max_hits
    return rule


def load_rules(directory: Path | None = None) -> list[dict]:
    """扫描规则目录,全部加载校验;重复 id 一律报错(治理:去重冲突检测)。"""
    directory = directory or BUILTIN_DIR
    rules: list[dict] = []
    seen: dict[str, str] = {}
    for path in sorted(directory.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise RuleError(f"{path.name}: YAML 解析失败: {e}")
        rule = validate_rule(doc, src_name=path.name)
        if rule["id"] in seen:
            raise RuleError(
                f"规则 id 重复: {rule['id']}({seen[rule['id']]} 与 {path.name})")
        seen[rule["id"]] = path.name
        rules.append(rule)
    return rules


def list_rules() -> list[dict]:
    """签名规则清单;每次实时加载,改 YAML 即生效。"""
    return load_rules()


# ==================== M2 统计规则:加载即校验(与签名规则同一治理纪律) ====================

def _validate_fields_list(value, name: str, errors: list[str]) -> list[str]:
    """归一字段列表校验:非空、每项在 NORM_FIELDS 白名单内。"""
    if not isinstance(value, list) or not value or \
            not all(isinstance(x, str) for x in value):
        errors.append(f"{name} 须为非空字段名列表")
        return []
    bad = [x for x in value if x not in NORM_FIELDS]
    if bad:
        errors.append(f"{name} 含未知归一字段 {bad}(允许: {sorted(NORM_FIELDS)})")
    return value


def _validate_number(value, name: str, errors: list[str], *,
                     integer: bool, gt: float) -> float | int | None:
    """数值参数校验:类型 + 下界(> gt)。"""
    ok_type = isinstance(value, int) and not isinstance(value, bool) \
        if integer else isinstance(value, (int, float)) \
        and not isinstance(value, bool)
    if not ok_type:
        errors.append(f"{name} 须为{'整数' if integer else '数值'}")
        return None
    if value <= gt:
        errors.append(f"{name} 须 > {gt}")
        return None
    return value


def validate_stat_rule(doc, *, src_name: str = "<yaml>") -> dict:
    """校验一份统计规则 YAML;通过则返回归一化 dict,否则 RuleError。

    与签名规则同一纪律:未知字段/未知算子/缺必填/坏参数一律报错,
    不静默跳过(内置规则损坏 = 工程事故,测试焊死)。
    """
    if not isinstance(doc, dict):
        raise RuleError(f"{src_name}: 规则须为 YAML 映射,收到 {type(doc).__name__}")
    errors: list[str] = []
    unknown = set(doc) - STAT_RULE_KEYS
    if unknown:
        errors.append(f"未知字段 {sorted(unknown)}(允许: {sorted(STAT_RULE_KEYS)})")
    for f in ("id", "title", "operator", "severity"):
        if f not in doc:
            errors.append(f"缺必填字段 {f}")
    if errors:
        raise RuleError(f"{src_name}: " + ";".join(errors))

    rid, sev, op = doc["id"], doc["severity"], doc["operator"]
    if not isinstance(rid, str) or not _ID_RE.match(rid):
        errors.append("id 须为小写连字符格式(如 ip-rate-spike)")
    if not isinstance(doc["title"], str) or not doc["title"].strip():
        errors.append("title 须为非空字符串")
    if sev not in SEVERITIES:
        errors.append(f"severity 须为 {sorted(SEVERITIES)} 之一")
    if op not in STAT_OPERATORS:
        errors.append(f"未知算子 {op!r}(允许: {sorted(STAT_OPERATORS)})")
        raise RuleError(f"{src_name}: " + ";".join(errors))
    if "note" in doc and not isinstance(doc["note"], str):
        errors.append("note 须为字符串(规则依据说明)")

    missing = _STAT_REQUIRED[op] - set(doc)
    if missing:
        errors.append(f"算子 {op} 缺必填参数 {sorted(missing)}")
        raise RuleError(f"{src_name}: " + ";".join(errors))

    out: dict = {"id": rid, "title": doc["title"].strip(), "severity": sev,
                 "operator": op, "note": doc.get("note")}

    if "key_fields" in _STAT_REQUIRED[op]:
        out["key_fields"] = _validate_fields_list(
            doc.get("key_fields"), "key_fields", errors)
    if op == "same_key_divergence":
        dv = doc.get("diverge_field")
        if dv not in NORM_FIELDS:
            errors.append(f"diverge_field 须为归一字段之一 {sorted(NORM_FIELDS)}")
        else:
            out["diverge_field"] = dv
        metric = doc.get("metric")
        if metric not in STAT_METRICS:
            errors.append(f"metric 须为 {sorted(STAT_METRICS)} 之一")
        else:
            out["metric"] = metric
        out["min_group_events"] = _validate_number(
            doc.get("min_group_events"), "min_group_events", errors,
            integer=True, gt=1)
        out["diverge_ratio"] = _validate_number(
            doc.get("diverge_ratio"), "diverge_ratio", errors,
            integer=False, gt=1.0)
    elif op == "cross_key_same_value":
        vf = doc.get("value_field")
        if vf not in NORM_FIELDS:
            errors.append(f"value_field 须为归一字段之一 {sorted(NORM_FIELDS)}")
        else:
            out["value_field"] = vf
        out["min_keys"] = _validate_number(
            doc.get("min_keys"), "min_keys", errors, integer=True, gt=1)
        out["max_value_freq"] = _validate_number(
            doc.get("max_value_freq"), "max_value_freq", errors,
            integer=True, gt=1)
        kb = doc.get("exclude_kb")
        if kb is not None:
            if not isinstance(kb, str) or not _KB_NAME_RE.match(kb):
                errors.append("exclude_kb 须为小写字母/数字/下划线的 KB 名")
            else:
                out["exclude_kb"] = kb
    elif op == "rate_spike":
        out["bucket_seconds"] = _validate_number(
            doc.get("bucket_seconds"), "bucket_seconds", errors,
            integer=True, gt=0)
        out["zscore"] = _validate_number(
            doc.get("zscore"), "zscore", errors, integer=False, gt=0.0)
        out["min_bucket_count"] = _validate_number(
            doc.get("min_bucket_count"), "min_bucket_count", errors,
            integer=True, gt=0)
    elif op == "size_outlier":
        metric = doc.get("metric")
        if metric not in STAT_METRICS:
            errors.append(f"metric 须为 {sorted(STAT_METRICS)} 之一")
        else:
            out["metric"] = metric
        out["min_group_events"] = _validate_number(
            doc.get("min_group_events"), "min_group_events", errors,
            integer=True, gt=1)
        out["deviate_ratio"] = _validate_number(
            doc.get("deviate_ratio"), "deviate_ratio", errors,
            integer=False, gt=1.0)
        out["max_outliers"] = _validate_number(
            doc.get("max_outliers", 3), "max_outliers", errors,
            integer=True, gt=0)
    elif op == "sequence":
        # 链式 motif:steps 2~3 步,每步 {field: 归一字段, in: 协议常量列表}
        steps = doc.get("steps")
        if not isinstance(steps, list) or not (2 <= len(steps) <= 3):
            errors.append("steps 须为 2~3 步的列表(每步 {field, in})")
        else:
            norm_steps: list[dict] = []
            for i, s in enumerate(steps):
                if not isinstance(s, dict) or set(s) != {"field", "in"}:
                    errors.append(f"steps[{i}] 须为 {{field, in}} 两键映射")
                    continue
                if s["field"] not in NORM_FIELDS:
                    errors.append(f"steps[{i}].field 须为归一字段之一 "
                                  f"{sorted(NORM_FIELDS)}")
                    continue
                vals = s["in"]
                if not isinstance(vals, list) or not vals or \
                        not all(isinstance(x, (str, int))
                                and not isinstance(x, bool) for x in vals):
                    errors.append(f"steps[{i}].in 须为非空协议常量列表"
                                  "(状态码/方法这类,不写案件特定值)")
                    continue
                # 匹配大小写不敏感、数字转字符串,加载时一次归一
                norm_steps.append({"field": s["field"],
                                   "in": sorted({str(x).lower() for x in vals})})
            if len(norm_steps) == len(steps):
                out["steps"] = norm_steps
        out["window_seconds"] = _validate_number(
            doc.get("window_seconds"), "window_seconds", errors,
            integer=True, gt=0)
        out["min_first_step_count"] = _validate_number(
            doc.get("min_first_step_count", 3), "min_first_step_count", errors,
            integer=True, gt=0)
    elif op == "periodicity":
        out["min_events"] = _validate_number(
            doc.get("min_events", 6), "min_events", errors, integer=True, gt=2)
        out["max_cv"] = _validate_number(
            doc.get("max_cv", 0.2), "max_cv", errors, integer=False, gt=0.0)
        out["min_span_seconds"] = _validate_number(
            doc.get("min_span_seconds", 300), "min_span_seconds", errors,
            integer=True, gt=0)
    if "max_hits" in doc:
        out["max_hits"] = _validate_number(
            doc["max_hits"], "max_hits", errors, integer=True, gt=0)
    if errors:
        raise RuleError(f"{src_name}: " + ";".join(errors))
    return out


def load_kb(name: str, kb_dir: Path | None = None) -> dict:
    """加载排除清单 KB(backend/kb/{name}.yaml);损坏即 RuleError,不静默。

    结构:{id?, title?, tokens: 非空字符串列表, note?};token 统一小写,
    匹配语义 = 值小写化后子串包含(真实爬虫 UA 形如 'Mozilla/5.0 (compatible; Googlebot/…)',词根不在开头,startswith 实测定性失效 2026-08-05)。
    """
    if not _KB_NAME_RE.match(name):
        raise RuleError(f"非法 KB 名: {name!r}")
    path = (kb_dir or KB_DIR) / f"{name}.yaml"
    if not path.is_file():
        raise RuleError(f"KB 不存在: {path.name}(统计规则引用的排除清单必须落盘)")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RuleError(f"{path.name}: YAML 解析失败: {e}")
    if not isinstance(doc, dict):
        raise RuleError(f"{path.name}: KB 须为 YAML 映射")
    tokens = doc.get("tokens")
    if not isinstance(tokens, list) or not tokens or \
            not all(isinstance(p, str) and p.strip() for p in tokens):
        raise RuleError(f"{path.name}: tokens 须为非空字符串列表")
    return {"name": name, "tokens": [p.strip().lower() for p in tokens]}


def load_stat_rules(directory: Path | None = None,
                    kb_dir: Path | None = None) -> list[dict]:
    """扫描统计规则目录,全部加载校验;重复 id 报错;引用的排除 KB
    同步加载校验(KB 损坏加载即暴露),token 挂到规则的 _tokens 上。"""
    directory = directory or STATS_DIR
    rules: list[dict] = []
    seen: dict[str, str] = {}
    for path in sorted(directory.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise RuleError(f"{path.name}: YAML 解析失败: {e}")
        rule = validate_stat_rule(doc, src_name=path.name)
        if rule["id"] in seen:
            raise RuleError(
                f"规则 id 重复: {rule['id']}({seen[rule['id']]} 与 {path.name})")
        seen[rule["id"]] = path.name
        if rule.get("exclude_kb"):
            kb = load_kb(rule["exclude_kb"], kb_dir=kb_dir)
            rule["_tokens"] = kb["tokens"]
        else:
            rule["_tokens"] = []
        rules.append(rule)
    return rules


def list_stat_rules() -> list[dict]:
    """统计规则清单(对外视图:剥掉内部派生键,operator 等参数原样出)。"""
    return [{k: v for k, v in r.items() if not k.startswith("_")}
            for r in load_stat_rules()]


def find_rule(rule_id: str) -> dict | None:
    """按 id 找规则(签名 → 统计 → 跨源内置),审核 title 查找用。"""
    for r in load_rules():
        if r["id"] == rule_id:
            return r
    for r in load_stat_rules():
        if r["id"] == rule_id:
            return r
    if CROSS_SOURCE_RULE["id"] == rule_id:
        return CROSS_SOURCE_RULE
    return None


# ==================== 匹配:字段条件 AND,字段内子串 OR,大小写不敏感 ====================

def match_rule(rule: dict, norm: dict, raw: str) -> tuple[str, str] | None:
    """一条事件套一条规则;命中返回 (matched_field, matched_value),否则 None。

    多字段 AND:任一字段不命中即整体不命中;多字段同时命中时按 match 声明
    顺序记第一个(见模块头注诚实边界)。raw 字段取整行原文兜底。
    """
    first: tuple[str, str] | None = None
    for field, subs in rule["match"].items():
        value = raw if field == "raw" else norm.get(field)
        if value is None:
            return None
        text = str(value).lower()          # status 等数字字段转字符串再比
        hit_sub = next((s for s in subs if s in text), None)
        if hit_sub is None:
            return None                    # AND:任一字段不命中即整体不命中
        if first is None:
            first = (field, hit_sub)
    return first


# ==================== M2 统计算子(聚合经 query 检索层,判定在本模块) ====================

def _iso(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


def _key_str(key_fields: list[str], key: list) -> str:
    """分组键 → 人读串,如 path=/api/item src_ip=1.2.3.4。"""
    return " ".join(f"{f}={v}" for f, v in zip(key_fields, key))


def _run_divergence(rule: dict, case_id: str, source_id: str) -> list[dict]:
    """算子① same_key_divergence:同键异值分化。

    组(键字段)内按分化字段分桶,桶 metric 均值 max/min ≥ diverge_ratio
    且组事件总数 ≥ min_group_events → 一条命中(代表行=组内最小行号)。
    """
    rows = query.agg_divergence(case_id, source_id, rule["key_fields"],
                                rule["diverge_field"], rule["metric"])
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(r["key"]), []).append(r)
    hits: list[dict] = []
    for key, buckets in groups.items():
        total = sum(b["count"] for b in buckets)
        if total < rule["min_group_events"]:
            continue  # 小样本噪声闸
        vals = [b for b in buckets if b["avg"] is not None]
        if len(vals) < 2:
            continue  # 不足两个有 metric 的桶,无从分化
        avgs = [b["avg"] for b in vals]
        lo, hi = min(avgs), max(avgs)
        if lo <= 0:
            if hi <= 0:
                continue
            ratio = float("inf")   # 一桶为零一桶非零:无限分化,如实命中
        else:
            ratio = hi / lo
        if ratio < rule["diverge_ratio"]:
            continue
        group = dict(zip(rule["key_fields"], key))
        ratio_txt = "∞" if math.isinf(ratio) else f"×{ratio:.1f}"
        hits.append({
            "line_no": min(b["first_line"] for b in buckets),
            "matched_field": rule["diverge_field"],
            "matched_value": ratio_txt,
            "snippet": (f"分化≠异常,交人复核:键 {_key_str(rule['key_fields'], key)}"
                        f" 按 {rule['diverge_field']} 分桶,{rule['metric']} 均值"
                        f"最高/最低 {ratio_txt}(阈值 ×{rule['diverge_ratio']});"
                        f"line_no 为组内代表行"),
            "ts_utc": None,
            "detail": {
                "kind": "divergence", "group": group,
                "diverge_field": rule["diverge_field"], "metric": rule["metric"],
                "ratio": None if math.isinf(ratio) else round(ratio, 3),
                "buckets": [{"value": b["diverge"], "count": b["count"],
                             "avg": round(b["avg"], 3)} for b in vals],
                "rep_line_no": min(b["first_line"] for b in buckets),
            },
        })
    return hits


def _run_cluster(rule: dict, case_id: str, source_id: str) -> list[dict]:
    """算子② cross_key_same_value:异键同值聚簇(疑似同源,弱信号)。

    值出现在 ≥ min_keys 个不同键 且 值全局频次 < max_value_freq(稀有度闸)
    且 不命中排除 KB 前缀(已知爬虫/库默认 UA)→ 一条命中。
    """
    rows = query.agg_value_keys(case_id, source_id, rule["value_field"],
                                rule["key_fields"])
    by_value: dict[str, list[dict]] = {}
    for r in rows:
        by_value.setdefault(r["value"], []).append(r)
    hits: list[dict] = []
    for value, occ in by_value.items():
        if len(occ) < rule["min_keys"]:
            continue  # 键数闸
        total = sum(o["count"] for o in occ)
        if total >= rule["max_value_freq"]:
            continue  # 稀有度闸:高频值(爬虫/工具默认)不聚簇
        if any(t in value.lower() for t in rule["_tokens"]):
            continue  # 排除 KB:已知爬虫/库默认前缀
        keys = [o["key"] for o in occ]
        first_ts = min((o["first_ts"] for o in occ if o["first_ts"]),
                       default=None)
        last_ts = max((o["last_ts"] for o in occ if o["last_ts"]),
                      default=None)
        key_desc = "/".join(rule["key_fields"])
        hits.append({
            "line_no": min(o["first_line"] for o in occ),
            "matched_field": rule["value_field"],
            "matched_value": value[:_SNIPPET_MAX],
            "snippet": (f"疑似同源聚簇(弱信号):{rule['value_field']}=「{value}」"
                        f"出现在 {len(keys)} 个不同 {key_desc};"
                        f"概率性信号,不代表同一攻击者,交人复核"),
            "ts_utc": first_ts,
            "detail": {
                "kind": "cluster", "value": value,
                "keys": [" ".join(map(str, k)) for k in keys],
                "counts": [{"key": " ".join(map(str, o["key"])),
                            "count": o["count"]} for o in occ],
                "total_freq": total, "first_ts": first_ts, "last_ts": last_ts,
                "rep_line_no": min(o["first_line"] for o in occ),
            },
        })
    return hits


def _run_rate_spike(rule: dict, case_id: str, source_id: str) -> list[dict]:
    """算子③ rate_spike:同键时间桶计数 z-score 突刺。

    基线=该键自身有事件的时间桶(空桶不补零);std=0(所有桶同计数)
    无突刺可言,跳过。突刺桶须同时过 zscore 与 min_bucket_count 双闸。
    """
    rows = query.agg_rate_buckets(case_id, source_id, rule["key_fields"],
                                  rule["bucket_seconds"])
    by_key: dict[tuple, list[dict]] = {}
    for r in rows:
        by_key.setdefault(tuple(r["key"]), []).append(r)
    hits: list[dict] = []
    for key, buckets in by_key.items():
        counts = [b["count"] for b in buckets]
        mean = sum(counts) / len(counts)
        std = math.sqrt(sum((c - mean) ** 2 for c in counts) / len(counts))
        if std == 0:
            continue  # 所有桶同计数,无突刺可言
        for b in buckets:
            z = (b["count"] - mean) / std
            if z < rule["zscore"] or b["count"] < rule["min_bucket_count"]:
                continue
            group = dict(zip(rule["key_fields"], key))
            hits.append({
                "line_no": b["first_line"],
                "matched_field": ",".join(rule["key_fields"]),
                "matched_value": " ".join(map(str, key))[:_SNIPPET_MAX],
                "snippet": (f"速率突刺≠攻击,交人复核:键 "
                            f"{_key_str(rule['key_fields'], key)} 在时间桶 "
                            f"{_iso(b['bucket_start'])}({rule['bucket_seconds']}s)"
                            f"内 {b['count']} 次,z={z:.1f}(阈值 "
                            f"{rule['zscore']});line_no 为桶内代表行"),
                "ts_utc": _iso(b["bucket_start"]),
                "detail": {
                    "kind": "rate_spike", "group": group,
                    "bucket_start": _iso(b["bucket_start"]),
                    "bucket_seconds": rule["bucket_seconds"],
                    "count": b["count"], "mean": round(mean, 3),
                    "std": round(std, 3), "z": round(z, 3),
                    "rep_line_no": b["first_line"],
                },
            })
    return hits


def _run_size_outlier(rule: dict, case_id: str, source_id: str) -> list[dict]:
    """算子④ size_outlier(2026-08-08 用户狩猎思路):同键组内字节离群。

    同路径(默认+方法+状态码)的响应尺寸主体聚在中位数附近,
    偏离超 deviate_ratio 倍的少数派逐条出命中——**line_no 直指那次
    异常响应本身**(不是组代表行),查看器可直达。
    尺寸离群≠实锤(动态内容天然变长),文案写死交人复核。
    """
    rows = query.agg_size_outliers(
        case_id, source_id, rule["key_fields"], rule["metric"],
        rule["min_group_events"], rule["deviate_ratio"],
        rule.get("max_outliers", 3))
    hits: list[dict] = []
    for r in rows:
        group = dict(zip(rule["key_fields"], r["key"]))
        direction = "偏大" if r["value"] > r["median"] else "偏小"
        hits.append({
            "line_no": r["line_no"],
            "matched_field": ",".join(rule["key_fields"]),
            "matched_value": _key_str(rule["key_fields"], r["key"])[:_SNIPPET_MAX],
            "snippet": (f"尺寸离群≠实锤,交人复核:{_key_str(rule['key_fields'], r['key'])}"
                        f" 组内 {r['group_count']} 次响应中位数 "
                        f"{r['median']:.0f}B,本次 {r['value']:.0f}B({direction}超 "
                        f"{rule['deviate_ratio']}x);line_no 即该次响应"),
            "ts_utc": r["ts_utc"],
            "detail": {
                "kind": "size_outlier", "group": group,
                "line_no": r["line_no"], "value": r["value"],
                "median": r["median"], "group_count": r["group_count"],
                "direction": direction,
                "deviate_ratio": rule["deviate_ratio"],
            },
        })
    return hits


def _run_sequence(rule: dict, case_id: str, source_id: str) -> list[dict]:
    """算子⑤ sequence(链式 motif):同键 A→B(→C)时间窗链。

    同组(键字段)内按 ts_utc 排序:step1 命中 ≥ min_first_step_count 次
    (防偶然闸)且最后一次 step1 之后 window_seconds 内依次出现后续步
    → 一条命中,锚点行 = 末步命中行,证据带 step1 计数与时间窗。
    ts_utc NULL 的事件检索层已排除(整源 NULL 由 run_rules 如实跳过)。
    链式命中≠成功入侵(正常用户试错后登录成功同样符合),文案写死交人复核。
    """
    step_fields = sorted({s["field"] for s in rule["steps"]})
    rows = query.agg_event_series(case_id, source_id, rule["key_fields"],
                                  step_fields)
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(r["key"]), []).append(r)
    steps = [{**s, "_set": set(s["in"])} for s in rule["steps"]]

    def _match(step: dict, ev: dict) -> bool:
        v = ev["values"].get(step["field"])
        return v is not None and str(v).lower() in step["_set"]

    window = rule["window_seconds"]
    hits: list[dict] = []
    for key, evs in groups.items():
        first_idx = [i for i, ev in enumerate(evs) if _match(steps[0], ev)]
        if len(first_idx) < rule["min_first_step_count"]:
            continue                                # 第一步次数闸(防偶然)
        # 链式推进:末次 step1 之后 window 内依次找后续步(同刻按行号序);
        # 遇到超窗事件即断链(窗口从上一命中步起算)
        chain = [first_idx[-1]]
        for step in steps[1:]:
            prev_ts = evs[chain[-1]]["ts_epoch"]
            nxt = None
            for j in range(chain[-1] + 1, len(evs)):
                if evs[j]["ts_epoch"] - prev_ts > window:
                    break                           # 超窗,链断
                if _match(step, evs[j]):
                    nxt = j
                    break
            if nxt is None:
                break
            chain.append(nxt)
        if len(chain) != len(steps):
            continue                                # 链不完整,不命中
        anchor = evs[chain[-1]]
        group = dict(zip(rule["key_fields"], key))
        first_last = evs[first_idx[-1]]
        chain_desc = " → ".join(
            f"{s['field']} in [{','.join(s['in'])}]" for s in rule["steps"])
        hits.append({
            "line_no": anchor["line_no"],
            "matched_field": ",".join(rule["key_fields"]),
            "matched_value": _key_str(rule["key_fields"], key)[:_SNIPPET_MAX],
            "snippet": (f"链式命中≠成功入侵,交人复核:键 "
                        f"{_key_str(rule['key_fields'], key)} 出现 "
                        f"{chain_desc} 链(第一步 ×{len(first_idx)},"
                        f"窗口 {window}s);line_no 为末步命中行"),
            "ts_utc": _iso(anchor["ts_epoch"]),
            "detail": {
                "kind": "sequence", "group": group,
                "steps": [{"field": s["field"], "in": s["in"]}
                          for s in rule["steps"]],
                "first_step_count": len(first_idx),
                "window_seconds": window,
                "first_step_last_ts": _iso(first_last["ts_epoch"]),
                "final_ts": _iso(anchor["ts_epoch"]),
                "chain_line_nos": [evs[j]["line_no"] for j in chain],
                "rep_line_no": anchor["line_no"],
            },
        })
    return hits


def _run_periodicity(rule: dict, case_id: str, source_id: str) -> list[dict]:
    """算子⑥ periodicity(周期信标):同键低慢规律间隔(C2 beacon 特征)。

    同组按 ts_utc 排序算相邻间隔:事件数 ≥ min_events 且 首尾跨度 ≥
    min_span_seconds(防短簇误判)且 间隔变异系数 cv ≤ max_cv → 一条命中,
    锚点 = 组内首行,证据带间隔均值/cv/次数。
    周期≠恶意:心跳/健康检查/监控轮询同样周期——弱信号进待审区交人复核。
    """
    rows = query.agg_event_series(case_id, source_id, rule["key_fields"])
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(r["key"]), []).append(r)
    hits: list[dict] = []
    for key, evs in groups.items():
        if len(evs) < rule["min_events"]:
            continue                                # 小样本噪声闸
        ts = [ev["ts_epoch"] for ev in evs]
        span = ts[-1] - ts[0]
        if span < rule["min_span_seconds"]:
            continue                                # 跨度闸:短簇不算信标
        intervals = [b - a for a, b in zip(ts, ts[1:])]
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            continue                                # 全同刻(跨度闸已拦,双保险)
        std = math.sqrt(sum((i - mean) ** 2 for i in intervals)
                        / len(intervals))
        cv = std / mean
        if cv > rule["max_cv"]:
            continue                                # 不够规律,不命中
        group = dict(zip(rule["key_fields"], key))
        hits.append({
            "line_no": evs[0]["line_no"],
            "matched_field": ",".join(rule["key_fields"]),
            "matched_value": _key_str(rule["key_fields"], key)[:_SNIPPET_MAX],
            "snippet": (f"周期≠恶意,交人复核(心跳/监控同样周期):键 "
                        f"{_key_str(rule['key_fields'], key)} {len(evs)} 次,"
                        f"间隔均值 {mean:.0f}s cv={cv:.3f}(阈值 "
                        f"{rule['max_cv']}),跨度 {span:.0f}s;"
                        f"line_no 为组内首行"),
            "ts_utc": _iso(ts[0]),
            "detail": {
                "kind": "periodicity", "group": group,
                "events": len(evs), "span_seconds": round(span, 3),
                "interval_mean": round(mean, 3), "cv": round(cv, 4),
                "max_cv": rule["max_cv"],
                "min_span_seconds": rule["min_span_seconds"],
                "rep_line_no": evs[0]["line_no"],
            },
        })
    return hits


_STAT_RUNNERS = {"same_key_divergence": _run_divergence,
                 "cross_key_same_value": _run_cluster,
                 "rate_spike": _run_rate_spike,
                 "size_outlier": _run_size_outlier,
                 "sequence": _run_sequence,
                 "periodicity": _run_periodicity}


def _run_cross_source(case_id: str, source_ids: list[str],
                      src_names: dict[str, str]) -> list[dict]:
    """跨源联动(算子外独立一步):qualifier=global 实体的 canonical_key
    出现在 ≥2 个源 → 每个涉及源一条命中(rule_id=cross-source-entity)。

    防张冠李戴闸:host_scoped(私网/账户)实体在检索层 SQL 已排除,
    这里再断言一遍(双保险,测试焊死)。
    """
    rows = query.cross_source_global_entities(case_id, source_ids)
    by_key: dict[str, list[dict]] = {}
    for r in rows:
        by_key.setdefault(r["canonical_key"], []).append(r)
    # 关联强度(SAG 式 PageRank,2026-08-14):同一批命中里强关联浮顶;
    # 分数只是排序依据,写进 detail 供人看,不参与判定
    _scores = query.entity_linkage_scores(case_id)
    hits: list[dict] = []
    for key, occ in by_key.items():
        sources = sorted({o["source_id"] for o in occ})
        if len(sources) < 2:
            continue
        names = [src_names.get(s, s) for s in sources]
        for o in occ:
            hits.append({
                "rule_id": CROSS_SOURCE_RULE["id"],
                "severity": CROSS_SOURCE_RULE["severity"],
                "source_id": o["source_id"],
                "line_no": o["first_line"],
                "matched_field": "canonical_key",
                "matched_value": key,
                "snippet": (f"跨源联动:global 实体 {key} 出现在 "
                            f"{len(sources)} 个源({', '.join(names)});"
                            f"同值未必同人,交人复核;line_no 为该源内代表行"),
                "ts_utc": o["first_ts"],
                "detail": {
                    "kind": "cross_source", "value": key,
                    "entity_type": o["entity_type"],
                    "sources": [{"source_id": s,
                                 "name": src_names.get(s, s)} for s in sources],
                    "rep_line_no": o["first_line"],
                    "linkage_score": round(
                        _scores.get((o["source_id"], o["first_line"]), 0.0), 6),
                },
            })
    # 强关联浮顶(同分按行号,确定性)
    hits.sort(key=lambda h: (-h["detail"]["linkage_score"], h["line_no"]))
    return hits


# ==================== 扫描:签名逐事件 + 统计聚合 + 跨源联动 ====================

def run_rules(conn: sqlite3.Connection, case_id: str,
              source_id: str | None = None, actor: str = "system",
              rule_ids: list[str] | None = None) -> dict:
    """对案件(或指定源)全量扫描,命中写 hits 待审区(重跑幂等)。

    三阶段:①签名逐事件扫描(经 query.scan_events)②统计算子聚合
    (经 query.agg_*)③跨源联动(经 query.cross_source_global_entities)。
    返回 {scanned, hits_new, hits_total, per_rule, signature, stats,
    cross_source};顶层 scanned/hits_new/hits_total/per_rule 保持 M1 语义
    (签名段),分段报告在 signature/stats/cross_source 三段。

    rule_ids:可选子集扫描(签名+统计+自定义 enable+跨源内置的统一 id
    空间);None=全量(旧行为)。未知 id / 选中未启用(draft/review)的
    自定义规则 → 422 如实报错,一条不跑。
    轮次:每次运行记 scan_runs 一行(round_no 每案件递增),命中带
    round_no;老数据 round_no NULL=「历史」。
    """
    if conn.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone() is None:
        raise RuleError(f"案件不存在: {case_id}", status=404)
    t0 = time.monotonic()
    rules = load_rules()
    stat_rules = load_stat_rules()      # 含排除 KB 加载校验,坏 KB 在此暴露
    # 自定义规则(data/rules_custom/):只有 enable 进扫描,draft/review 不进;
    # 与内置规则同一 schema 闸(rulescustom.load_enabled 内已校验)
    from . import rulescustom
    custom_sig, custom_stat = rulescustom.load_enabled()
    rules = rules + custom_sig
    stat_rules = stat_rules + custom_stat

    # ---- 子集选择:统一 id 空间校验,非法选择一条不跑(422 如实) ----
    run_cross_source = True
    if rule_ids is not None:
        selected = set(rule_ids)
        runnable = ({r["id"] for r in rules} | {r["id"] for r in stat_rules}
                    | {CROSS_SOURCE_RULE["id"]})
        # draft/review 的自定义规则:id 存在但不在可跑空间,单独如实报
        not_enabled = {c["id"] for c in rulescustom.list_custom()
                       if c.get("status") in ("draft", "review")}
        unknown = sorted(selected - runnable - not_enabled)
        if unknown:
            raise RuleError(f"未知规则 id: {unknown}"
                            "(可选空间=签名+统计+enable 自定义+跨源内置)",
                            status=422)
        blocked = sorted(selected & not_enabled)
        if blocked:
            raise RuleError(f"选中的自定义规则未启用(draft/review): {blocked};"
                            "转 enable 后才进扫描", status=422)
        rules = [r for r in rules if r["id"] in selected]
        stat_rules = [r for r in stat_rules if r["id"] in selected]
        run_cross_source = CROSS_SOURCE_RULE["id"] in selected

    # ---- 轮次登记:每案件递增 round_no;摘要在扫描结束后回填 ----
    round_no = conn.execute(
        "SELECT COALESCE(MAX(round_no), 0) + 1 AS n FROM scan_runs"
        " WHERE case_id = ?", (case_id,)).fetchone()["n"]
    with conn:
        conn.execute(
            "INSERT INTO scan_runs (id, case_id, round_no, rule_ids_json,"
            " actor, summary_json, created_at) VALUES (?,?,?,?,?,?,?)",
            (uuid.uuid4().hex, case_id, round_no,
             json.dumps(sorted(rule_ids), ensure_ascii=False)
             if rule_ids is not None else None,
             actor, None, _now()))

    # 命中预算帽:每规则每案最多新增 max_hits 条(YAML 可选,默认签名 500/
    # 统计 50);超出停止该规则插入,truncated 如实记溢出条数
    sig_caps = {r["id"]: r.get("max_hits", SIG_MAX_HITS) for r in rules}
    stat_caps = {r["id"]: r.get("max_hits", STAT_MAX_HITS) for r in stat_rules}
    sig_truncated = dict.fromkeys(sig_caps, 0)
    stat_truncated = dict.fromkeys(stat_caps, 0)
    # 源 → (log_type, sha256):target=web 规则只套 web 源,any 套全部
    src_rows = conn.execute(
        "SELECT id, name, log_type, sha256 FROM log_sources WHERE case_id = ?",
        (case_id,)).fetchall()
    src_meta = {r["id"]: (r["log_type"], r["sha256"]) for r in src_rows}
    src_names = {r["id"]: r["name"] for r in src_rows}
    if source_id is not None and source_id not in src_meta:
        raise RuleError(f"日志源不存在或不属于本案件: {source_id}", status=404)
    scope_ids = [source_id] if source_id else list(src_meta)

    scanned = 0
    per_rule = {r["id"]: 0 for r in rules}
    batch: list[tuple] = []
    hits_before = conn.execute(
        "SELECT COUNT(*) AS c FROM hits WHERE case_id = ?", (case_id,)
    ).fetchone()["c"]

    def _flush() -> None:
        """批量提交命中(实测:逐行事务 56ms/条,w3af 3926 命中 218s;
        500/批 INSERT OR IGNORE 同幂等语义,扫描提速一个数量级;
        新增数由前后总数差得出,不依赖 executemany rowcount)。"""
        if not batch:
            return
        with conn:
            conn.executemany(
                "INSERT OR IGNORE INTO hits (id, case_id, source_id, line_no,"
                " rule_id, severity, matched_field, matched_value, snippet,"
                " ts_utc, status, created_at, detail_json, round_no)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,'pending',?,?,?)", batch)
        batch.clear()

    def _count() -> int:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM hits WHERE case_id = ?", (case_id,)
        ).fetchone()["c"]

    # ---- 阶段①:签名逐事件扫描(现状语义不动 + 预算帽) ----
    for ev in query.scan_events(case_id, source_id=source_id):
        scanned += 1
        log_type = src_meta[ev["source_id"]][0]
        for rule in rules:
            if rule["target"] != "any" and rule["target"] != log_type:
                continue
            m = match_rule(rule, ev["norm"], ev["raw"])
            if m is None:
                continue
            if per_rule[rule["id"]] >= sig_caps[rule["id"]]:
                sig_truncated[rule["id"]] += 1    # 超帽:停止插入,如实记溢出
                continue
            batch.append((uuid.uuid4().hex, case_id, ev["source_id"],
                          ev["line_no"], rule["id"], rule["severity"],
                          m[0], m[1], ev["raw"][:_SNIPPET_MAX], ev["ts_utc"],
                          _now(), None, round_no))
            per_rule[rule["id"]] += 1
            if len(batch) >= 500:
                _flush()
    _flush()
    sig_new = _count() - hits_before

    # ---- 阶段②:统计算子(每源每规则聚合;统计命中 detail_json 结构化) ----
    stat_per_rule = {r["id"]: 0 for r in stat_rules}
    skipped: list[dict] = []
    stat_before = _count()
    for sid in scope_ids:
        for rule in stat_rules:
            if rule["operator"] in _TS_OPERATORS:
                cov = query.source_ts_coverage(case_id, sid)
                if cov["with_ts"] == 0:
                    # 时间未知不硬算,如实跳过并在报告注明
                    skipped.append({
                        "rule_id": rule["id"], "source_id": sid,
                        "reason": "ts_utc 全 NULL(时区未知),"
                                  "时序算子跳过,不硬算"})
                    continue
            for h in _STAT_RUNNERS[rule["operator"]](rule, case_id, sid):
                if stat_per_rule[rule["id"]] >= stat_caps[rule["id"]]:
                    stat_truncated[rule["id"]] += 1    # 超帽:停止插入,记溢出
                    continue
                batch.append((uuid.uuid4().hex, case_id, sid, h["line_no"],
                              rule["id"], rule["severity"], h["matched_field"],
                              h["matched_value"], h["snippet"], h["ts_utc"],
                              _now(), json.dumps(h["detail"],
                                                 ensure_ascii=False),
                              round_no))
                stat_per_rule[rule["id"]] += 1
                if len(batch) >= 500:
                    _flush()
    _flush()
    stat_new = _count() - stat_before

    # ---- 阶段③:跨源联动(global 实体 ≥2 源;host_scoped 永不跨源) ----
    # 子集扫描时仅当选中 cross-source-entity 才跑(统一 id 空间的一员)
    cs_before = _count()
    cs_hits = _run_cross_source(case_id, scope_ids, src_names) \
        if run_cross_source else []
    for h in cs_hits:
        batch.append((uuid.uuid4().hex, case_id, h["source_id"], h["line_no"],
                      h["rule_id"], h["severity"], h["matched_field"],
                      h["matched_value"], h["snippet"], h["ts_utc"],
                      _now(), json.dumps(h["detail"], ensure_ascii=False),
                      round_no))
        if len(batch) >= 500:
            _flush()
    _flush()
    cs_new = _count() - cs_before

    # per_rule 记「本次命中数(含重复)」;hits_new 为去重后实际新增,两值分列如实;
    # truncated 记预算帽溢出条数(0 也带,前端「已截断」标注直接读)
    hits_total = _count()
    hits_new = hits_total - hits_before

    def _per_rule_rows(counts: dict, truncs: dict) -> list[dict]:
        return [{"rule_id": rid, "hits": n, "truncated": truncs.get(rid, 0)}
                for rid, n in counts.items()]

    report = {
        "scanned": scanned, "hits_new": hits_new, "hits_total": hits_total,
        "round_no": round_no,
        "per_rule": _per_rule_rows(per_rule, sig_truncated),
        "signature": {
            "scanned": scanned, "hits_new": sig_new,
            "per_rule": _per_rule_rows(per_rule, sig_truncated),
        },
        "stats": {
            "hits_new": stat_new,
            "per_rule": _per_rule_rows(stat_per_rule, stat_truncated),
            "skipped": skipped,
        },
        "cross_source": {
            "hits_new": cs_new,
            "entities": sorted({h["matched_value"] for h in cs_hits}),
        },
    }
    truncated_total = sum(sig_truncated.values()) + sum(stat_truncated.values())
    with conn:
        # 轮次摘要回填(scanned/hits_new/truncated 计数,如实)
        conn.execute(
            "UPDATE scan_runs SET summary_json = ?"
            " WHERE case_id = ? AND round_no = ?",
            (json.dumps({"scanned": scanned, "hits_new": hits_new,
                         "hits_total": hits_total,
                         "truncated": truncated_total,
                         "rule_ids": sorted(rule_ids)
                         if rule_ids is not None else None},
                        ensure_ascii=False), case_id, round_no))
        db.append_audit(conn, case_id, action="rules_run", scope=source_id,
                        actor=actor,
                        detail={"scanned": scanned, "hits_new": hits_new,
                                "hits_total": hits_total,
                                "round_no": round_no,
                                "rule_ids": sorted(rule_ids)
                                if rule_ids is not None else None,
                                "per_rule": {k: v for k, v in per_rule.items() if v},
                                "stats": {k: v for k, v in stat_per_rule.items() if v},
                                "truncated": {k: v for k, v in
                                              {**sig_truncated,
                                               **stat_truncated}.items() if v},
                                "stats_skipped": len(skipped),
                                "cross_source": report["cross_source"]["entities"]})
    # 运行日志摘要(规则扫描落点;分段计数与耗时,与审计并行)
    logging_setup.app_logger().info(
        "规则扫描 case=%s source=%s 签名=%d 统计=%d 联动=%d 新增命中=%d "
        "扫描事件=%d %dms actor=%s",
        case_id, source_id or "全案件", sig_new, stat_new, cs_new, hits_new,
        scanned, int((time.monotonic() - t0) * 1000), actor)
    return report


# ==================== 待审区(§1 判断权归人:候选 → 人审 → 线索) ====================

def list_hits(conn: sqlite3.Connection, case_id: str, *,
              status: str | None = None, severity: str | None = None,
              q: str | None = None, round_no: str | None = None,
              hit_id: str | None = None,
              limit: int = 50, offset: int = 0) -> dict:
    """待审区检索:状态/严重级/轮次过滤 + 关键词(rule_id/命中值/摘要子串)+ 分页。

    round_no 过滤:"history"=老数据(round_no NULL,展示「历史」);
    数字串=该轮;None=全部。每条带 round_no(NULL 如实)。
    hit_id:精确锚定单条(记录区锚点跳转用)。
    """
    conds, params = ["case_id = ?"], [case_id]
    if hit_id:
        conds.append("id = ?")
        params.append(hit_id)
    if status:
        if status not in HIT_STATUS:
            raise RuleError(f"status 须为 {sorted(HIT_STATUS)} 之一")
        conds.append("status = ?")
        params.append(status)
    if severity:
        if severity not in SEVERITIES:
            raise RuleError(f"severity 须为 {sorted(SEVERITIES)} 之一")
        conds.append("severity = ?")
        params.append(severity)
    if round_no:
        if round_no == "history":
            conds.append("round_no IS NULL")
        elif round_no.isdigit() and int(round_no) >= 1:
            conds.append("round_no = ?")
            params.append(int(round_no))
        else:
            raise RuleError("round 须为轮次号(≥1)或 history(老数据)")
    if q:
        # 关键词:rule_id / matched_value / snippet / 源行号 四域子串 OR
        # (待审区搜索刚需,2026-08-05 用户反馈);LIKE 通配符按字面量转义
        esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{esc}%"
        conds.append("(rule_id LIKE ? ESCAPE '\\'"
                     " OR matched_value LIKE ? ESCAPE '\\'"
                     " OR snippet LIKE ? ESCAPE '\\'"
                     " OR CAST(line_no AS TEXT) LIKE ? ESCAPE '\\')")
        params.extend([like, like, like, like])
    where = " AND ".join(conds)
    total = conn.execute(
        f"SELECT COUNT(*) AS c FROM hits WHERE {where}", params).fetchone()["c"]
    rows = conn.execute(
        f"SELECT * FROM hits WHERE {where}"
        " ORDER BY created_at, id LIMIT ? OFFSET ?",
        (*params, limit, offset)).fetchall()
    items = []
    for r in rows:
        item = dict(r)
        # detail_json 出库即解析(M2 统计/联动命中的结构化细节;签名命中为 None)
        item["detail_json"] = json.loads(item["detail_json"]) \
            if item.get("detail_json") else None
        items.append(item)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


def list_scan_rounds(conn: sqlite3.Connection, case_id: str) -> dict:
    """扫描轮次台账(待审区轮次下拉/审计追溯用;round_no 升序如实列出)。"""
    rows = conn.execute(
        "SELECT round_no, rule_ids_json, actor, summary_json, created_at"
        " FROM scan_runs WHERE case_id = ? ORDER BY round_no",
        (case_id,)).fetchall()
    items = []
    for r in rows:
        items.append({
            "round_no": r["round_no"],
            "rule_ids": json.loads(r["rule_ids_json"])
            if r["rule_ids_json"] else None,          # None=全量扫描
            "actor": r["actor"],
            "summary": json.loads(r["summary_json"])
            if r["summary_json"] else None,
            "created_at": r["created_at"],
        })
    return {"total": len(items), "items": items}


# ==================== M2 互证:同 system 兄弟源 ±window 内同 path/同 IP ====================

def corroborate_hit(conn: sqlite3.Connection, hit_id: str,
                    window_seconds: int = 300) -> dict:
    """命中的兄弟源互证:该 hit 所属源的同 system 兄弟源中,ts_utc ±window
    内 norm.path 相同或 src_ip 相同的事件(经 query 检索层,限量 20)。

    三态如实区分:no_ts(hit 锚点行无 ts_utc,时间未知不硬算)/
    no_siblings(无同 system 兄弟源)/ok|none(有互证 | 有兄弟源但窗内无)。
    """
    if not isinstance(window_seconds, int) or \
            not (1 <= window_seconds <= 86400):
        raise RuleError("window_seconds 须为 1..86400 的整数秒")
    hit = _get_hit(conn, hit_id)
    src = conn.execute("SELECT id, name, system FROM log_sources WHERE id = ?",
                       (hit["source_id"],)).fetchone()
    if src is None:
        raise RuleError("命中锚定的日志源已不存在,证据链断", status=409)
    base = {"hit_id": hit_id, "source_id": hit["source_id"],
            "line_no": hit["line_no"], "window_seconds": window_seconds}

    # 锚点行的归一字段与时间(经检索层 read_window,锚点不丢)
    win = query.read_window(hit["source_id"], hit["line_no"], hit["line_no"])
    if not win["lines"]:
        raise RuleError("命中锚点行在事件层不存在,证据链断", status=409)
    ev = win["lines"][0]
    if not ev["ts_utc"]:
        return {**base, "status": "no_ts", "siblings": [], "items": [],
                "note": "锚点行 ts_utc 为 NULL(时区未知),时间未知不硬算,"
                        "互证不可用"}
    siblings = [dict(r) for r in conn.execute(
        "SELECT id, name, system FROM log_sources"
        " WHERE case_id = ? AND id != ? AND system IS NOT NULL AND system = ?",
        (hit["case_id"], hit["source_id"], src["system"])).fetchall()] \
        if src["system"] else []
    if not siblings:
        return {**base, "status": "no_siblings", "siblings": [], "items": [],
                "note": "无同 system 兄弟源(system 未登记或全案仅此一源),"
                        "互证不可用"}

    center = datetime.fromisoformat(ev["ts_utc"])
    delta = timedelta(seconds=window_seconds)
    items = query.corroborate_events(
        hit["case_id"], [s["id"] for s in siblings],
        center - delta, center + delta,
        ev["norm"].get("path"), ev["norm"].get("src_ip"), limit=20)
    return {
        **base,
        "status": "ok" if items else "none",
        "siblings": siblings,
        "items": items,
        "note": None if items else
                "有兄弟源但窗内无同 path/同 IP 事件(如实无互证,不等于无问题)",
    }


def _get_hit(conn: sqlite3.Connection, hit_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM hits WHERE id = ?", (hit_id,)).fetchone()
    if row is None:
        raise RuleError(f"命中不存在: {hit_id}", status=404)
    return row


def list_clues(conn: sqlite3.Connection, case_id: str) -> dict:
    """线索列表(人审入库的产物)。"""
    rows = conn.execute(
        "SELECT * FROM clues WHERE case_id = ? ORDER BY created_at, id",
        (case_id,)).fetchall()
    return {"total": len(rows), "items": [dict(r) for r in rows]}


def accept_hit(conn: sqlite3.Connection, hit_id: str,
               note: str | None = None, actor: str = "system") -> dict:
    """人审核通过 → 写线索(clues 表唯一写入路径),hit 状态 → accepted。

    clue: title 自动 = 规则 title;body = 命中摘要 + 锚点;anchor 三件套
    (source_id + line_no + sha256)取自 hit 与其源登记,缺一不可。
    已裁决 hit 再裁决 → 409(乐观纪律);全程一事务 + 审计。
    """
    hit = _get_hit(conn, hit_id)
    if hit["status"] != "pending":
        raise RuleError(f"命中已是 {hit['status']} 状态,不能重复审核", status=409)
    rule = find_rule(hit["rule_id"])
    title = rule["title"] if rule else hit["rule_id"]
    src = conn.execute("SELECT sha256 FROM log_sources WHERE id = ?",
                       (hit["source_id"],)).fetchone()
    if src is None:
        raise RuleError("命中锚定的日志源已不存在,证据链断,拒收", status=409)
    body = (f"[规则命中] {title}\n"
            f"规则: {hit['rule_id']} (severity={hit['severity']})\n"
            f"命中: {hit['matched_field']} 含「{hit['matched_value']}」\n"
            f"原文: {hit['snippet']}\n"
            f"锚点: 日志源 {hit['source_id']} 第 {hit['line_no']} 行"
            f" sha256={src['sha256']}")
    if note and note.strip():
        body += f"\n审核备注: {note.strip()}"
    clue_id = uuid.uuid4().hex
    with conn:
        conn.execute(
            "INSERT INTO clues (id, case_id, title, body, anchor_source_id,"
            " anchor_line_no, anchor_sha256, created_at, created_by)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (clue_id, hit["case_id"], title, body, hit["source_id"],
             hit["line_no"], src["sha256"], _now(), actor))
        conn.execute(
            "UPDATE hits SET status = 'accepted', reviewed_at = ?,"
            " review_note = ? WHERE id = ?", (_now(), note, hit_id))
        db.append_audit(conn, hit["case_id"], action="hit_accept",
                        scope=hit_id, actor=actor,
                        detail={"rule_id": hit["rule_id"], "clue_id": clue_id,
                                "anchor": {"source_id": hit["source_id"],
                                           "line_no": hit["line_no"],
                                           "sha256": src["sha256"]},
                                "note": note})
    clue = conn.execute("SELECT * FROM clues WHERE id = ?",
                        (clue_id,)).fetchone()
    return {"hit_id": hit_id, "status": "accepted", "clue": dict(clue)}


def reject_hit(conn: sqlite3.Connection, hit_id: str,
               note: str | None = None, actor: str = "system") -> dict:
    """人审核驳回 → 状态 rejected + 留痕;线索库不进任何东西。"""
    hit = _get_hit(conn, hit_id)
    if hit["status"] != "pending":
        raise RuleError(f"命中已是 {hit['status']} 状态,不能重复审核", status=409)
    with conn:
        conn.execute(
            "UPDATE hits SET status = 'rejected', reviewed_at = ?,"
            " review_note = ? WHERE id = ?", (_now(), note, hit_id))
        db.append_audit(conn, hit["case_id"], action="hit_reject",
                        scope=hit_id, actor=actor,
                        detail={"rule_id": hit["rule_id"], "note": note})
    return {"hit_id": hit_id, "status": "rejected"}
