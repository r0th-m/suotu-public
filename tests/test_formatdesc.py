"""M4 描述文件引擎 + 治理链 + AI 辅助起草(合成纪律,AI 全程 mock)。

覆盖:
- schema 校验全负面(缺字段/未知键/坏 regex/未知归一字段/未知 kind/
  空 ts_formats/缺 ts_field 等);
- 引擎三 kind(regex/json/csv)正样本字段级断言 + 坏行计数 + extras +
  多行合并(续行并入 + 计数 + 孤儿续行坏行);
- 注册表:desc:<name> 仅 enable 放行,draft/review → None;
- 治理链(API):导入恒 draft/撞名 409/状态机只许向前/enable 可 disable/
  仅 draft 可删/validate 预览/export;
- AI 起草:mock chat 草稿不落盘/坏 JSON 502/不合 schema 502 ai_invalid/
  offline 503/审计+usage 留痕;
- 端到端:合成 OA 审计 CSV(中文)→ enable → 上传 → confirm desc:oa-demo
  → 解析 → 字段条件检索 actor 命中。
"""
from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient

from backend.app import ai, formatdesc, ingest
from backend.app.formats import descriptor, find_format, list_formats
from backend.app.formats.descriptor import FormatDescError
from backend.app.main import app

# ---------------------------------------------------------------- 合成夹具

# regex 审计格式(单行)
OA_REGEX_YAML = """
name: oa-regex
title: 合成 OA 审计(空格分隔)
kind: regex
line_regex: '^(?P<ts>\\S+ \\S+)\\s+(?P<actor>\\S+)\\s+(?P<action>\\S+)\\s+(?P<object>.*?)\\s+(?P<result>\\S+)\\s+(?P<ip>\\S+)$'
field_map: {ts: ts_raw, actor: actor, action: action, object: object, result: result}
ts_field: ts
ts_formats: ['%Y-%m-%d %H:%M:%S']
status: enable
note: 合成夹具
"""
OA_REGEX_LINES = [
    "2026-08-01 09:00:01 张三 登录 OA系统 成功 10.0.0.8",
    "2026-08-01 09:01:22 李四 导出 工资表 失败 10.0.0.9",
]

# json 行格式
JSON_YAML = """
name: app-json
kind: json
json: true
field_map: {time: ts_raw, user: actor, op: action, lvl: level}
ts_field: time
ts_formats: ['%Y/%m/%d %H:%M:%S']
status: enable
"""
JSON_LINES = [
    '{"time": "2026/08/01 10:00:00", "user": "u1", "op": "read", "lvl": "INFO", "extra_key": 7}',
    '{"time": "2026/08/01 10:00:01", "user": "u2", "op": "write"}',
    'not json at all',
    '["数组不是对象"]',
]

# csv 审计格式(中文表头,端到端用)
OA_CSV_YAML = """
name: oa-demo
title: 合成 OA 审计 CSV
kind: csv
csv: {delimiter: ',', header: true}
field_map: {时间: ts_raw, 操作人: actor, 动作: action, 对象: object, 结果: result}
ts_field: 时间
ts_formats: ['%Y-%m-%d %H:%M:%S']
status: draft
note: 端到端合成夹具
"""
OA_CSV_TEXT = (
    "时间,操作人,动作,对象,结果\n"
    "2026-08-01 09:00:01,张三,登录,OA系统,成功\n"
    "2026-08-01 09:05:40,李四,导出,工资表,失败\n"
    "2026-08-01 09:07:12,张三,审批,请假单,成功\n"
)

# 多行合并格式(Java 堆栈式)
MULTILINE_YAML = """
name: app-multiline
kind: regex
line_regex: '^(?P<ts>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\s+(?P<level>\\S+)\\s+(?P<logger>\\S+)\\s+-\\s+(?P<message>.*)$'
field_map: {ts: ts_raw, level: level, logger: logger, message: message}
ts_field: ts
ts_formats: ['%Y-%m-%d %H:%M:%S']
multiline: {start_regex: '^\\d{4}-'}
status: enable
"""
MULTILINE_LINES = [
    "2026-08-01 10:00:00 ERROR oa.Service - 保存失败",
    "java.lang.RuntimeException: boom",
    "    at oa.Service.save(Service.java:42)",
    "2026-08-01 10:00:01 INFO oa.Service - 保存成功",
]


@pytest.fixture()
def desc_dir(data_dir, monkeypatch, tmp_path):
    """描述文件目录隔离(SUOTU_FORMATDESC_DIR → tmp)。"""
    d = tmp_path / "desc"
    monkeypatch.setenv("SUOTU_FORMATDESC_DIR", str(d))
    return d


@pytest.fixture()
def client(desc_dir):
    with TestClient(app) as c:
        yield c


def _engine(yaml_text: str) -> descriptor.CompiledDesc:
    return descriptor.CompiledDesc(descriptor.load_desc_text(yaml_text))


# ---------------------------------------------------------------- schema 负面

@pytest.mark.parametrize("yaml_text, fragment", [
    # 缺 name
    ("kind: regex\nline_regex: '^(?P<a>x)$'\nfield_map: {a: ts_raw}\n"
     "ts_field: a\nts_formats: ['%Y']\n", "name"),
    # name 非法(大写/空格)
    ("name: Bad Name\nkind: regex\nline_regex: '^(?P<a>x)$'\n"
     "field_map: {a: ts_raw}\nts_field: a\nts_formats: ['%Y']\n", "name"),
    # 未知 kind
    ("name: a\nkind: grok\nfield_map: {a: ts_raw}\nts_field: a\n"
     "ts_formats: ['%Y']\n", "kind"),
    # 未知顶层键
    ("name: a\nkind: json\nfield_map: {a: ts_raw}\nts_field: a\n"
     "ts_formats: ['%Y']\ngrok_pattern: x\n", "未知键"),
    # 坏 line_regex
    ("name: a\nkind: regex\nline_regex: '^(?P<a>($'\n"
     "field_map: {a: ts_raw}\nts_field: a\nts_formats: ['%Y']\n", "编译失败"),
    # line_regex 无命名分组
    ("name: a\nkind: regex\nline_regex: '^x+$'\nfield_map: {a: ts_raw}\n"
     "ts_field: a\nts_formats: ['%Y']\n", "命名分组"),
    # field_map 未知归一字段
    ("name: a\nkind: json\nfield_map: {a: ts_raw, b: no_such_field}\n"
     "ts_field: a\nts_formats: ['%Y']\n", "未知归一字段"),
    # field_map 缺 ts_raw 映射(缺时间字段)
    ("name: a\nkind: json\nfield_map: {a: actor}\nts_field: a\n"
     "ts_formats: ['%Y']\n", "时间字段"),
    # ts_field 不在 field_map
    ("name: a\nkind: json\nfield_map: {a: ts_raw}\nts_field: b\n"
     "ts_formats: ['%Y']\n", "ts_field"),
    # ts_formats 空
    ("name: a\nkind: json\nfield_map: {a: ts_raw}\nts_field: a\n"
     "ts_formats: []\n", "ts_formats"),
    # field_map 引用不存在的分组
    ("name: a\nkind: regex\nline_regex: '^(?P<a>x)$'\n"
     "field_map: {a: ts_raw, ghost: actor}\nts_field: a\n"
     "ts_formats: ['%Y']\n", "不存在的分组"),
    # csv 缺 csv 配置
    ("name: a\nkind: csv\nfield_map: {a: ts_raw}\nts_field: a\n"
     "ts_formats: ['%Y']\n", "csv"),
    # csv header: false(本期不支持,不猜列序)
    ("name: a\nkind: csv\ncsv: {delimiter: ',', header: false}\n"
     "field_map: {a: ts_raw}\nts_field: a\nts_formats: ['%Y']\n", "header"),
    # multiline 坏 start_regex
    ("name: a\nkind: json\nfield_map: {a: ts_raw}\nts_field: a\n"
     "ts_formats: ['%Y']\nmultiline: {start_regex: '^('}\n", "start_regex"),
])
def test_schema_negatives(yaml_text, fragment):
    with pytest.raises(FormatDescError) as exc:
        descriptor.load_desc_text(yaml_text)
    assert fragment in str(exc.value)


def test_schema_negative_top_level_not_mapping():
    with pytest.raises(FormatDescError):
        descriptor.load_desc_text("- just\n- a\n- list\n")


def test_schema_negative_bad_yaml():
    with pytest.raises(FormatDescError) as exc:
        descriptor.load_desc_text("a: [unclosed\n")
    assert "YAML" in str(exc.value)


# ---------------------------------------------------------------- 引擎:regex

def test_engine_regex_positive_fields_and_extras():
    outcomes = list(_engine(OA_REGEX_YAML).parse(OA_REGEX_LINES))
    assert [o.kind for o in outcomes] == ["event", "event"]
    e0 = outcomes[0]
    assert e0.line_no == 1 and e0.dt_local is not None
    assert e0.ts_raw == "2026-08-01 09:00:01"
    n = e0.norm
    assert n["actor"] == "张三" and n["action"] == "登录"
    assert n["object"] == "OA系统" and n["result"] == "成功"
    assert n["extras"]["ip"] == "10.0.0.8"      # 未映射字段进 extras,不丢数据


def test_engine_regex_bad_lines_counted():
    text = OA_REGEX_LINES[0] + "\n这行完全不匹配\n" + \
        "2026-99-99 99:99:99 王五 登录 OA系统 成功 10.0.0.1\n"
    outcomes = list(_engine(OA_REGEX_YAML).parse(text.splitlines()))
    kinds = [o.kind for o in outcomes]
    assert kinds == ["event", "bad", "bad"]      # 不匹配 + 时间解析失败
    assert "时间" in (outcomes[2].reason or "")
    assert outcomes[2].ts_raw == "2026-99-99 99:99:99"   # ts_raw 原样留证


# ---------------------------------------------------------------- 引擎:json

def test_engine_json_positive_and_bad():
    outcomes = list(_engine(JSON_YAML).parse(JSON_LINES))
    kinds = [o.kind for o in outcomes]
    assert kinds == ["event", "event", "bad", "bad"]
    e0 = outcomes[0]
    assert e0.norm["actor"] == "u1" and e0.norm["action"] == "read"
    assert e0.norm["level"] == "INFO"
    assert e0.norm["extras"]["extra_key"] == 7   # 未映射键进 extras
    assert e0.dt_local is not None
    assert outcomes[2].reason and "JSON" in outcomes[2].reason
    assert "非对象" in (outcomes[3].reason or "")


# ---------------------------------------------------------------- 引擎:csv

def test_engine_csv_positive_header_driven():
    outcomes = list(_engine(OA_CSV_YAML).parse(OA_CSV_TEXT.splitlines()))
    assert outcomes[0].kind == "skip"            # 表头 skip 计数(列序依据)
    events = [o for o in outcomes if o.kind == "event"]
    assert len(events) == 3
    n = events[0].norm
    assert n["actor"] == "张三" and n["action"] == "登录"
    assert n["object"] == "OA系统" and n["result"] == "成功"
    assert events[0].ts_raw == "2026-08-01 09:00:01"


def test_engine_csv_field_count_mismatch_bad():
    text = OA_CSV_TEXT + "2026-08-01 10:00:00,王五,登录\n"   # 截断少列
    outcomes = list(_engine(OA_CSV_YAML).parse(text.splitlines()))
    bad = [o for o in outcomes if o.kind == "bad"]
    assert len(bad) == 1 and "字段数" in (bad[0].reason or "")


# ---------------------------------------------------------------- 引擎:多行合并

def test_engine_multiline_continuation_merged():
    outcomes = list(_engine(MULTILINE_YAML).parse(MULTILINE_LINES))
    events = [o for o in outcomes if o.kind == "event"]
    assert len(events) == 2 and not any(o.kind == "bad" for o in outcomes)
    e0 = events[0]
    assert e0.line_no == 1                        # 锚起始物理行号
    assert e0.continuation_lines == 2             # 续行计数如实
    assert "java.lang.RuntimeException" in e0.raw  # 续行并入 raw 全文
    assert "Service.java:42" in e0.raw
    assert e0.norm["level"] == "ERROR" and e0.norm["logger"] == "oa.Service"
    assert e0.norm["message"] == "保存失败"        # ts/字段只在起始行解析
    assert events[1].continuation_lines == 0


def test_engine_multiline_orphan_continuation_is_bad():
    """起始正则未匹配且前面无宿主事件 → 坏行(不静默吞)。"""
    text = "    at nowhere.Here.x(Here.java:1)\n" + "\n".join(MULTILINE_LINES)
    outcomes = list(_engine(MULTILINE_YAML).parse(text.splitlines()))
    assert outcomes[0].kind == "bad" and "无宿主" in (outcomes[0].reason or "")
    assert [o.kind for o in outcomes[1:]] == ["event", "event"]


def test_engine_zero_hit_all_bad():
    """格式选错:全坏行(0 命中由 ingest 判 failed,端到端见 API 用例)。"""
    outcomes = list(_engine(OA_REGEX_YAML).parse(
        ["@@@ alien @@@", "### alien ###"]))
    assert [o.kind for o in outcomes] == ["bad", "bad"]


# ---------------------------------------------------------------- 注册表

def test_registry_desc_enable_only(desc_dir):
    desc_dir.mkdir(parents=True)
    (desc_dir / "oa-regex.yaml").write_text(OA_REGEX_YAML, encoding="utf-8")
    (desc_dir / "app-json.yaml").write_text(
        JSON_YAML.replace("status: enable", "status: draft"), encoding="utf-8")
    mod = find_format("desc:oa-regex")
    assert mod is not None and mod.FORMAT_ID == "desc:oa-regex"
    assert find_format("desc:app-json") is None    # draft 不放行
    assert find_format("desc:nonexistent") is None
    ids = {f["format_id"] for f in list_formats()}
    assert "desc:oa-regex" in ids and "desc:app-json" not in ids


# ---------------------------------------------------------------- 治理链(API)

def _import(client, yaml_text):
    return client.post("/formatdesc:import", json={"yaml_text": yaml_text})


def test_import_always_draft_even_if_yaml_says_enable(client):
    r = _import(client, OA_REGEX_YAML)             # YAML 里写的 enable
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "draft"               # 外部导入一律 draft
    assert find_format("desc:oa-regex") is None    # draft 不可用于解析
    items = client.get("/formatdesc").json()["items"]
    assert {i["name"]: i["status"] for i in items} == {"oa-regex": "draft"}


def test_import_conflict_409_and_bad_schema_400(client):
    assert _import(client, OA_REGEX_YAML).status_code == 201
    r = _import(client, OA_REGEX_YAML)
    assert r.status_code == 409 and "撞 name" in r.json()["detail"]
    r2 = _import(client, "name: x\nkind: grok\n")
    assert r2.status_code == 400 and "kind" in r2.json()["detail"]


def test_draft_confirm_422_honest(client):
    """draft 描述文件 confirm → 422 如实「未启用」(不是 400 未知格式)。"""
    _import(client, OA_REGEX_YAML)
    cid = client.post("/cases", json={"name": "x"}).json()["id"]
    up = client.post(f"/cases/{cid}/sources:upload",
                     files={"file": ("oa.log", OA_REGEX_LINES[0].encode(),
                                     "text/plain")})
    sid = up.json()["sources"][0]["source_id"]
    r = client.post(f"/sources/{sid}/confirm",
                    json={"format_id": "desc:oa-regex"})
    assert r.status_code == 422 and "未启用" in r.json()["detail"]


def test_transition_state_machine(client):
    _import(client, OA_REGEX_YAML)
    # 只能向前:draft → enable 直接跳 → 409
    r = client.post("/formatdesc/oa-regex:transition", json={"to": "enable"})
    assert r.status_code == 409 and "非法流转" in r.json()["detail"]
    # draft → review → enable
    assert client.post("/formatdesc/oa-regex:transition",
                       json={"to": "review"}).json()["status"] == "review"
    # review 仍不可解析(未 enable)
    assert find_format("desc:oa-regex") is None
    assert client.post("/formatdesc/oa-regex:transition",
                       json={"to": "enable"}).json()["status"] == "enable"
    assert find_format("desc:oa-regex") is not None
    # enable → draft(disable 留痕)
    assert client.post("/formatdesc/oa-regex:transition",
                       json={"to": "draft"}).json()["status"] == "draft"
    assert find_format("desc:oa-regex") is None
    # 未知目标状态 / 不存在的描述文件
    assert client.post("/formatdesc/oa-regex:transition",
                       json={"to": "sideways"}).status_code == 400
    assert client.post("/formatdesc/ghost:transition",
                       json={"to": "review"}).status_code == 404


def test_delete_only_draft(client):
    _import(client, OA_REGEX_YAML)
    client.post("/formatdesc/oa-regex:transition", json={"to": "review"})
    r = client.delete("/formatdesc/oa-regex")      # review 不可删
    assert r.status_code == 409 and "仅 draft 可删" in r.json()["detail"]
    client.post("/formatdesc/oa-regex:transition", json={"to": "enable"})
    assert client.delete("/formatdesc/oa-regex").status_code == 409
    # disable 回 draft 后可删
    client.post("/formatdesc/oa-regex:transition", json={"to": "draft"})
    assert client.delete("/formatdesc/oa-regex").json()["deleted"] is True
    assert client.get("/formatdesc/oa-regex").status_code == 404


def test_get_and_export(client):
    _import(client, OA_REGEX_YAML)
    got = client.get("/formatdesc/oa-regex").json()
    assert got["format_id"] == "desc:oa-regex" and got["kind"] == "regex"
    exported = client.get("/formatdesc/oa-regex:export")
    assert exported.status_code == 200
    assert "name: oa-regex" in exported.text       # YAML 原文可带走
    assert client.get("/formatdesc/ghost:export").status_code == 404


def test_validate_endpoint_preview(client):
    # 坏 schema:ok:false,不落盘
    bad = client.post("/formatdesc:validate",
                      json={"yaml_text": "name: x\nkind: grok\n"})
    assert bad.json()["ok"] is False and bad.json()["errors"]
    # 好 schema + 样本试解析预览
    good = client.post("/formatdesc:validate", json={
        "yaml_text": OA_REGEX_YAML, "sample_lines": OA_REGEX_LINES + ["坏行"]})
    body = good.json()
    assert body["ok"] is True
    pv = body["preview"]
    assert pv["parsed"] == 2 and pv["bad_lines"] == 1
    assert pv["events"][0]["norm"]["actor"] == "张三"
    assert pv["bad_samples"]                       # 坏行样本如实列出
    # validate 不写盘
    assert client.get("/formatdesc").json()["items"] == []


def test_governance_audit_trail(client, conn):
    """import/transition/delete 全写审计(哈希链)。"""
    _import(client, OA_REGEX_YAML)
    client.post("/formatdesc/oa-regex:transition", json={"to": "review"})
    client.delete("/formatdesc/oa-regex")  # review 不可删 → 再退 draft 删
    client.post("/formatdesc/oa-regex:transition", json={"to": "enable"})
    client.post("/formatdesc/oa-regex:transition", json={"to": "draft"})
    client.delete("/formatdesc/oa-regex")
    actions = [r["action"] for r in conn.execute(
        "SELECT action FROM audit_log WHERE case_id = 'formatdesc'"
        " ORDER BY id")]
    assert "formatdesc_import" in actions
    assert "formatdesc_transition" in actions
    assert "formatdesc_delete" in actions


# ---------------------------------------------------------------- AI 辅助起草

@pytest.fixture()
def source_with_sample(client):
    cid = client.post("/cases", json={"name": "ai 案"}).json()["id"]
    up = client.post(f"/cases/{cid}/sources:upload",
                     files={"file": ("oa.log",
                                     ("\n".join(OA_REGEX_LINES) + "\n").encode(),
                                     "text/plain")})
    return up.json()["sources"][0]["source_id"]


AI_GOOD_PROPOSAL = {
    "kind": "regex",
    "line_regex": r"^(?P<ts>\S+ \S+)\s+(?P<actor>\S+)\s+(?P<action>\S+)"
                  r"\s+(?P<object>.*?)\s+(?P<result>\S+)\s+(?P<ip>\S+)$",
    "field_map": {"ts": "ts_raw", "actor": "actor", "action": "action",
                  "object": "object", "result": "result"},
    "ts_formats": ["%Y-%m-%d %H:%M:%S"],
}


def _mock_chat(monkeypatch, content):
    monkeypatch.setattr(ai, "chat", lambda messages, **kw: {
        "content": content, "tool_calls": None, "model": "mock-model",
        "usage": {"prompt_tokens": 10, "completion_tokens": 20,
                  "total_tokens": 30}})


def test_ai_draft_happy_path(client, ai_env, monkeypatch, source_with_sample,
                             desc_dir):
    _mock_chat(monkeypatch, json.dumps(AI_GOOD_PROPOSAL,
                                       ensure_ascii=False))
    r = client.post(f"/sources/{source_with_sample}/draft-format", json={})
    assert r.status_code == 200
    body = r.json()
    assert "draft_yaml" in body and "name: todo-rename-me" in body["draft_yaml"]
    assert "人审" in body["draft_yaml"]            # 诚实文案写死
    assert "人审后才生效" in body["note"]
    assert body["usage"]["total_tokens"] == 30     # usage 记账
    # 草稿不落盘:desc 目录依旧空
    assert client.get("/formatdesc").json()["items"] == []


def test_ai_draft_audit_and_usage(client, ai_env, monkeypatch,
                                  source_with_sample, conn):
    _mock_chat(monkeypatch, json.dumps(AI_GOOD_PROPOSAL))
    client.post(f"/sources/{source_with_sample}/draft-format", json={})
    rows = [dict(r) for r in conn.execute(
        "SELECT actor, action, detail_json FROM audit_log"
        " WHERE action = 'formatdesc_ai_draft'")]
    assert len(rows) == 1 and rows[0]["actor"] == "ai"
    detail = json.loads(rows[0]["detail_json"])
    assert detail["ok"] is True
    assert detail["usage"]["total_tokens"] == 30   # usage 进审计


def test_ai_draft_bad_json_502(client, ai_env, monkeypatch,
                               source_with_sample):
    _mock_chat(monkeypatch, "这不是 JSON,抱歉")
    r = client.post(f"/sources/{source_with_sample}/draft-format", json={})
    assert r.status_code == 502 and "ai_bad_json" in r.json()["detail"]


def test_ai_draft_schema_invalid_502(client, ai_env, monkeypatch,
                                     source_with_sample):
    bad = {**AI_GOOD_PROPOSAL,
           "field_map": {"ts": "ts_raw", "actor": "invented_field"}}
    _mock_chat(monkeypatch, json.dumps(bad))
    r = client.post(f"/sources/{source_with_sample}/draft-format", json={})
    assert r.status_code == 502 and "ai_invalid" in r.json()["detail"]
    assert "未知归一字段" in r.json()["detail"]


def test_ai_draft_offline_503(client, ai_env, source_with_sample):
    """offline_lite(无 key,不 mock)→ 503 如实。"""
    r = client.post(f"/sources/{source_with_sample}/draft-format", json={})
    assert r.status_code == 503 and "offline_lite" in r.json()["detail"]


# ---------------------------------------------------------------- 端到端

def test_end_to_end_csv_audit_format(client):
    """合成 OA 审计 CSV(中文)→ import → enable → 上传 → confirm → 解析
    → 字段条件检索 actor 命中。"""
    assert _import(client, OA_CSV_YAML).status_code == 201
    client.post("/formatdesc/oa-demo:transition", json={"to": "review"})
    client.post("/formatdesc/oa-demo:transition", json={"to": "enable"})

    cid = client.post("/cases", json={"name": "端到端"}).json()["id"]
    up = client.post(f"/cases/{cid}/sources:upload",
                     files={"file": ("oa.csv", OA_CSV_TEXT.encode("utf-8"),
                                     "text/csv")},
                     data={"system": "oa-01"})
    sid = up.json()["sources"][0]["source_id"]
    r = client.post(f"/sources/{sid}/confirm",
                    json={"format_id": "desc:oa-demo",
                          "tz_declared": "Asia/Shanghai", "log_type": "audit"})
    assert r.status_code == 200
    r = client.post(f"/sources/{sid}/parse")
    assert r.status_code == 200, r.json()
    report = r.json()
    assert report["parsed"] == 3 and report["bad_lines"] == 0
    assert report["skipped_lines"] == 1            # 表头

    # 字段条件检索:actor=张三 命中 2 条(经单一检索层)
    s = client.get(f"/cases/{cid}/search",
                   params={"field_filters": json.dumps({"actor": "张三"})})
    assert s.status_code == 200
    body = s.json()
    assert body["total"] == 2
    assert all(i["norm"]["actor"] == "张三" for i in body["items"])
    assert body["items"][0]["ts_utc"] is not None  # 时区归一已生效
    # 锚点齐全:源 + 行号 + sha256
    first = body["items"][0]
    assert first["source_id"] == sid and first["line_no"] == 2
    assert first["sha256"]


def test_end_to_end_disable_after_confirm(client):
    """confirm 后被 disable → parse 如实失败(不拿 draft 格式解析)。"""
    _import(client, OA_CSV_YAML)
    client.post("/formatdesc/oa-demo:transition", json={"to": "review"})
    client.post("/formatdesc/oa-demo:transition", json={"to": "enable"})
    cid = client.post("/cases", json={"name": "x"}).json()["id"]
    up = client.post(f"/cases/{cid}/sources:upload",
                     files={"file": ("oa.csv", OA_CSV_TEXT.encode(), "text/csv")})
    sid = up.json()["sources"][0]["source_id"]
    client.post(f"/sources/{sid}/confirm",
                json={"format_id": "desc:oa-demo", "log_type": "audit"})
    client.post("/formatdesc/oa-demo:transition", json={"to": "draft"})
    r = client.post(f"/sources/{sid}/parse")
    assert r.status_code == 400 and "未启用" in r.json()["detail"]


def test_encoding_declared_and_invalid(tmp_path):
    """encoding 键:合法 codec 收;未知编码加载即暴露(GBK 业务日志场景)。"""
    from backend.app.formats import descriptor
    spec = {
        "name": "gbk-demo", "kind": "regex",
        "line_regex": r"^(?P<ts>\S+) (?P<message>.*)$",
        "field_map": {"ts": "ts_raw", "message": "message"},
        "ts_field": "ts", "ts_formats": ["%Y-%m-%d"],
        "encoding": "gbk",
    }
    import yaml as _yaml
    d = tmp_path / "gbk.yaml"
    d.write_text(_yaml.safe_dump(spec, allow_unicode=True), encoding="utf-8")
    compiled = descriptor.load_desc_file(d) if hasattr(descriptor, "load_desc_file") \
        else descriptor.CompiledDesc(descriptor.load_desc_text(d.read_text(encoding="utf-8")))
    assert compiled.encoding == "gbk"
    spec["encoding"] = "not-a-codec"
    d.write_text(_yaml.safe_dump(spec, allow_unicode=True), encoding="utf-8")
    with pytest.raises(descriptor.FormatDescError):
        descriptor.load_desc_text(d.read_text(encoding="utf-8"))


def test_gbk_file_parsed_via_encoding(tmp_path):
    """GBK 字节源文件:按声明编码解析,中文不乱码(不硬猜不替换)。"""
    import yaml as _yaml
    from backend.app.formats import descriptor
    spec = {
        "name": "gbk-demo", "kind": "regex",
        "line_regex": r"^\[(?P<ts>[^\]]+)\] (?P<message>.*)$",
        "field_map": {"ts": "ts_raw", "message": "message"},
        "ts_field": "ts", "ts_formats": ["%Y-%m-%d %H:%M:%S"],
        "encoding": "gbk",
    }
    compiled = descriptor.CompiledDesc(
        descriptor.load_desc_text(_yaml.safe_dump(spec, allow_unicode=True)))
    f = tmp_path / "gbk.log"
    f.write_bytes("[2018-11-07 19:14:04] 错误#1146: 表不存在\n".encode("gbk"))
    from backend.app import ingest
    lines = list(ingest._iter_lines(f, compiled.encoding))
    outcomes = list(compiled.parse(lines))
    ev = [o for o in outcomes if o.kind == "event"]
    assert len(ev) == 1
    assert "错误#1146" in ev[0].norm.get("message", "")


def test_multiline_bounded_truncation(tmp_path):
    """合并上限:超界截断如实标记,后续行成孤儿块(不丢弃不静默)。"""
    import yaml as _yaml
    from backend.app.formats import descriptor
    spec = {
        "name": "ml-cap", "kind": "regex",
        "line_regex": r"^(?P<ts>\d{4}-\d{2}-\d{2}) (?P<message>.*)$",
        "field_map": {"ts": "ts_raw", "message": "message"},
        "ts_field": "ts", "ts_formats": ["%Y-%m-%d"],
        "multiline": {"start_regex": r"^\d{4}-",
                      "max_continuation_lines": 2, "max_block_bytes": 4096},
    }
    compiled = descriptor.CompiledDesc(
        descriptor.load_desc_text(_yaml.safe_dump(spec)))
    lines = ["2026-08-01 first", " cont1", " cont2", " cont3", " cont4",
             "2026-08-02 second"]
    outcomes = list(compiled.parse(lines))
    events = [o for o in outcomes if o.kind == "event"]
    bads = [o for o in outcomes if o.kind == "bad"]
    assert len(events) == 2                      # 首块截断事件 + 第二事件
    first, second = events
    assert first.norm["extras"]["multiline_truncated"] is True
    assert first.continuation_lines == 2         # 只并入 cont1/cont2
    assert second.norm["message"] == "second"
    # 孤儿块首行不匹配 line_regex → 坏行,但整块原文留证+原因标注
    assert len(bads) == 1
    assert "cont3" in bads[0].raw and "cont4" in bads[0].raw
    assert "孤儿续行块" in (bads[0].reason or "")
