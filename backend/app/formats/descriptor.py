"""自定义格式描述文件引擎(SUOTU_DESIGN §4.3,数据层兜底)。

描述文件是数据不是代码:YAML 声明 kind(regex|json|csv)/line_regex/
field_map/ts_field/ts_formats/multiline,本模块「加载即校验」(schema 不过
一律 FormatDescError,零静默),编译成与内置格式同契约的 parse() 驱动对象
(CompiledDesc,可直接进 ingest 三段式管线)。

schema(backend/formats/desc/*.yaml 或 SUOTU_FORMATDESC_DIR 指向目录):
  name: 唯一小写连字符;format_id = "desc:<name>"
  kind: regex|json|csv
  line_regex: kind=regex 必填,命名分组覆盖每行结构
  csv: {delimiter, header}   kind=csv 必填;本期仅支持 header: true
       (无表头则列名无依据,不猜列序)
  field_map: {源分组/JSON键/CSV列: 归一字段}
  ts_field: field_map 中映射到 ts_raw 的那个源字段(行内时间)
  ts_formats: strptime 格式列表,非空,逐个试
  multiline: {start_regex} 可选;不匹配的非空行并入上一事件 raw(续行)
  status: draft|review|enable(治理状态,流转见 formatdesc.py)
  note: 格式出处(诚实标注)

纪律:
- 归一字段词表固定(mini-ECS,见 NORM_VOCAB);保留映射值 "ts_raw" 表示
  该源字段是行内时间——解析进 ts_raw/dt_local,不进 norm;
- field_map 未覆盖的源字段进 extras,不丢数据(§4.5);
- 多行合并:ts 只在起始行解析;续行计数如实记 continuation_lines;
  起始正则未匹配且前面无宿主事件 → 坏行(不静默吞);
  空行恒 skip(不打断也不并入多行块,与单行模式同语义);
- 坏行零静默与内置格式同;非空文件 0 命中由 ingest 统一判 failed
  (与内置格式同一条路径,不另搞一套);
- ts_formats 的格式串本身无法离线验证(strptime 是逐值解析),坏格式
  只会在解析时如实表现为坏行——加载校验只保证「非空字符串列表」,
  此边界如实标注;
- 治理状态机不在这里:find_enabled 只放行 status==enable 的文件,
  draft/review 一律不可用于解析(判断权归人,confirm 时如实 422,
  见 ingest.confirm_source)。
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

import yaml

from .base import LineOutcome

# 归一字段词表(mini-ECS,§4.5):web 族 + 审计族 + 通用族
NORM_VOCAB = {
    # web 族
    "src_ip", "method", "path", "query", "status", "bytes", "ua", "referer",
    # 审计族
    "actor", "action", "object", "result", "detail",
    # 通用族(中间件/杂项)
    "level", "logger", "message", "exception",
}
# 保留映射值:行内时间字段(进 ts_raw/dt_local,不进 norm)
TS_NORM = "ts_raw"

KINDS = {"regex", "json", "csv"}
STATUSES = {"draft", "review", "enable"}

# schema 允许的顶层键(未知键一律报错,加载即校验)
TOP_KEYS = {"name", "title", "kind", "line_regex", "json", "csv",
            "field_map", "ts_field", "ts_formats", "multiline",
            "status", "note", "encoding"}
CSV_KEYS = {"delimiter", "header"}
MULTILINE_KEYS = {"start_regex", "max_continuation_lines", "max_block_bytes"}

_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


class FormatDescError(Exception):
    """描述文件 schema / 加载失败的明确原因(缺字段/未知键/坏正则等)。"""


def desc_dir() -> Path:
    """描述文件目录:默认 backend/formats/desc,SUOTU_FORMATDESC_DIR 可覆盖
    (测试隔离用;配置现读不缓存,同 config.py 纪律)。

    2026-08-05 实测修复:曾误解析到 backend/app/formats/desc(parents[1]),
    与出厂目录 backend/formats/desc 分裂成两处(治理状态两边漂移);
    parents[2]=backend 才对。"""
    return Path(os.environ.get(
        "SUOTU_FORMATDESC_DIR",
        str(Path(__file__).resolve().parents[2] / "formats" / "desc")))


# ------------------------------------------------------------------ schema 校验

def validate_desc(data) -> dict:
    """加载即校验:任何一项不过 → FormatDescError(问题全部列出,一次说清)。

    通过则原样返回 dict(调用方自行取用)。纯函数,不碰盘。
    """
    problems: list[str] = []
    if not isinstance(data, dict):
        raise FormatDescError("描述文件须为 YAML 映射(顶层是键值对)")

    unknown = sorted(set(data) - TOP_KEYS)
    if unknown:
        problems.append(f"未知键 {unknown}(允许: {sorted(TOP_KEYS)})")

    name = data.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        problems.append("name 缺失或非法(须小写连字符,如 oa-audit-demo)")

    kind = data.get("kind")
    if kind not in KINDS:
        problems.append(f"kind 缺失或未知: {kind!r}(允许: {sorted(KINDS)})")

    if "title" in data and not isinstance(data["title"], str):
        problems.append("title 须为字符串")
    if "note" in data and not isinstance(data["note"], str):
        problems.append("note 须为字符串")
    if "json" in data and not isinstance(data["json"], bool):
        problems.append("json 键只接受布尔值(kind=json 的声明位)")

    # encoding:声明源文件编码(缺省 utf-8;GBK 业务日志是常态,mix_logs 实测)
    enc = data.get("encoding")
    if enc is not None:
        if not isinstance(enc, str) or not enc.strip():
            problems.append("encoding 须为非空字符串(如 gbk/utf-8)")
        else:
            import codecs
            try:
                codecs.lookup(enc.strip())
            except LookupError:
                problems.append(f"encoding 未知编码: {enc!r}(按 Python codec 名)")

    status = data.get("status", "draft")
    if status not in STATUSES:
        problems.append(
            f"status 未知: {status!r}(允许: {sorted(STATUSES)})")

    # kind 专属键
    line_re = None
    if kind == "regex":
        raw_re = data.get("line_regex")
        if not isinstance(raw_re, str) or not raw_re:
            problems.append("kind=regex 缺 line_regex")
        else:
            try:
                line_re = re.compile(raw_re)
                if not line_re.groupindex:
                    problems.append("line_regex 无命名分组(须 (?P<名>...) 覆盖"
                                    "每行结构)")
            except re.error as e:
                problems.append(f"line_regex 编译失败: {e}")
    if kind == "csv":
        csv_spec = data.get("csv")
        if not isinstance(csv_spec, dict):
            problems.append("kind=csv 缺 csv 配置({delimiter, header})")
        else:
            bad_csv_keys = sorted(set(csv_spec) - CSV_KEYS)
            if bad_csv_keys:
                problems.append(
                    f"csv 含未知键 {bad_csv_keys}(允许: {sorted(CSV_KEYS)})")
            delim = csv_spec.get("delimiter", ",")
            if not isinstance(delim, str) or not delim:
                problems.append("csv.delimiter 须为非空字符串")
            if csv_spec.get("header") is not True:
                problems.append("csv.header 本期仅支持 true(带表头;"
                                "无表头则列名无依据,不猜列序)")

    # field_map / ts_field / ts_formats
    field_map = data.get("field_map")
    ts_field = data.get("ts_field")
    if not isinstance(field_map, dict) or not field_map:
        problems.append("field_map 缺失或为空({源字段: 归一字段})")
    else:
        bad_norm = sorted({v for v in field_map.values()
                           if v not in NORM_VOCAB and v != TS_NORM})
        if bad_norm:
            problems.append(
                f"field_map 含未知归一字段 {bad_norm}"
                f"(允许: {sorted(NORM_VOCAB)} + 保留值 {TS_NORM})")
        ts_keys = sorted(k for k, v in field_map.items() if v == TS_NORM)
        if not ts_keys:
            problems.append(f"field_map 缺时间字段(须有且仅有一个源字段映射到 "
                            f"{TS_NORM})")
        elif len(ts_keys) > 1:
            problems.append(f"field_map 多个源字段映射到 {TS_NORM}: "
                            f"{ts_keys}(时间字段唯一)")
        if not isinstance(ts_field, str) or ts_field not in field_map:
            problems.append("ts_field 缺失或不在 field_map 中"
                            "(须指向映射到 ts_raw 的那个源字段)")
        elif field_map.get(ts_field) != TS_NORM:
            problems.append(
                f"ts_field 指向的 {ts_field!r} 未映射到 {TS_NORM}")
        if kind == "regex" and line_re is not None:
            bad_groups = sorted(set(field_map) - set(line_re.groupindex))
            if bad_groups:
                problems.append(
                    f"field_map 引用了 line_regex 不存在的分组 {bad_groups}")

    ts_formats = data.get("ts_formats")
    if (not isinstance(ts_formats, list) or not ts_formats
            or not all(isinstance(f, str) and f for f in ts_formats)):
        problems.append("ts_formats 须为非空字符串列表(strptime 格式)")

    multiline = data.get("multiline")
    if multiline is not None:
        if not isinstance(multiline, dict):
            problems.append("multiline 须为映射({start_regex})")
        else:
            bad_ml = sorted(set(multiline) - MULTILINE_KEYS)
            if bad_ml:
                problems.append(
                    f"multiline 含未知键 {bad_ml}"
                    f"(允许: {sorted(MULTILINE_KEYS)})")
            start = multiline.get("start_regex")
            if not isinstance(start, str) or not start:
                problems.append("multiline 缺 start_regex")
            else:
                try:
                    re.compile(start)
                except re.error as e:
                    problems.append(f"multiline.start_regex 编译失败: {e}")
            # 合并上限(2026-08-05 SmartBI 双格式实测:无界合并出 4.8MB
            # 单事件,DuckDB COPY 2MB 行限直接炸;必须有界)
            for key, lo, hi in (("max_continuation_lines", 1, 100000),
                                ("max_block_bytes", 1024, 1_900_000)):
                v = multiline.get(key)
                if v is not None and (not isinstance(v, int)
                                      or isinstance(v, bool)
                                      or not lo <= v <= hi):
                    problems.append(
                        f"multiline.{key} 须为 {lo}..{hi} 的整数")

    if problems:
        raise FormatDescError("描述文件校验未过: " + "; ".join(problems))
    return data


# ------------------------------------------------------------------ 编译驱动对象

class CompiledDesc:
    """描述文件编译产物:与内置解析器模块同契约(FORMAT_ID/NAME/parse)。"""

    def __init__(self, spec: dict):
        self.spec = spec
        self.name = spec["name"]
        self.FORMAT_ID = f"desc:{self.name}"
        self.NAME = spec.get("title") or self.name
        self.kind = spec["kind"]
        self.field_map: dict = dict(spec["field_map"])
        self.ts_field: str = spec["ts_field"]
        self.ts_formats: list[str] = list(spec["ts_formats"])
        self._line_re = (re.compile(spec["line_regex"])
                         if self.kind == "regex" else None)
        csv_spec = spec.get("csv") or {}
        self._delimiter = csv_spec.get("delimiter", ",")
        ml = spec.get("multiline") or {}
        self._start_re = (re.compile(ml["start_regex"])
                          if ml.get("start_regex") else None)
        # 合并上限(无界合并会出 MB 级单事件,DuckDB COPY 2MB 行限炸库)
        self._max_cont: int = int(ml.get("max_continuation_lines", 2000))
        self._max_bytes: int = int(ml.get("max_block_bytes", 1_000_000))
        # 源文件编码(描述文件声明,ingest 读金库时按此解码;缺省 utf-8)
        self.encoding: str = (spec.get("encoding") or "utf-8").strip()
        self._columns: list[str] | None = None   # csv 表头(每趟 parse 现读)

    # ---- 三种 kind 的「行 → 源字段 dict」 ----

    def _fields_regex(self, raw: str):
        m = self._line_re.match(raw)
        if m is None:
            return None, "不匹配 line_regex 行式"
        return {k: v for k, v in m.groupdict().items() if v is not None}, None

    def _fields_json(self, raw: str):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            return None, f"行内 JSON 解析失败: {e.msg}"
        if not isinstance(obj, dict):
            return None, "行内 JSON 非对象(每行须为一个 JSON 对象)"
        return obj, None

    def _fields_csv(self, raw: str):
        cells = next(csv.reader(io.StringIO(raw),
                                delimiter=self._delimiter))
        if self._columns is None:
            return None, "缺表头(header 未读到,不猜列序)"
        if len(cells) != len(self._columns):
            return None, (f"字段数 {len(cells)} 与表头 {len(self._columns)} "
                          "不一致(截断/多列)")
        return dict(zip(self._columns, cells)), None

    def _fields_of(self, raw: str):
        if self.kind == "regex":
            return self._fields_regex(raw)
        if self.kind == "json":
            return self._fields_json(raw)
        return self._fields_csv(raw)

    # ---- 源字段 dict → LineOutcome(field_map 落归一/extras + 时间解析) ----

    def _build(self, line_no: int, raw: str, fields: dict) -> LineOutcome:
        if self.ts_field not in fields:
            return LineOutcome(line_no, raw, "bad",
                               reason=f"缺时间字段 {self.ts_field!r}")
        norm: dict = {}
        extras: dict = {}
        ts_val = None
        for key, value in fields.items():
            target = self.field_map.get(key)
            if target is None:
                extras[key] = value            # 未映射字段进 extras,不丢数据
            elif target == TS_NORM:
                ts_val = value
            else:
                norm[target] = value
        ts_text = None if ts_val is None else str(ts_val)
        dt_local = None
        for fmt in self.ts_formats:            # 逐个格式试,全失败即坏行
            try:
                dt_local = datetime.strptime(ts_text or "", fmt)
                break
            except ValueError:
                continue
        if dt_local is None:
            return LineOutcome(line_no, raw, "bad", ts_raw=ts_text,
                               reason=f"时间解析失败(字段 {self.ts_field!r},"
                                      "ts_formats 全部不匹配)")
        if extras:
            norm["extras"] = extras
        return LineOutcome(line_no, raw, "event",
                           ts_raw=ts_text, dt_local=dt_local, norm=norm)

    def _parse_single(self, line_no: int, raw: str) -> LineOutcome:
        fields, err = self._fields_of(raw)
        if err is not None:
            return LineOutcome(line_no, raw, "bad", reason=err)
        return self._build(line_no, raw, fields)

    def _finish_block(self, start_line: int, parts: list[str],
                      truncated: bool = False, orphan: bool = False) -> LineOutcome:
        """多行块收尾:只在起始行解析,raw 合并续行全文,计数如实。
        truncated=合并超上限被截(如实标记);orphan=截断后无宿主的
        孤儿续行块(同样如实标记,不静默不丢弃)。"""
        o = self._parse_single(start_line, parts[0])
        o.raw = "\n".join(parts)               # 坏行也保留整块原文留证
        if o.kind == "event":
            o.continuation_lines = len(parts) - 1
            if truncated:
                o.norm.setdefault("extras", {})["multiline_truncated"] = True
            if orphan:
                o.norm.setdefault("extras", {})["continuation_orphan"] = True
        else:
            # 坏行同样如实标注截断/孤儿(原文已在 raw 留证)
            marks = []
            if truncated:
                marks.append("合并超上限被截")
            if orphan:
                marks.append("孤儿续行块(截断后无宿主)")
            if marks:
                o.reason = (o.reason or "") + ";" + ";".join(marks)
        return o

    # ---- 与内置格式同契约的 parse() ----

    def parse(self, lines: Iterable[str]) -> Iterator[LineOutcome]:
        it = enumerate(lines, 1)

        # csv:首条非空行是表头(skip 计数),列序以表头为准不猜
        if self.kind == "csv":
            self._columns = None
            for line_no, raw in it:
                raw = raw.rstrip("\r\n")
                if not raw.strip():
                    yield LineOutcome(line_no, raw, "skip", reason="空行")
                    continue
                self._columns = next(csv.reader(
                    io.StringIO(raw), delimiter=self._delimiter))
                yield LineOutcome(line_no, raw, "skip",
                                  reason="CSV 表头(列序依据)")
                break

        start_re = self._start_re
        # block = [起始行号, [行原文...], 已合并字节数, orphan 标记]
        block: list | None = None
        for line_no, raw in it:
            raw = raw.rstrip("\r\n")
            if not raw.strip():
                # 空行恒 skip:不打断也不并入多行块(语义如实,不脑补)
                yield LineOutcome(line_no, raw, "skip", reason="空行")
                continue
            if start_re is None:
                yield self._parse_single(line_no, raw)
                continue
            if start_re.match(raw):
                if block is not None:
                    yield self._finish_block(block[0], block[1],
                                             orphan=block[3])
                block = [line_no, [raw], len(raw), False]
            elif block is not None:
                # 合并上限:超界即截断封块(truncated 如实),当前行作孤儿块
                # 新起——双格式混排文件(JULI+应用 log4j 共写 catalina.out)
                # 不允许无界合并出 MB 级单事件(DuckDB COPY 2MB 行限会炸)
                if len(block[1]) - 1 >= self._max_cont or \
                        block[2] + len(raw) > self._max_bytes:
                    yield self._finish_block(block[0], block[1],
                                             truncated=True, orphan=block[3])
                    block = [line_no, [raw], len(raw), True]
                else:
                    block[1].append(raw)       # 续行并入上一事件
                    block[2] += len(raw)
            else:
                yield LineOutcome(line_no, raw, "bad",
                                  reason="续行无宿主事件(起始正则未匹配,"
                                         "前面没有可并入的事件)")
        if block is not None:
            yield self._finish_block(block[0], block[1], orphan=block[3])


# ------------------------------------------------------------------ 目录装载

def load_desc_text(yaml_text: str) -> dict:
    """YAML 全文 → 校验过的 spec dict(YAML 坏/schema 坏 → FormatDescError)。"""
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise FormatDescError(f"YAML 解析失败: {e}") from e
    return validate_desc(data)


def desc_path(name: str) -> Path:
    return desc_dir() / f"{name}.yaml"


def desc_status(name: str) -> str | None:
    """描述文件当前治理状态;文件不存在 → None;文件坏 → 如实 'broken'
    (损坏不由本函数抛,装载/解析路径才抛 FormatDescError)。"""
    path = desc_path(name)
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return "broken"
    if not isinstance(data, dict):
        return "broken"
    st = data.get("status", "draft")
    return st if st in STATUSES else "broken"


def find_enabled(name: str) -> CompiledDesc | None:
    """desc:<name> 的解析器装载:仅 status==enable 放行;draft/review/
    不存在 → None(调用方如实报「未启用/未知」,不猜)。坏文件 →
    FormatDescError(加载即校验,不带病解析)。"""
    path = desc_path(name)
    if not path.is_file():
        return None
    spec = load_desc_text(path.read_text(encoding="utf-8"))
    if spec.get("status", "draft") != "enable":
        return None
    return CompiledDesc(spec)


def list_enabled() -> list[dict]:
    """enable 状态的描述文件清单(并进注册表 list_formats,人手选可见)。

    扫描容错:坏 YAML/非 enable 一律跳过(它们本来就不可用于解析;
    损坏的完整暴露在 formatdesc 治理端点的清单里,不在注册表面上炸)。
    """
    out: list[dict] = []
    d = desc_dir()
    if not d.is_dir():
        return out
    for path in sorted(d.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("status", "draft") != "enable":
            continue
        name = data.get("name") or path.stem
        out.append({"format_id": f"desc:{name}",
                    "name": data.get("title") or name})
    return out
