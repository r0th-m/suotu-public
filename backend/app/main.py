"""索图 FastAPI 入口(M0 入库/检索 + M1 规则引擎/待审区 + M2 统计规则/联动
+ M3 AI 工具层/L2 播种/L3 精读/KB 解释器 + M4 描述文件治理/AI 起草
+ M4 封存导出/登录认证/树庭实体互查 + M5 交流区/即席聚合
+ M6 AI 设置面板(多厂商,移植自树庭)
+ 运行日志(logging_setup/logview,移植自树庭 v1.2.0:app/error/operation
  三文件,与审计链严格分离)。

M4 起全局认证闸:除 /healthz /auth/login /auth/setup 外全部端点要登录态;
审计锚真人——人动作端点经 auth.current_username 取会话用户名做 actor
(无会话内部调用恒 "system",AI 动作恒 "ai",见 db.append_audit)。

检索一律经 query 单一检索层(AI 工具同此,
见 ai_tools.py),规则引擎全量扫描经 query.scan_events、统计聚合经
query.agg_*,本文件只做参数透传与 HTTP 语义(404/400/409/202),
不另开数据路径。
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, \
    Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import ai, analysis, auth, bridge, chat, config, db, duck, \
    formatdesc, ingest, kb_explainer, logging_setup, logview, query, \
    rules, seal, vault, viewer

# 运行日志(移植自树庭 v1.2.0):绑定 data/logs/ 三个文件(app/error/operation);
# 与审计哈希链严格分离,互不混入
logging_setup.setup_logging()

# 免认证白名单:健康检查 + 登录/首启引导 + 静态前端入口(SPA 页面本身公开,
# React 启动后调 /auth/me 自判登录态再渲染登录页;API 一律认证,语义同树庭)
_AUTH_WHITELIST = {"/healthz", "/auth/login", "/auth/setup"}


def _is_public_path(path: str) -> bool:
    """公开路径:白名单精确命中 / SPA 入口(/) / 静态资产(/assets/*);
    其余一律认证(API)。/mcp 走自己的 Bearer token 闸(MCPGateway 内),
    不进会话白名单——token 认证在网关层完成,这里放行。"""
    if path in _AUTH_WHITELIST or path == "/" or path == "/favicon.ico":
        return True
    if path == "/mcp" or path.startswith("/mcp/"):
        return True                          # MCP 端点:token 闸见 mcp_server
    return path.startswith("/assets/")


def _auth_guard(request: Request) -> None:
    """全局认证闸(app 级依赖;SPA 入口与静态资产公开,API 一律认证)。

    认证通过把用户名挂到 request.state,业务端点经 auth.current_username
    取真人做审计 actor。
    """
    if not _is_public_path(request.url.path):
        request.state.username = auth.require_user(request)


APP_VERSION = "v1.1.0"  # 2026-08-13(MCP 服务端/外发双闸/并行化)

app = FastAPI(title="索图", version=APP_VERSION,
              dependencies=[Depends(_auth_guard)])
app.include_router(auth.router)
app.include_router(logview.router)


# ---- 请求级操作日志(operation.log) + 未捕获异常兜底(error.log) ----
# 静态资产与 / 不记(防刷屏);其余请求一律记 方法/路径/用户名/状态码/耗时。
# 用户名在全局认证闸(_auth_guard)挂到 request.state,中间件在响应后读取。
_OP_SKIP_PREFIXES = ("/assets/",)
_OP_SKIP_PATHS = {"/", "/favicon.ico", "/healthz"}
_OP_SKIP_SUFFIXES = (".js", ".css", ".html", ".htm", ".map", ".ico", ".png",
                     ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".woff",
                     ".woff2", ".ttf", ".eot")


@app.middleware("http")
async def _operation_log_middleware(request: Request, call_next):
    path = request.url.path
    skip = (path in _OP_SKIP_PATHS or path.startswith(_OP_SKIP_PREFIXES)
            or path.endswith(_OP_SKIP_SUFFIXES))
    t0 = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        # 未捕获异常:完整堆栈 + 请求上下文(path/user) → error.log,对外 500
        dur_ms = int((time.monotonic() - t0) * 1000)
        user = getattr(request.state, "username", None) or "-"
        logging_setup.error_logger().error(
            "未捕获异常 %s %s user=%s (%dms)", request.method, path, user,
            dur_ms, exc_info=True)
        if not skip:
            logging_setup.op_logger().info(
                "%s %s user=%s status=500 %dms", request.method, path, user,
                dur_ms)
        return JSONResponse({"detail": "内部错误,已记录 error.log"},
                            status_code=500)
    if not skip:
        dur_ms = int((time.monotonic() - t0) * 1000)
        user = getattr(request.state, "username", None) or "-"
        logging_setup.op_logger().info(
            "%s %s user=%s status=%d %dms",
            request.method, path, user, response.status_code, dur_ms)
    return response


@app.on_event("startup")
def _log_startup() -> None:
    logging_setup.app_logger().info(
        "服务启动 version=%s data_dir=%s log_level=%s",
        app.version, config.data_dir(),
        os.environ.get("SUOTU_LOG_LEVEL", "INFO"))


@app.on_event("shutdown")
def _log_shutdown() -> None:
    logging_setup.app_logger().info("服务关闭 version=%s", app.version)


@app.on_event("startup")
def _recover_zombies() -> None:
    """启动即清理僵尸 analysis run(进程退出导致 running 永卡,2026-08-05 实测)。"""
    analysis.recover_zombie_runs()


@contextmanager
def _conn():
    c = db.connect()
    try:
        yield c
    finally:
        c.close()


def _get_case_or_404(conn: sqlite3.Connection, case_id: str):
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        raise HTTPException(404, f"案件不存在: {case_id}")
    return row


def _get_source_or_404(conn: sqlite3.Connection, source_id: str):
    row = conn.execute("SELECT * FROM log_sources WHERE id = ?",
                       (source_id,)).fetchone()
    if row is None:
        raise HTTPException(404, f"日志源不存在: {source_id}")
    return row


def _source_view(conn: sqlite3.Connection, source_id: str) -> dict:
    row = _get_source_or_404(conn, source_id)
    return {**dict(row), "parse_report": ingest.latest_parse_report(conn, source_id)}


# ------------------------------------------------------------------ cases

class CaseIn(BaseModel):
    name: str


@app.post("/cases")
def create_case(body: CaseIn, actor: str = Depends(auth.current_username)):
    with _conn() as conn:
        case_id = uuid.uuid4().hex
        with conn:
            conn.execute("INSERT INTO cases (id, name, created_at) VALUES (?,?,?)",
                         (case_id, body.name,
                          datetime.now(timezone.utc).isoformat()))
            db.append_audit(conn, case_id, action="case_create", actor=actor,
                            detail={"name": body.name})
        return {"id": case_id, "name": body.name}


@app.get("/cases")
def list_cases():
    with _conn() as conn:
        return {"items": [dict(r) for r in conn.execute(
            "SELECT c.*, COALESCE(p.ai_external_blocked, 0) AS ai_external_blocked"
            " FROM cases c LEFT JOIN case_ai_policy p ON p.case_id = c.id"
            " ORDER BY c.created_at DESC")]}


class CaseAiPolicyIn(BaseModel):
    ai_external_blocked: bool


@app.patch("/cases/{case_id}/ai-policy")
def set_case_ai_policy(case_id: str, body: CaseAiPolicyIn,
                       actor: str = Depends(auth.current_username)):
    """按案件「禁止 AI 外发」开关(2026-08-11,合规底线)。

    开启后本案件一切 online 档 AI 调用被 chat() 硬闸门拒绝
    (external_blocked);本地 Ollama(offline_ai)不受影响。幂等,
    变更进审计哈希链。
    """
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        return ai.set_case_external_blocked(conn, case_id,
                                            body.ai_external_blocked, actor)


@app.get("/cases/{case_id}")
def get_case(case_id: str):
    with _conn() as conn:
        row = _get_case_or_404(conn, case_id)
        sources = [dict(r) for r in conn.execute(
            "SELECT * FROM log_sources WHERE case_id = ? ORDER BY created_at",
            (case_id,))]
        return {**dict(row), "sources": sources}


# ------------------------------------------------------------------ sources

@app.post("/cases/{case_id}/sources:upload")
def upload_source(case_id: str, file: UploadFile = File(...),
                  system: str | None = Form(None),
                  source_note: str | None = Form(None),
                  evidence_kind: str = Form("log"),
                  actor: str = Depends(auth.current_username)):
    """上传日志文件或 zip → 登记 + 指纹建议(只建议,不确认)。

    evidence_kind=supplementary 登记为补充证据(人随时补的材料,
    打标随检索层可查;2026-08-09,20260807 案工作方式沉淀)。
    """
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        try:
            return ingest.register_upload(conn, case_id, file.filename or "upload",
                                          file.file, system=system,
                                          source_note=source_note, actor=actor,
                                          evidence_kind=evidence_kind)
        except ingest.IngestError as e:
            raise HTTPException(e.status, str(e))


@app.get("/sources/{source_id}")
def get_source(source_id: str):
    """源状态 + 登记信息 + 最近一次解析报告。指纹建议在 upload 响应里给。"""
    with _conn() as conn:
        return _source_view(conn, source_id)


class ConfirmIn(BaseModel):
    format_id: str
    tz_declared: str | None = None
    log_type: str = "unknown"


@app.post("/sources/{source_id}/confirm")
def confirm_source(source_id: str, body: ConfirmIn,
                   actor: str = Depends(auth.current_username)):
    with _conn() as conn:
        _get_source_or_404(conn, source_id)
        try:
            return ingest.confirm_source(conn, source_id, body.format_id,
                                         tz_declared=body.tz_declared,
                                         log_type=body.log_type, actor=actor)
        except ingest.IngestError as e:
            raise HTTPException(e.status, str(e))


@app.post("/sources/{source_id}/parse")
def parse_source(source_id: str,
                 actor: str = Depends(auth.current_username)):
    with _conn() as conn:
        _get_source_or_404(conn, source_id)
        try:
            report = ingest.parse_source(conn, source_id, actor=actor)
        except ingest.IngestError as e:
            raise HTTPException(e.status, str(e))
        if report.get("status") == "failed":
            # 如实 422:解析失败不是「成功返回空」
            raise HTTPException(422, report.get("error"))
        return report


@app.get("/sources/{source_id}/lines")
def source_lines(source_id: str, offset: int = Query(0, ge=0),
                 limit: int = Query(200, ge=1, le=2000)):
    """查看器:金库原文带行号(读前哈希校验)。"""
    with _conn() as conn:
        try:
            return viewer.read_lines(conn, source_id, offset=offset, limit=limit)
        except viewer.ViewerError as e:
            raise HTTPException(404, str(e))
        except vault.VaultIntegrityError as e:
            raise HTTPException(409, str(e))


# ------------------------------------------------------------ 检索层透传

@app.get("/cases/{case_id}/search")
def search(case_id: str, q: str | None = None, source_id: str | None = None,
           field_filters: str | None = None,
           ts_from: str | None = None, ts_to: str | None = None,
           limit: int = Query(50, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """单一检索层透传;field_filters 为 JSON 对象串,如 {"status":"404"}。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
    filters = None
    if field_filters:
        try:
            filters = json.loads(field_filters)
            if not isinstance(filters, dict):
                raise ValueError
        except ValueError:
            raise HTTPException(400, "field_filters 须为 JSON 对象串")
    try:
        return query.search(case_id, q=q, source_id=source_id,
                            field_filters=filters,
                            ts_from=ts_from, ts_to=ts_to,
                            limit=limit, offset=offset)
    except ValueError as e:
        raise HTTPException(400, f"时间参数非法: {e}")


@app.get("/cases/{case_id}/stats")
def stats(case_id: str, source_id: str | None = None):
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
    return query.stats(case_id, source_id=source_id)


@app.get("/cases/{case_id}/entities/lookup")
def entity_lookup(case_id: str, value: str, cross_source: bool = False):
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
    return query.entity_lookup(case_id, value, cross_source=cross_source)


@app.get("/cases/{case_id}/aggregate")
def aggregate(case_id: str, field: str, source_id: str | None = None,
              field_filters: str | None = None,
              ts_from: str | None = None, ts_to: str | None = None,
              limit: int = Query(20, ge=1, le=200)):
    """M5 即席聚合(命中驱动二次排查,确定性零 AI):按归一字段 GROUP BY 分布。

    field 白名单闸 = rules.NORM_FIELDS(mini-ECS);其余参数与 /search 同语义
    (同一检索层)。「提取该实体全部事件」「时间窗展开」用 /search 即可。
    """
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
    if field not in rules.NORM_FIELDS:
        raise HTTPException(
            400, f"field 须为归一字段白名单之一: {sorted(rules.NORM_FIELDS)}")
    filters = None
    if field_filters:
        try:
            filters = json.loads(field_filters)
            if not isinstance(filters, dict):
                raise ValueError
        except ValueError:
            raise HTTPException(400, "field_filters 须为 JSON 对象串")
    try:
        return query.aggregate(case_id, field, source_id=source_id,
                               field_filters=filters,
                               ts_from=ts_from, ts_to=ts_to, limit=limit)
    except ValueError as e:
        raise HTTPException(400, f"参数非法: {e}")


# ------------------------------------------------------------ M1 规则/待审区

@app.get("/cases/{case_id}/rules")
def list_rules(case_id: str):
    """规则清单:items=签名规则(M1 契约不动,补 operator:null),
    stats=统计规则(算子+参数)与跨源联动内置条目;加载即校验,坏规则 400。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
    try:
        items = [{**r, "operator": None} for r in rules.list_rules()]
        stats = rules.list_stat_rules() + [rules.CROSS_SOURCE_RULE]
        return {"items": items, "stats": stats}
    except rules.RuleError as e:
        raise HTTPException(e.status, str(e))


class RulesRunIn(BaseModel):
    source_id: str | None = None


@app.post("/cases/{case_id}/rules:run")
def run_rules(case_id: str, body: RulesRunIn | None = None,
              actor: str = Depends(auth.current_username)):
    """L1 全量扫描(签名+统计+跨源,经 query 单一检索层);命中进待审区,
    报告按 signature/stats/cross_source 分段。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        try:
            return rules.run_rules(conn, case_id,
                                   source_id=(body.source_id if body else None),
                                   actor=actor)
        except rules.RuleError as e:
            raise HTTPException(e.status, str(e))


@app.get("/cases/{case_id}/hits")
def list_hits(case_id: str, status: str | None = None,
              severity: str | None = None,
              q: str | None = None,
              limit: int = Query(50, ge=1, le=1000),
              offset: int = Query(0, ge=0)):
    """候选待审区:状态/严重级过滤 + 关键词(rule_id/命中值/摘要/行号)+ 分页。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        try:
            return rules.list_hits(conn, case_id, status=status,
                                   severity=severity, q=q,
                                   limit=limit, offset=offset)
        except rules.RuleError as e:
            raise HTTPException(e.status, str(e))


class ReviewIn(BaseModel):
    note: str | None = None


@app.post("/hits/{hit_id}:accept")
def accept_hit(hit_id: str, body: ReviewIn | None = None,
               actor: str = Depends(auth.current_username)):
    """人审核通过 → 写线索(clues 唯一写入路径);已裁决再裁决 → 409。"""
    with _conn() as conn:
        try:
            return rules.accept_hit(conn, hit_id,
                                    note=(body.note if body else None),
                                    actor=actor)
        except rules.RuleError as e:
            raise HTTPException(e.status, str(e))


@app.post("/hits/{hit_id}:reject")
def reject_hit(hit_id: str, body: ReviewIn | None = None,
               actor: str = Depends(auth.current_username)):
    """人审核驳回 → 状态 rejected + 留痕;线索库不进任何东西。"""
    with _conn() as conn:
        try:
            return rules.reject_hit(conn, hit_id,
                                    note=(body.note if body else None),
                                    actor=actor)
        except rules.RuleError as e:
            raise HTTPException(e.status, str(e))


@app.get("/cases/{case_id}/clues")
def list_clues(case_id: str):
    """线索列表(人审入库的产物)。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        return rules.list_clues(conn, case_id)


@app.get("/hits/{hit_id}/corroborate")
def corroborate(hit_id: str,
                window_seconds: int = Query(300, ge=1, le=86400)):
    """M2 互证:同 system 兄弟源 ±window 内同 path/同 IP 事件;
    ok/none/no_siblings/no_ts 四态如实区分。"""
    with _conn() as conn:
        try:
            return rules.corroborate_hit(conn, hit_id,
                                         window_seconds=window_seconds)
        except rules.RuleError as e:
            raise HTTPException(e.status, str(e))


# ------------------------------------------------------------ M4 描述文件治理

class FormatDescTextIn(BaseModel):
    yaml_text: str


class FormatDescValidateIn(BaseModel):
    yaml_text: str
    sample_lines: list[str] | None = None


class TransitionIn(BaseModel):
    to: str


def _formatdesc_errors(e: Exception) -> HTTPException:
    if isinstance(e, formatdesc.GovernanceError):
        return HTTPException(e.status, str(e))
    return HTTPException(400, str(e))            # FormatDescError(schema)


@app.post("/formatdesc:import", status_code=201)
def import_formatdesc(body: FormatDescTextIn,
                      actor: str = Depends(auth.current_username)):
    """导入描述文件 YAML 全文 → 恒 draft(外部导入永不自动启用,§4.3);
    撞 name 409;schema 不过 400(问题逐条列出)。"""
    with _conn() as conn:
        try:
            return formatdesc.import_desc(conn, body.yaml_text, actor=actor)
        except (formatdesc.GovernanceError, formatdesc.FormatDescError) as e:
            raise _formatdesc_errors(e)


@app.get("/formatdesc")
def list_formatdesc():
    """描述文件清单(含治理状态;坏文件如实标 broken)。"""
    return {"items": formatdesc.list_descs()}


@app.get("/formatdesc/{name}:export", response_class=PlainTextResponse)
def export_formatdesc(name: str):
    """导出落盘 YAML 原文(人可带走/社区交换)。

    注册顺序在 GET /formatdesc/{name} 之前——否则 "x:export" 会被
    普通详情路由当 name 吞掉(Starlette 按注册序匹配)。"""
    try:
        return formatdesc.export_desc(name)
    except formatdesc.GovernanceError as e:
        raise HTTPException(e.status, str(e))


@app.get("/formatdesc/{name}")
def get_formatdesc(name: str):
    try:
        return formatdesc.get_desc(name)
    except (formatdesc.GovernanceError, formatdesc.FormatDescError) as e:
        raise _formatdesc_errors(e)


@app.post("/formatdesc/{name}:transition")
def transition_formatdesc(name: str, body: TransitionIn,
                          actor: str = Depends(auth.current_username)):
    """状态机:draft→review→enable 只许向前;enable→draft 为 disable 留痕。"""
    with _conn() as conn:
        try:
            return formatdesc.transition(conn, name, body.to, actor=actor)
        except (formatdesc.GovernanceError, formatdesc.FormatDescError) as e:
            raise _formatdesc_errors(e)


@app.delete("/formatdesc/{name}")
def delete_formatdesc(name: str,
                      actor: str = Depends(auth.current_username)):
    """删除:仅 draft 可删(enable 先 disable 回 draft);留痕。"""
    with _conn() as conn:
        try:
            return formatdesc.delete_desc(conn, name, actor=actor)
        except (formatdesc.GovernanceError, formatdesc.FormatDescError) as e:
            raise _formatdesc_errors(e)


@app.post("/formatdesc:validate")
def validate_formatdesc(body: FormatDescValidateIn):
    """校验 + 抽样试解析预览(不写盘):schema 不过 ok:false 逐条列出;
    给 sample_lines 则复用真实引擎跑预览(坏行如实)。"""
    return formatdesc.validate_text(body.yaml_text,
                                    sample_lines=body.sample_lines)


class DraftFormatIn(BaseModel):
    sample_lines: int = 30


@app.post("/sources/{source_id}/draft-format")
def draft_format(source_id: str, body: DraftFormatIn | None = None):
    """AI 辅助起草描述文件(§4.4):抽头 N 行 → AI 提议 → schema 校验 →
    草稿 YAML 文本(不落盘!人审编辑后 :import;AI 草稿≠可用格式)。
    offline_lite → 503;AI 坏 JSON/不合 schema → 502 如实。"""
    n = body.sample_lines if body else 30
    with _conn() as conn:
        _get_source_or_404(conn, source_id)
        try:
            return formatdesc.draft_format_ai(conn, source_id, sample_lines=n)
        except ai.AIError as e:
            if e.kind == ai.KIND_OFFLINE:
                raise HTTPException(503, str(e))   # 无 AI 档如实 503
            raise HTTPException(502, f"AI 调用失败({e.kind}): {e}")
        except formatdesc.GovernanceError as e:
            raise HTTPException(e.status, str(e))
        except vault.VaultIntegrityError as e:
            raise HTTPException(409, str(e))


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": APP_VERSION}


# ------------------------------------------------------------ M3 KB 解释器

@app.get("/kb/explain")
def kb_explain(kind: str, value: str):
    """确定性解释:命中 covered:true;未覆盖 covered:false,不硬解释。"""
    try:
        return kb_explainer.explain(kind, value)
    except kb_explainer.KBError as e:
        raise HTTPException(400, str(e))


# ------------------------------------------------------------ M3 AI 状态/分析 run

@app.get("/ai/status")
def ai_status():
    """AI 档位:只报配置在不在,不测活(诚实:配置≠可用)。"""
    return ai.status()


# ------------------------------------------------------------ M6 AI 设置(移植自树庭)

class AiConfigIn(BaseModel):
    provider: str = Field(
        min_length=1,
        description="deepseek|openai|dashscope|zhipu|moonshot|ollama|custom")
    base_url: str | None = Field(default=None, description="缺省用厂商预设")
    model: str | None = Field(default=None,
                              description="缺省用预设首个推荐模型")
    api_key: str | None = Field(default=None,
                                description="空串/缺省 = 不动现有 key")
    consent_external: bool = Field(
        default=False,
        description="在线厂商需显式同意外发(案件数据将发送至第三方模型服务)")


@app.get("/ai/consent")
def get_ai_consent():
    """全局 AI 外发同意状态(2026-08-11 合规闸):只回状态,不回敏感信息。"""
    with _conn() as conn:
        rec = ai.external_consent(conn)
    return {"consented": bool(rec and rec["consented"]),
            "updated_at": rec["updated_at"] if rec else None,
            "actor": rec["actor"] if rec else None}


@app.post("/ai/consent")
def post_ai_consent(actor: str = Depends(auth.current_username)):
    """记录全局 AI 外发同意(一次性,幂等;审计锚操作人)。"""
    with _conn() as conn:
        return ai.record_external_consent(conn, actor)


@app.get("/ai/config")
def get_ai_config():
    """AI 设置读取(系统级一份):只回掩码状态,key 明文永不出后端。"""
    return ai.config_snapshot()


@app.put("/ai/config")
def put_ai_config(body: AiConfigIn,
                  actor: str = Depends(auth.current_username)):
    """AI 设置写回项目根 .env(保留无关行;改完即生效,不重启)。

    审计 ai_config_change 只记厂商/模型/base_url/操作人,永不记 key;
    未知厂商 / needs_key 厂商无 key(新填与已存皆无)→ 422 如实。
    合规闸(2026-08-11):配置结果是 online 档(非 ollama 且有可用 key)
    且全局外发同意未记录时,必须带 consent_external=true(面板显式勾选)
    才允许保存;勾选即落同意记录(审计锚人,一次性)。
    """
    with _conn() as conn:
        prospective_online = body.provider != "ollama" and bool(
            body.api_key or ai._resolve_config()["api_key"])
        if prospective_online and ai.external_consent(conn) is None:
            if not body.consent_external:
                raise HTTPException(
                    422, "在线 AI 将外发案件数据到第三方模型服务:"
                         "保存需带 consent_external=true(面板显式勾选同意)")
            ai.record_external_consent(conn, actor)
    try:
        snap = ai.save_config(body.provider, body.base_url, body.model,
                              body.api_key)
    except ValueError as e:
        raise HTTPException(422, str(e))
    with _conn() as conn:
        with conn:
            db.append_audit(conn, "system", actor=actor,
                            action="ai_config_change", scope="ai",
                            detail={"provider": snap["provider"],
                                    "base_url": snap["base_url"],
                                    "model": snap["model"]})
    return snap


class AiConfigTestIn(BaseModel):
    """测连表单值:测的是这份表单(不写 .env、不写审计)。"""
    provider: str = Field(
        min_length=1,
        description="deepseek|openai|dashscope|zhipu|moonshot|ollama|custom")
    base_url: str | None = Field(default=None, description="缺省用厂商预设")
    model: str | None = Field(default=None,
                              description="缺省用预设首个推荐模型")
    api_key: str | None = Field(default=None,
                                description="空串/缺省 = 沿用已保存的 key 测")


@app.post("/ai/config/test")
def test_ai_config(body: AiConfigTestIn):
    """AI 测连(至多 1 次真实调用):ollama 列本地模型;云端 1-token chat。

    测连与保存解耦:测表单值,**不写 .env、不写 ai_config_change 审计**——
    只有 PUT 保存才写。失败如实分类:
    network / auth(401/403)/ not_found(404)/ rate_limit / server。
    """
    try:
        override = ai.resolve_form_config(body.provider, body.base_url,
                                          body.model, body.api_key)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return ai.test_config(override=override)


class AnalysisRunIn(BaseModel):
    source_id: str
    window_lines: int = 200
    budget: int | None = None          # None=环境缺省;0=不限(用户显式选择)


@app.post("/cases/{case_id}/analysis:run", status_code=202)
def run_analysis(case_id: str, body: AnalysisRunIn,
                 actor: str = Depends(auth.current_username)):
    """发起 L2 播种 + L3 精读(后台线程);同一源 running 中再发 → 409。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        try:
            return analysis.start_analysis(conn, case_id, body.source_id,
                                           window_lines=body.window_lines,
                                           actor=actor, budget=body.budget)
        except analysis.AnalysisError as e:
            raise HTTPException(e.status, str(e))


@app.get("/cases/{case_id}/analysis")
def list_analysis(case_id: str):
    """案件的分析 run 列表(新→旧)。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        return analysis.list_runs(case_id)


@app.get("/analysis/{run_id}")
def get_analysis(run_id: str):
    """run 状态轮询:status/report(锚点/窗口/各窗摘要/综合故事)/usage。"""
    try:
        return analysis.get_run(run_id)
    except analysis.AnalysisError as e:
        raise HTTPException(e.status, str(e))


@app.post("/analysis/{run_id}:abort")
def abort_analysis(run_id: str,
                   actor: str = Depends(auth.current_username)):
    """用户中断:running → aborted(执行线程每窗前检查,熔断联动)。"""
    with _conn() as conn:
        try:
            return analysis.abort_run(conn, run_id, actor=actor)
        except analysis.AnalysisError as e:
            raise HTTPException(e.status, str(e))


# ------------------------------------------------------------ M5 交流区(人机对话)

class ChatSessionIn(BaseModel):
    title: str | None = None
    from_hit_id: str | None = None       # 追问模式:命中详情注入 system 上下文


class ChatMessageIn(BaseModel):
    content: str


@app.post("/cases/{case_id}/chat/sessions", status_code=201)
def create_chat_session(case_id: str, body: ChatSessionIn | None = None,
                        actor: str = Depends(auth.current_username)):
    """建交流区会话;from_hit_id=追问模式(命中必须属本案,防串味)。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        try:
            return chat.create_session(
                conn, case_id, title=(body.title if body else None),
                from_hit_id=(body.from_hit_id if body else None),
                actor=actor)
        except chat.ChatError as e:
            raise HTTPException(e.status, str(e))


@app.get("/cases/{case_id}/chat/sessions")
def list_chat_sessions(case_id: str):
    """会话列表(新→旧,带消息数)。"""
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        return chat.list_sessions(conn, case_id)


@app.get("/chat/sessions/{session_id}/messages")
def get_chat_messages(session_id: str):
    """会话消息(旧→新;AI 轮带 tool_log/usage 快照)。"""
    with _conn() as conn:
        try:
            return chat.get_messages(conn, session_id)
        except chat.ChatError as e:
            raise HTTPException(e.status, str(e))


@app.post("/chat/sessions/{session_id}/messages")
def post_chat_message(session_id: str, body: ChatMessageIn,
                      actor: str = Depends(auth.current_username)):
    """发消息:人消息落库 → AI 回答(熔断四条复用 ai.run_agent)→ 落库。

    AI 产物不落任何业务表(§1):回答只是消息;offline_lite 诚实降级。
    """
    with _conn() as conn:
        try:
            return chat.post_message(conn, session_id, body.content,
                                     actor=actor)
        except chat.ChatError as e:
            raise HTTPException(e.status, str(e))


# ------------------------------------------------------------ M4 封存导出

@app.post("/cases/{case_id}:seal")
def seal_case_endpoint(case_id: str,
                       actor: str = Depends(auth.current_username)):
    """一案可封存(§1):case.db 快照(仅本案行)+ 金库原文 + manifest +
    审计链逐条 → data/exports/<case>_<UTC>.zip。

    只读动作,**不锁案件**(继续分析请重新打包,note 如实标注);
    sealed_at 留痕(案件列表可见);同一案件可多次封存。
    """
    with _conn() as conn:
        _get_case_or_404(conn, case_id)
        try:
            return seal.seal_case(conn, case_id, actor=actor)
        except seal.SealError as e:
            raise HTTPException(e.status, str(e))


@app.post("/seal/verify")
def verify_seal_endpoint(file: UploadFile = File(...)):
    """独立校验封存包:重算金库 sha256 对账 manifest + 审计链逐条验哈希链。

    校验逻辑是纯函数(seal.verify_seal_bytes),不依赖平台数据库——
    脱离平台也能验(独立校验工具精神);坏 zip → 422 如实。
    """
    try:
        return seal.verify_seal_bytes(file.file.read())
    except seal.SealError as e:
        raise HTTPException(e.status, str(e))


# ------------------------------------------------------------ M4 树庭实体互查(§9 实体桥 v2)

@app.get("/bridge/treecourt/entities")
def bridge_treecourt_entities(value: str = Query(min_length=1)):
    """按值互查树庭实体(只读,不写任何东西)。

    树庭不可达/未配置凭据 → available=false + reason 如实(不报错页);
    响应带 source_platform=treecourt(前端联动预留)。
    """
    return bridge.query_entities(value)


# ------------------------------------------------------------ MCP 服务端

try:
    from . import mcp_server
    _MCP_AVAILABLE = True
except ImportError:      # 现场便携包形态(打包时物理剔除 mcp 模块)
    mcp_server = None
    _MCP_AVAILABLE = False


@app.get("/mcp-admin/status")
def mcp_status():
    """MCP 接入状态(开关 + token 数 + 模块在否;内容不敏感)。"""
    if not _MCP_AVAILABLE:
        return {"available": False, "enabled": False, "tokens": []}
    with _conn() as conn:
        return {"available": True,
                "enabled": mcp_server.mcp_enabled(conn),
                "tokens": mcp_server.list_tokens(conn)}


class McpEnabledIn(BaseModel):
    enabled: bool


@app.post("/mcp-admin/enabled")
def mcp_set_enabled(body: McpEnabledIn,
                    actor: str = Depends(auth.current_username)):
    """MCP 端点开关(默认关闭;变更进审计链)。"""
    if not _MCP_AVAILABLE:
        raise HTTPException(404, "本部署形态不含 MCP 模块(现场便携包)")
    with _conn() as conn:
        return mcp_server.set_mcp_enabled(conn, body.enabled, actor)


class McpTokenIn(BaseModel):
    label: str | None = None


@app.post("/mcp-admin/tokens", status_code=201)
def mcp_create_token(body: McpTokenIn,
                     actor: str = Depends(auth.current_username)):
    """签发 MCP API token:明文仅此响应一次,库里只存哈希。"""
    if not _MCP_AVAILABLE:
        raise HTTPException(404, "本部署形态不含 MCP 模块(现场便携包)")
    with _conn() as conn:
        return mcp_server.create_token(conn, actor, body.label)


@app.post("/mcp-admin/tokens/{token_id}/revoke")
def mcp_revoke_token(token_id: str,
                     actor: str = Depends(auth.current_username)):
    if not _MCP_AVAILABLE:
        raise HTTPException(404, "本部署形态不含 MCP 模块(现场便携包)")
    with _conn() as conn:
        ok = mcp_server.revoke_token(conn, token_id, actor)
    if not ok:
        raise HTTPException(404, "token 不存在或已吊销")
    return {"revoked": token_id}


# MCP 服务端点(注册先于 SPA 兜底;鉴权/限频/审计在网关层)。
# 显式 api_route 转发而非 mount:mount 的 path 剥前缀会把请求导去不存在的
# 子路由(405),直接透传 scope 最干净。
# 教训(2026-08-13):SDK 的 StreamableHTTPSessionManager.run() 每实例只能
# 调一次,且任务组绑定事件循环——子 app/管理器必须**随每次 startup 新建**
# (测试多 TestClient 轮转时各自独立),不能 import 时建一次。
_MCP_GATEWAY = None
_MCP_SESSION_CM = None

if _MCP_AVAILABLE:

    @app.on_event("startup")
    async def _mcp_session_start():
        global _MCP_GATEWAY, _MCP_SESSION_CM
        sub, mgr = mcp_server.build_mcp_app()
        _MCP_GATEWAY = mcp_server.MCPGateway(sub)
        _MCP_SESSION_CM = mgr.run()
        await _MCP_SESSION_CM.__aenter__()

    @app.on_event("shutdown")
    async def _mcp_session_stop():
        global _MCP_GATEWAY, _MCP_SESSION_CM
        if _MCP_SESSION_CM is not None:
            await _MCP_SESSION_CM.__aexit__(None, None, None)
        _MCP_SESSION_CM = None
        _MCP_GATEWAY = None

    @app.api_route("/mcp", methods=["GET", "POST", "DELETE"])
    async def mcp_endpoint(request: Request):
        if _MCP_GATEWAY is None:           # 未 startup(不应发生)如实 503
            raise HTTPException(503, "MCP 服务未初始化")
        await _MCP_GATEWAY(request.scope, request.receive, request._send)


# ---- 前端静态托管(M0 单端口形态:dist 存在即挂载;API 路由注册在前优先) ----
from pathlib import Path

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        """SPA 兜底:dist 里存在的文件直发,其余回 index.html;
        API 路径已在上方注册,优先级高于本兜底。"""
        candidate = (_DIST / full_path).resolve()
        if full_path and candidate.is_file() and _DIST in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(_DIST / "index.html")
