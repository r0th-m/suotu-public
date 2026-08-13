"""运行日志系统测试(移植自树庭 v1.2.0):三类日志/轮转/敏感打码/
operation 中间件/错误兜底/认证事件/日志 API/诊断包/AI 调用摘要。

红线断言:key/口令/token 永不进日志(全部用假值);审计链与运行日志严格分离。
"""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.app import ai, db, logging_setup
from backend.app.main import app

# 测试用假凭据(非真实 key;断言行里搜不到这些值即打码生效)
FAKE_KEY = "sk-faketestkey0123456789abcdef"
FAKE_TOKEN = "faketoken0123456789abcdef"
FAKE_PASSWORD = "FakePass#12345"


@pytest.fixture()
def logs(data_dir):
    """每个测试独立的 data/logs/(setup_logging 可重入,按当前 SUOTU_DATA_DIR 重绑)。"""
    return logging_setup.setup_logging()


def _read(kind: str) -> str:
    p = logging_setup.log_path(kind)
    return p.read_text(encoding="utf-8") if p.is_file() else ""


# ==================== 三类日志写入与分文件路由 ====================

def test_three_log_files_written(logs):
    logging_setup.app_logger().info("运行心跳测试")
    logging_setup.error_logger().error("错误测试")
    logging_setup.op_logger().info("GET /x user=tester status=200 1ms")
    assert "运行心跳测试" in _read("app")
    assert "错误测试" in _read("error")
    assert "GET /x user=tester" in _read("operation")
    # 各归其位:不串文件
    assert "错误测试" not in _read("app")
    assert "运行心跳测试" not in _read("operation")
    # 格式含级别与 logger 名
    assert "INFO" in _read("app") and "suotu.app" in _read("app")


def test_run_logs_never_touch_audit(logs, conn):
    """红线:运行日志与审计哈希链严格分离——写日志不产生任何审计行。"""
    logging_setup.app_logger().info("纯排障日志")
    logging_setup.error_logger().error("纯错误日志")
    n = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
    assert n == 0


def test_log_level_env(data_dir, monkeypatch):
    monkeypatch.setenv("SUOTU_LOG_LEVEL", "WARNING")
    logging_setup.setup_logging()
    logging_setup.app_logger().info("不应落盘")
    logging_setup.app_logger().warning("应落盘")
    content = _read("app")
    assert "不应落盘" not in content
    assert "应落盘" in content


# ==================== 轮转 ====================

def test_rotation(data_dir):
    logging_setup.setup_logging(max_bytes=400, backup_count=2)
    log = logging_setup.app_logger()
    for i in range(60):
        log.info("轮转填充行 %03d %s", i, "x" * 60)
    rotated = logging_setup.log_path("app").with_name("app.log.1")
    assert rotated.is_file()                       # 轮转生效,旧段保留
    assert logging_setup.log_path("app").is_file()
    # 备份数上限 2:不产生 app.log.3
    assert not logging_setup.log_path("app").with_name("app.log.3").exists()


# ==================== 敏感信息打码(红线,断言级) ====================

def test_sensitive_values_masked(logs):
    log = logging_setup.app_logger()
    log.info("配置 api_key=%s 完成", FAKE_KEY)
    log.info("请求头 Authorization: Bearer %s", FAKE_TOKEN)
    log.info("登录 password=%s", FAKE_PASSWORD)
    log.info("Cookie: suotu_session=%s", FAKE_TOKEN)
    content = _read("app")
    assert FAKE_KEY not in content
    assert FAKE_TOKEN not in content
    assert FAKE_PASSWORD not in content
    assert content.count("***") >= 4               # 打码标记在


def test_sensitive_mask_in_exception(logs):
    """异常消息带 key 也打码(堆栈文本一并过过滤器)。"""
    try:
        raise RuntimeError(f"调用失败 key={FAKE_KEY}")
    except RuntimeError:
        logging_setup.error_logger().error("带异常", exc_info=True)
    content = _read("error")
    assert FAKE_KEY not in content
    assert "Traceback" in content                  # 堆栈保留


# ==================== operation.log 中间件 ====================

def test_operation_log_has_username(logs, auth_session):
    client = TestClient(app)
    r = client.get("/cases")
    assert r.status_code == 200
    content = _read("operation")
    assert "GET /cases user=tester status=200" in content
    assert "ms" in content                          # 带耗时


def test_operation_log_records_error_status(logs):
    client = TestClient(app)
    r = client.get("/cases/不存在的id")
    assert r.status_code == 404
    assert "status=404" in _read("operation")


def test_root_and_assets_skipped(logs):
    """静态资产 /assets 与 / 不记(防刷屏)。"""
    client = TestClient(app)
    client.get("/")
    client.get("/assets/index-nope.js")
    client.get("/favicon.ico")
    content = _read("operation")
    assert "GET / " not in content
    assert "/assets/" not in content
    assert "favicon" not in content


def test_uncaught_exception_to_error_log(logs):
    """未捕获异常:error.log 带完整堆栈 + 请求上下文,对外 500 不泄露。"""
    from fastapi import Depends
    from fastapi.routing import APIRoute

    from backend.app.main import _auth_guard

    def _boom():
        raise RuntimeError(f"boom-日志测试异常 key={FAKE_KEY}")

    # 插队到路由表最前,防 SPA 兜底路由抢先匹配
    app.router.routes.insert(0, APIRoute(
        "/_boom_test_logging", _boom, dependencies=[Depends(_auth_guard)]))

    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/_boom_test_logging")
    assert r.status_code == 500
    content = _read("error")
    assert "boom-日志测试异常" in content
    assert "Traceback" in content                   # 完整堆栈
    assert "user=tester" in content                 # 请求上下文
    assert FAKE_KEY not in content                  # 异常里的 key 同样打码
    assert "status=500" in _read("operation")


# ==================== 认证事件(不记口令) ====================

def test_login_events_logged_without_password(logs):
    client = TestClient(app)
    r = client.post("/auth/login",
                    json={"username": "tester", "password": FAKE_PASSWORD})
    assert r.status_code == 401                     # 错口令
    r = client.post("/auth/login",
                    json={"username": "tester", "password": "Tester#2026pass"})
    assert r.status_code == 200
    content = _read("app")
    assert "登录失败(凭据不符) user=tester" in content
    assert "登录成功 user=tester" in content
    assert FAKE_PASSWORD not in content             # 口令永不进日志
    assert "Tester#2026pass" not in content


# ==================== 日志查看 API ====================

def test_logs_api_requires_auth(logs):
    client = TestClient(app)
    client.cookies.clear()
    assert client.get("/logs", params={"file": "app"}).status_code == 401
    assert client.get("/logs/files").status_code == 401
    assert client.post("/diagnostics/bundle").status_code == 401


def test_logs_api_tail_and_keyword(logs):
    log = logging_setup.app_logger()
    for i in range(50):
        log.info("line-%02d", i)
    client = TestClient(app)
    r = client.get("/logs", params={"file": "app", "lines": 10})
    assert r.status_code == 200
    body = r.json()
    assert len(body["lines"]) == 10                 # 只取尾部 10 行
    assert "line-49" in body["lines"][-1]
    assert "line-40" in body["lines"][0]
    r = client.get("/logs", params={"file": "app", "lines": 50, "q": "line-1"})
    lines = r.json()["lines"]
    assert lines and all("line-1" in ln for ln in lines)   # 关键字过滤
    assert not any("line-2" in ln for ln in lines)


def test_logs_api_invalid_file(logs):
    """file 白名单:非法名 400,文件名永不拼进路径(防目录穿越)。"""
    client = TestClient(app)
    assert client.get("/logs", params={"file": "../../etc/passwd"}).status_code == 400
    assert client.get("/logs", params={"file": "case.db"}).status_code == 400


def test_logs_files_api(logs):
    logging_setup.app_logger().info("有内容")
    client = TestClient(app)
    r = client.get("/logs/files")
    assert r.status_code == 200
    files = {f["file"]: f for f in r.json()["files"]}
    assert set(files) == {"app", "error", "operation"}
    assert files["app"]["exists"] and files["app"]["size"] > 0
    assert files["app"]["mtime"]


# ==================== AI 调用摘要(绝不记 prompt/回答) ====================

def test_ai_call_log_summary_no_prompt(logs, ai_env):
    """AI 调用日志只记元信息(模型/tokens/耗时/调用者),不含 prompt/回答内容。"""
    ai_env.setenv("AI_PROVIDER", "deepseek")
    ai_env.setenv("AI_API_KEY", FAKE_KEY)
    ai_env.setenv("AI_MODEL", "deepseek-v4-flash")

    def fake_call(messages, **kw):
        return {"content": "AI回答内容SECRET-ANSWER",
                "tool_calls": None,
                "model": "deepseek-v4-flash",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5,
                          "total_tokens": 15}}

    ai_env.setattr(ai, "_call_api", fake_call)
    ai.chat([{"role": "user", "content": "案件秘密SECRET-PROMPT"}])
    content = _read("app")
    assert "AI 调用 run=direct" in content
    assert "model=deepseek-v4-flash" in content
    assert "tokens=15" in content
    assert "ms" in content                          # 带耗时
    assert "SECRET-PROMPT" not in content           # prompt 不进日志
    assert "SECRET-ANSWER" not in content           # 回答不进日志
    assert FAKE_KEY not in content                  # key 不进日志


def test_ai_call_failure_logged(logs, ai_env):
    """AI 调用失败同样落摘要(分类+耗时),不记消息内容。"""
    ai_env.setenv("AI_PROVIDER", "deepseek")
    ai_env.setenv("AI_API_KEY", FAKE_KEY)
    ai_env.setenv("AI_MODEL", "deepseek-v4-flash")

    def boom(messages, **kw):
        raise ai.AIError(ai.KIND_NETWORK, "AI 服务不可达/超时(URLError)")

    ai_env.setattr(ai, "_call_api", boom)
    with pytest.raises(ai.AIError):
        ai.chat([{"role": "user", "content": "SECRET-PROMPT"}])
    content = _read("app")
    assert "AI 调用失败" in content and "kind=network" in content
    assert "SECRET-PROMPT" not in content


# ==================== 一键诊断包 ====================

def test_diagnostics_bundle(logs, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "deepseek")
    monkeypatch.setenv("AI_API_KEY", FAKE_KEY)
    monkeypatch.setenv("AI_MODEL", "deepseek-v4-flash")
    monkeypatch.setenv("SUOTU_SECRET_TOKEN", FAKE_TOKEN)   # 假 SUOTU_* 敏感变量
    monkeypatch.setattr(ai, "_read_env_file", lambda: {})  # .env 永不进测试
    logging_setup.app_logger().info("诊断包测试日志行")
    logging_setup.error_logger().error("ValueError: 测试错误计数")

    client = TestClient(app)
    r = client.post("/diagnostics/bundle")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert "suotu_diagnostics_" in r.headers["content-disposition"]

    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"logs/app.log", "logs/error.log", "logs/operation.log",
            "version.txt", "config_sanitized.txt",
            "error_stats.txt", "audit_status.txt"} <= names

    # 脱敏红线:整个 zip 全文搜不到任何 key/口令假值
    blob = b"".join(z.read(n) for n in z.namelist()).decode("utf-8", "replace")
    assert FAKE_KEY not in blob
    assert FAKE_TOKEN not in blob
    assert FAKE_PASSWORD not in blob

    cfg = z.read("config_sanitized.txt").decode("utf-8")
    assert "AI_PROVIDER: deepseek" in cfg
    assert "AI_API_KEY: 已配置" in cfg               # 只报配置与否,不带值
    assert "SUOTU_SECRET_TOKEN=***" in cfg           # 敏感名打码

    assert "诊断包测试日志行" in z.read("logs/app.log").decode("utf-8")
    assert "python:" in z.read("version.txt").decode("utf-8")
    assert "ValueError" in z.read("error_stats.txt").decode("utf-8")
    assert "chain_ok: True" in z.read("audit_status.txt").decode("utf-8")

    # 生成动作写审计哈希链(记动作,不记日志内容)
    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT actor, action FROM audit_log"
            " WHERE action='diagnostics_bundle' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None and row["actor"] == "tester"
