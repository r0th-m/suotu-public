"""测试公共件:tmp 数据目录隔离 + 合成夹具(不依赖真实样本)。

- SUOTU_DATA_DIR monkeypatch 到 tmp_path,每个用例独立案件库/金库/DuckDB;
- duck.reset() 关掉上一用例的共享连接并重置 FTS 探测结论;
- 样本全部合成(对 spec 写的正/负样本),不依赖真实日志。
"""
from __future__ import annotations

import io
import zipfile

import pytest

from backend.app import db, duck

# 测试环境提速(2026-08-05 实测定位):pytest 的 pytest-current 便利符号链接
# 在本机每次创建挂起 ~26s×2(cProfile 实锤 nt.symlink;裸 syscall 复现不出,
# 安全软件拦截嫌疑)。_force_symlink 是 pytest 官方的 best-effort 便利链接,
# no-op 不影响任何测试语义。
import _pytest.pathlib as _pytest_pathlib
_pytest_pathlib._force_symlink = lambda *a, **k: None

# ---- 合成正样本(对 spec 写) ----

NGINX_LINES = [
    '93.184.216.34 - - [10/Oct/2000:13:55:36 +0300] "GET /index.html HTTP/1.1" 200 1043 "http://example.com/" "Mozilla/5.0"',
    '192.168.1.10 - alice [10/Oct/2000:13:56:01 +0300] "POST /login?next=/admin HTTP/1.1" 302 680 "-" "curl/7.68.0"',
    '10.0.0.5 - - [10/Oct/2000:13:57:22 +0300] "GET /missing HTTP/1.1" 404 153 "-" "Mozilla/5.0 (scannerbot)"',
]
NGINX_TEXT = "\n".join(NGINX_LINES) + "\n"

APACHE_LINES = [
    '93.184.216.34 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326',
    '127.0.0.1 - frank [10/Oct/2000:13:55:37 -0700] "GET /admin/ HTTP/1.0" 403 199',
]
APACHE_TEXT = "\n".join(APACHE_LINES) + "\n"

IIS_LINES = [
    "#Software: Microsoft Internet Information Services 10.0",
    "#Version: 1.0",
    "#Date: 2026-07-20 00:00:01",
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-bytes time-taken",
    "2026-07-20 00:00:02 192.168.10.5 GET /Default.aspx - 80 - 93.184.216.34 Mozilla/5.0 - 200 431 15",
    "2026-07-20 00:00:03 192.168.10.5 POST /login.aspx ReturnUrl=%2f 80 bob 93.184.216.34 Mozilla/5.0 http://intranet/ 302 210 31",
]
IIS_TEXT = "\n".join(IIS_LINES) + "\n"

RAW_LINES = [
    "Jul 20 12:00:01 oa-app01 oddsvc[812]: something completely unstructured happened",
    "{\" bespoke\": true, \"note\": \"not jsonl we understand\" }",
    "!!! 蛮荒日志 third line, no schema at all",
]
RAW_TEXT = "\n".join(RAW_LINES) + "\n"

# ---- 合成负样本 ----

NGINX_TRUNCATED = NGINX_LINES[0] + "\n" + \
    '93.184.216.34 - - [10/Oct/2000:13:55:36 +0300] "GET /broken HTTP/1.1" 200' + "\n"
NGINX_BAD_TIME = NGINX_LINES[0] + "\n" + \
    '93.184.216.34 - - [99/Foo/2000:99:99:99 +0300] "GET /x HTTP/1.1" 200 1 "-" "-"' + "\n"
# 与三种 web 格式都不像的非空文本 → 0 行命中 → failed
ZERO_HIT_TEXT = "###%% totally alien format %%###\n@@@ another alien line @@@\n"


def make_zip(members: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in members.items():
            zf.writestr(name, text)
    return buf.getvalue()


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    """tmp 数据目录隔离(SUOTU_DATA_DIR monkeypatch)。"""
    d = tmp_path / "data"
    monkeypatch.setenv("SUOTU_DATA_DIR", str(d))
    duck.reset()
    yield d
    duck.reset()


@pytest.fixture()
def conn(data_dir):
    c = db.connect()
    yield c
    c.close()


@pytest.fixture(autouse=True)
def auth_session(data_dir, monkeypatch):
    """统一认证夹具(M4 认证上线):建测试用户并给本测试内所有 TestClient
    注入会话 Cookie(与主机取证平台 M5b 同款兼容模式)。

    认证上线后所有业务端点都要登录态;旧测试逐文件改代价太大,
    这里一处注入:monkeypatch TestClient.__init__,建客户端即带已认证 Cookie。
    需要「未认证」场景的测试(如 test_auth)自行 client.cookies.clear()。
    凭据仅测试用,非真实凭据;.env 永不进测试。
    """
    from fastapi.testclient import TestClient

    from backend.app import auth
    auth._fails.clear()                          # 防爆破计数跨用例清零
    auth.create_user("tester", "Tester#2026pass")
    token = auth.create_session("tester")
    orig_init = TestClient.__init__

    def _patched(self, *args, **kwargs):
        orig_init(self, *args, **kwargs)
        self.cookies.set(auth.COOKIE_NAME, token)

    monkeypatch.setattr(TestClient, "__init__", _patched)
    return {"username": "tester", "token": token}


@pytest.fixture()
def case_id(conn):
    cid = "case-test-1"
    with conn:
        conn.execute("INSERT INTO cases (id, name, created_at) VALUES (?,?,?)",
                     (cid, "测试案件", "2026-08-04T00:00:00+00:00"))
    return cid


def register_confirm_parse(conn, case_id, text, fmt, name="access.log",
                           tz="Asia/Shanghai", log_type="web"):
    """三段式一把梭(测试辅助,走真实 ingest 管线)。"""
    from backend.app import ingest
    reg = ingest.register_upload(conn, case_id, name, io.BytesIO(text.encode()))
    sid = reg["sources"][0]["source_id"]
    ingest.confirm_source(conn, sid, fmt, tz_declared=tz, log_type=log_type)
    report = ingest.parse_source(conn, sid)
    return sid, reg, report


# ---- M3 AI 测试公共件(纪律:.env 永不进测试 —— 禁读 .env + 环境变量 monkeypatch) ----

import uuid

from backend.app import ai as _ai


@pytest.fixture()
def ai_env(monkeypatch, data_dir):
    """AI 测试环境:禁读 .env(凭据永不进测试),AI_* / DEEPSEEK_* 环境变量
    全部清空,由用例按需 setenv;返回 monkeypatch 供用例继续用。
    2026-08-11 合规闸:用 AI 路径的用例默认已授予外发同意(闸门行为
    本身的测试在 test_ai_config.py,不经本 fixture)。"""
    monkeypatch.setattr(_ai, "_read_env_file", lambda: {})
    for key in ("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL",
                "AI_TOKEN_BUDGET", "AI_MAX_ROUNDS", "AI_MAX_TOOL_CALLS",
                "AI_TIMEOUT"):
        monkeypatch.delenv(key, raising=False)
    grant_ai_consent()
    return monkeypatch


def make_run_row(conn, case_id, source_id, *, budget=200000,
                 profile="online", status="running"):
    """直接落一行 analysis_runs(熔断/chat 测试的 run 上下文)。"""
    run_id = "run-test-" + uuid.uuid4().hex[:8]
    with conn:
        conn.execute(
            "INSERT INTO analysis_runs (id, case_id, source_id, status,"
            " profile, budget, created_at) VALUES (?,?,?,?,?,?,?)",
            (run_id, case_id, source_id, status, profile, budget,
             "2026-08-05T00:00:00+00:00"))
    return run_id


def make_source_row(conn, case_id, source_id="src-test-1", line_count=100):
    """直接落一行 log_sources(FK 需要;不走进库管线,纯台账)。"""
    with conn:
        conn.execute(
            "INSERT INTO log_sources (id, case_id, name, log_type, sha256,"
            " vault_path, line_count, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (source_id, case_id, "测试源", "web", "0" * 64, "vault/x",
             line_count, "parsed", "2026-08-05T00:00:00+00:00"))
    return source_id


def grant_ai_consent(actor: str = "tester") -> None:
    """测试环境默认授予 AI 外发同意(2026-08-11 合规闸配套)。

    走 AI 调用路径的用例经 ai_env 自动获得;闸门行为本身的用例
    (test_ai_config.py)自建/自删同意记录,不经 ai_env。
    """
    from backend.app import ai, db
    conn = db.connect()
    try:
        ai.record_external_consent(conn, actor)
    finally:
        conn.close()
