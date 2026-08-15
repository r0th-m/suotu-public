"""SQLite 案件库(case.db):人的登记层,权威源。

七表:
- cases:一次应急分析;
- log_sources:日志源登记(证据链的根,全部人填+留痕);
- audit_log:哈希链审计(prev_hash 链式可校验,改/删/插队必断链);
- hits(M1):规则命中的候选待审区——机器产物,恒 pending 起步,
  永不自动成线索(§1 判断权归人);
- clues(M1):人审入库的线索,唯一写入路径 = 人 accept hit(rules.py);
- analysis_runs(M3):L2/L3 分析 run 台账;M5 起复用为通用 AI run 台账
  (交流区每轮问答一行,source_id=NULL 表案件作用域,无单一源);
- chat_sessions / chat_messages(M5):交流区人机对话留痕——回答只是
  消息,永不落业务表(§1)。

纪律:
- WAL + busy_timeout,读写并发不互相卡死;
- audit 的「读上一条 entry_hash → 算哈希 → 插入」必须原子,进程级互斥锁焊死;
- actor M4 起锚真人:API 入口传会话用户名;无会话的内部调用(模块直调/
  后台线程)恒 "system";AI 动作恒 "ai"。留参数位,不硬编码在 SQL 里。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  sealed_at TEXT          -- M4 封存留痕(只读动作,不锁案件);NULL=未封存
);

-- 系统级键值设置(2026-08-11:AI 外发同意记录;一次同意,审计锚人)
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  actor TEXT NOT NULL
);

-- MCP 接入的 API token(2026-08-13):哈希存储,明文只在创建时回一次
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  label TEXT,
  token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

-- 按案件 AI 策略(2026-08-11,合规底线):独立表而非 cases 加列
CREATE TABLE IF NOT EXISTS case_ai_policy (
  case_id TEXT PRIMARY KEY REFERENCES cases(id),
  ai_external_blocked INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  actor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS log_sources (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  name TEXT NOT NULL,
  system TEXT,
  log_type TEXT NOT NULL DEFAULT 'unknown'
    CHECK (log_type IN ('web','middleware','audit','unknown')),
  format_id TEXT,
  tz_declared TEXT,
  time_range TEXT,
  source_note TEXT,
  evidence_kind TEXT NOT NULL DEFAULT 'log'
    CHECK (evidence_kind IN ('log','supplementary')),  -- 补充证据(2026-08-09):人随时补的材料,打标可检索
  sha256 TEXT NOT NULL,
  vault_path TEXT NOT NULL,
  line_count INTEGER,
  status TEXT NOT NULL DEFAULT 'registered'
    CHECK (status IN ('registered','confirmed','parsed','failed')),
  error TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY,
  case_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  scope TEXT,
  detail_json TEXT,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL
);
-- M1:候选命中待审区(§1 判断权归人:机器产物,永不自动成线索);
-- UNIQUE(source_id, line_no, rule_id) 去重,规则重跑幂等。
-- M2:detail_json 存统计/联动命中的结构化细节(签名命中为 NULL)。
-- 2026-08-15:round_no 记录该命中由第几轮扫描产出(老数据 NULL=「历史」)。
CREATE TABLE IF NOT EXISTS hits (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  source_id TEXT NOT NULL REFERENCES log_sources(id),
  line_no INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL
    CHECK (severity IN ('info','low','medium','high')),
  matched_field TEXT NOT NULL,
  matched_value TEXT NOT NULL,
  snippet TEXT NOT NULL,
  ts_utc TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','accepted','rejected')),
  created_at TEXT NOT NULL,
  reviewed_at TEXT,
  review_note TEXT,
  detail_json TEXT,
  round_no INTEGER,
  UNIQUE (source_id, line_no, rule_id)
);
-- 扫描轮次台账(2026-08-15):每次 rules:run 记一轮,round_no 每案件递增;
-- rule_ids_json NULL=全量扫描,否则为选中规则 id 列表;summary_json 为
-- 报告摘要(scanned/hits_new/truncated 计数)。
CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  round_no INTEGER NOT NULL,
  rule_ids_json TEXT,
  actor TEXT NOT NULL,
  summary_json TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (case_id, round_no)
);
-- 记录区人工笔记(2026-08-15):案件级工作记录(非证据——证据链在金库/
-- 审计链,笔记物理删除即可);anchor 可选,存类型+引用(id 或坐标)。
CREATE TABLE IF NOT EXISTS case_notes (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  body TEXT NOT NULL,
  anchor_kind TEXT
    CHECK (anchor_kind IN ('hit','scan_round','analysis_run','line')),
  anchor_ref TEXT,
  author TEXT NOT NULL,
  created_at TEXT NOT NULL
);
-- M1:线索(人审入库才算数);唯一写入路径 = 人 accept hit(见 rules.py)。
CREATE TABLE IF NOT EXISTS clues (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  anchor_source_id TEXT NOT NULL,
  anchor_line_no INTEGER NOT NULL,
  anchor_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);
-- M3:L2 播种 + L3 AI 精读的运行台账(analysis.py)。
-- anchors_json:锚点与播种报告(锚点清单/窗口清单/各窗 AI 摘要/综合故事);
-- usage_json:token 用量累进;tool_log_json:AI 工具调用台账(每次调用
-- {tool, args 摘要, result_count, truncated});budget:token 预算(快照)。
-- M5:复用为交流区 chat run 台账(source_id=NULL=案件作用域;老库由
-- _migrate 整表重建放开 NOT NULL)。
CREATE TABLE IF NOT EXISTS analysis_runs (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  source_id TEXT REFERENCES log_sources(id),
  status TEXT NOT NULL DEFAULT 'running'
    CHECK (status IN ('running','done','aborted','failed')),
  profile TEXT,
  anchors_json TEXT,
  budget INTEGER,
  usage_json TEXT,
  tool_log_json TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  finished_at TEXT
);
-- M5:交流区(人机对话)。from_hit_id=追问模式:该命中详情+锚点注入
-- system 上下文(主机取证平台 from_analysis 交接棒同款思想)。
CREATE TABLE IF NOT EXISTS chat_sessions (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  title TEXT,               -- NULL=未命名,首条消息截 30 字自动命名
  from_hit_id TEXT REFERENCES hits(id),
  created_at TEXT NOT NULL
);
-- AI 回答只是消息,永不落业务表(§1 判断权归人);tool_log_json/usage_json
-- 是该轮 AI run 台账(analysis_runs 行)的快照,run 行仍是权威留痕。
CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES chat_sessions(id),
  role TEXT NOT NULL CHECK (role IN ('user','assistant')),
  content TEXT NOT NULL,
  tool_log_json TEXT,
  usage_json TEXT,
  ts TEXT NOT NULL
);
"""

GENESIS = "GENESIS"

# 审计互斥锁:读 prev → 算哈希 → 插入 三步必须原子,否则并发写分叉断链。
_APPEND_LOCK = threading.Lock()


def connect(db_file: Path | None = None) -> sqlite3.Connection:
    path = db_file or config.case_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """老库兼容迁移:缺列则 ALTER 补上,幂等。

    - M2:hits.detail_json;
    - M4:cases.sealed_at(封存留痕,只读动作不锁案件);
    - M5:analysis_runs.source_id 放开可空(交流区 chat run 无源作用域)。
      SQLite 不能 ALTER 去掉 NOT NULL,老库整表重建一次;列序不变,
      INSERT SELECT * 直搬(幂等:重建后 notnull=0,不再进分支)。
    - 2026-08-09:log_sources.evidence_kind(补充证据,'log'|'supplementary')。
    - 2026-08-15:hits.round_no(扫描轮次;老数据 NULL=「历史」)。
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(hits)")}
    if "detail_json" not in cols:
        conn.execute("ALTER TABLE hits ADD COLUMN detail_json TEXT")
    if "round_no" not in cols:
        conn.execute("ALTER TABLE hits ADD COLUMN round_no INTEGER")
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(cases)")}
    if "sealed_at" not in cols:
        conn.execute("ALTER TABLE cases ADD COLUMN sealed_at TEXT")
    src_cols = {r["name"] for r in conn.execute("PRAGMA table_info(log_sources)")}
    if "evidence_kind" not in src_cols:
        conn.execute("ALTER TABLE log_sources ADD COLUMN evidence_kind"
                     " TEXT NOT NULL DEFAULT 'log'"
                     " CHECK (evidence_kind IN ('log','supplementary'))")
    run_cols = conn.execute("PRAGMA table_info(analysis_runs)").fetchall()
    src = next((r for r in run_cols if r["name"] == "source_id"), None)
    if src is not None and src["notnull"]:
        # 与 SCHEMA 中 analysis_runs 定义保持一致(除 RENAME 目标名)
        conn.executescript("""
ALTER TABLE analysis_runs RENAME TO analysis_runs_old;
CREATE TABLE analysis_runs (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  source_id TEXT REFERENCES log_sources(id),
  status TEXT NOT NULL DEFAULT 'running'
    CHECK (status IN ('running','done','aborted','failed')),
  profile TEXT,
  anchors_json TEXT,
  budget INTEGER,
  usage_json TEXT,
  tool_log_json TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  finished_at TEXT
);
INSERT INTO analysis_runs SELECT * FROM analysis_runs_old;
DROP TABLE analysis_runs_old;
""")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entry_hash(entry_id: int, case_id: str, ts: str, actor: str, action: str,
                scope: str | None, detail_json: str | None, prev_hash: str) -> str:
    payload = "|".join([
        str(entry_id), case_id, ts, actor, action,
        scope or "", detail_json or "", prev_hash,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit(conn: sqlite3.Connection, case_id: str, action: str,
                 scope: str | None = None, detail: dict | str | None = None,
                 actor: str = "system") -> str:
    """追加一条审计记录,返回 entry_hash。调用方负责事务提交。

    actor 默认 "system"(无会话内部调用);API 入口一律传会话用户名
    (M4 审计锚真人),AI 动作传 "ai"。
    """
    detail_text = detail if isinstance(detail, str) or detail is None else json.dumps(
        detail, ensure_ascii=False, sort_keys=True)
    with _APPEND_LOCK:
        prev = conn.execute(
            "SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev["entry_hash"] if prev else GENESIS
        entry_id = (prev["id"] + 1) if prev else 1
        ts = _now()
        entry_hash = _entry_hash(entry_id, case_id, ts, actor, action,
                                 scope, detail_text, prev_hash)
        conn.execute(
            "INSERT INTO audit_log (id, case_id, ts, actor, action, scope,"
            " detail_json, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?)",
            (entry_id, case_id, ts, actor, action, scope, detail_text,
             prev_hash, entry_hash),
        )
    return entry_hash


def verify_audit(conn: sqlite3.Connection) -> tuple[bool, str]:
    """校验审计哈希链连续性。返回 (是否完整, 说明)。"""
    prev_hash = GENESIS
    count = 0
    for row in conn.execute(
        "SELECT id, case_id, ts, actor, action, scope, detail_json,"
        " prev_hash, entry_hash FROM audit_log ORDER BY id"
    ):
        count += 1
        if row["id"] != count:
            return False, f"id 断档:期望 {count},实际 {row['id']}"
        if row["prev_hash"] != prev_hash:
            return False, f"prev_hash 断链于 id={row['id']}"
        expect = _entry_hash(row["id"], row["case_id"], row["ts"], row["actor"],
                             row["action"], row["scope"], row["detail_json"],
                             row["prev_hash"])
        if expect != row["entry_hash"]:
            return False, f"entry_hash 校验失败于 id={row['id']}(该行被篡改)"
        prev_hash = row["entry_hash"]
    return True, f"链完整,共 {count} 条"
