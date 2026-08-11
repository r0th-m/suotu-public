"""AI 编排层 + AI 设置(M3,SUOTU_DESIGN §1/§6.1,主机取证平台 ai.py 模式平移重写;
M6 设置面板:多厂商预设移植自主机取证平台)。

纪律:
- 纯 stdlib(urllib)OpenAI 兼容客户端,零新依赖;
- API key 只落项目根 .env:不进数据库、不进审计、不打日志、不进响应体,
  设置面板只回「已配置/未配置 + 掩码」,key 明文永不出接口;
- 配置每次调用动态重读(环境变量优先,.env 兜底),改完即生效;
- 统一 OpenAI 兼容 chat/completions + 厂商预设(AI_PRESETS);Ollama 走其
  OpenAI 兼容端点({base}/v1,免 key),本地模型经 {base 去 /v1}/api/tags 列;
- 规范化配置键 AI_PROVIDER/AI_BASE_URL/AI_MODEL/AI_API_KEY;
  向后兼容:只有 DEEPSEEK_* 键的旧部署零迁移(按 deepseek 处理);
- 档位两档(§6 三档梯度的索图取舍):ollama → online(本地免 key);
  其余有 key → online;无 key 且非 ollama → offline_lite
  (诚实降级:L1 全跑 + L2 确定性播种,L3 精读跳过并如实标注)。AI 永远可关;
- 每次调用写审计哈希链(actor=ai,含模型/token 用量),失败同样留痕,零静默;
  调用摘要(模型/tokens/耗时/run)同时落 app.log 运行日志,只记元信息,
  **prompt/回答内容永不进日志**;
- usage 累进 run(analysis_runs.usage_json),token 预算超了即停并如实标
  budget_exceeded;
- AI 输出一律「AI 推测·待核」,本层没有任何入库路径(§1 判断权归人)。

熔断(硬约束,断言级测试焊死,见 run_agent):
- 每 run 工具调度轮数上限(AI_MAX_ROUNDS,缺省 12)→ round_limit;
- 每 run 工具调用次数上限(AI_MAX_TOOL_CALLS,缺省 30)→ tool_call_limit;
- token 预算(AI_TOKEN_BUDGET,缺省 200000,建 run 时快照进 budget 列)
  → budget_exceeded;
- 相同工具+相同参数第 3 次出现 → 判循环即停 loop_detected(第 3 次不执行);
- run 状态 aborted(用户中断)每轮前检查 → aborted。
"""
from __future__ import annotations

import copy
import json
import os
import socket
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import config, db, logging_setup

# L3 精读/综合的系统提示纪律:结论锚行号、不确定说需人工核实、只输出 JSON
SYSTEM_PROMPT_L3 = (
    "你是应急日志分析工作台的精读助手,协助应急分析师研判日志窗口。\n"
    "纪律(必须严格遵守):\n"
    "1. 只基于用户消息中给出的日志行回答;每行带行号,结论必须锚到行号"
    "(line_refs),绝不臆造窗口外的内容。\n"
    "2. 你的所有推断都属「AI 推测·待核」,措辞必须体现不确定性"
    "(「疑似」「需人工核实」),不下确定性结论。\n"
    "3. 只输出一个 JSON 对象,不要任何其他文字:\n"
    '{"findings":[{"summary":"发现描述","suspicion":"high|medium|low|info",'
    '"line_refs":[行号]}],"window_note":"本窗一句话摘要"}\n'
    "4. 未见异常时 findings 给空数组并在 window_note 如实描述所见;"
    "「无异常」结论由系统按三重否定纪律裁定,你只描述所见,不宣告清白。"
)

# 综合 pass 的系统提示(全部 window_note → 一段故事,同纪律)
SYSTEM_PROMPT_SYNTH = (
    "你是应急日志分析工作台的综合助手。用户会给你若干日志窗口的精读摘要"
    "(每条约带窗口行号范围)。请把它们串成一段连贯的排查故事。\n"
    "纪律:只基于给定摘要,不臆造;引用时指明窗口行号范围;推断一律"
    "「疑似/需人工核实」措辞;直接输出故事正文(中文,从简)。"
)

_DEFAULT_BASE_URL = "https://api.deepseek.com"
_DEFAULT_MODEL = "deepseek-chat"
_DEFAULT_TIMEOUT = 120.0

# ==================== 厂商预设表(统一 OpenAI 兼容端点,移植自主机取证平台) ====================
# 每厂商:默认 base_url + 推荐模型清单 + 是否需要 key(ollama 本地免 key)。
AI_PRESETS: list[dict] = [
    {"id": "deepseek", "name": "DeepSeek",
     "base_url": "https://api.deepseek.com",
     "recommended_models": ["deepseek-v4-flash", "deepseek-v4-pro"],
     "needs_key": True},
    {"id": "openai", "name": "OpenAI",
     "base_url": "https://api.openai.com/v1",
     "recommended_models": ["gpt-4o-mini", "gpt-4o"],
     "needs_key": True},
    {"id": "dashscope", "name": "通义千问(DashScope 兼容模式)",
     "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
     "recommended_models": ["qwen-plus", "qwen-turbo", "qwen-max"],
     "needs_key": True},
    {"id": "zhipu", "name": "智谱",
     "base_url": "https://open.bigmodel.cn/api/paas/v4",
     "recommended_models": ["glm-4-flash", "glm-4-plus", "glm-4-air"],
     "needs_key": True},
    {"id": "moonshot", "name": "Moonshot(Kimi)",
     "base_url": "https://api.moonshot.cn/v1",
     # kimi-k2 为当前主流型号;不确定时可回退 moonshot-v1-8k
     "recommended_models": ["kimi-k2-0711-preview", "moonshot-v1-8k",
                            "moonshot-v1-32k", "moonshot-v1-128k"],
     "needs_key": True},
    {"id": "ollama", "name": "Ollama(本地)",
     "base_url": "http://localhost:11434/v1",
     # 本地模型由 {base 去 /v1}/api/tags 动态列出,不设静态推荐
     "recommended_models": [],
     "needs_key": False},
    {"id": "custom", "name": "自定义(OpenAI 兼容)",
     "base_url": "", "recommended_models": [], "needs_key": True},
]
DEFAULT_TOKEN_BUDGET = 500000   # 缺省 50 万(2026-08-05 实测:20 万只够 5 窗)
DEFAULT_MAX_ROUNDS = 12
DEFAULT_MAX_TOOL_CALLS = 30

# AI 调用失败的错误分类(对外如实分类,不吞不混)
KIND_NETWORK = "network"        # 网络不可达 / 超时
KIND_RATE_LIMIT = "rate_limit"  # 429 限流
KIND_SERVER = "server"          # 5xx 服务端
KIND_AUTH = "auth"              # 401/403 鉴权失败
KIND_NOT_FOUND = "not_found"    # 404 端点/模型不存在
KIND_CLIENT = "client"          # 其他 4xx
KIND_OFFLINE = "offline"        # 无凭据(offline_lite 档)
KIND_BAD_RESPONSE = "bad_response"  # 响应体结构不符(不臆造内容)
KIND_CONSENT_REQUIRED = "consent_required"  # 在线档未记录外发同意(合规闸)
KIND_EXTERNAL_BLOCKED = "external_blocked"  # 本案件设置了「禁止 AI 外发」

# 熔断停机原因(断言级测试焊死)
STOP_COMPLETED = "completed"
STOP_ROUND_LIMIT = "round_limit"
STOP_TOOL_CALL_LIMIT = "tool_call_limit"
STOP_BUDGET = "budget_exceeded"
STOP_LOOP = "loop_detected"
STOP_ABORTED = "aborted"


class AIError(Exception):
    """AI 调用失败,kind 为上述分类之一;message 不含凭据。"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class CircuitStop(Exception):
    """熔断停机:reason 为 STOP_* 之一;message 如实说明。"""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


# ==================== AI 外发同意与按案件闸门(2026-08-11,合规底线) ==========
#
# 两道闸,都只拦 online(外发)档;ollama 本地/offline_lite 不受影响:
# ①全局外发同意:settings 表 ai_external_consent 行,设置面板显式勾选后
#   落库(一次性,audit 锚操作人);chat() 调用前硬校验——即使手改 .env
#   绕过面板,没有同意记录一样调不出去(纵深防御);
# ②按案件「禁止 AI 外发」:case_ai_policy 表,开了之后该案件的一切
#   online 调用被拒(本地 ollama 仍可用)。
# 闸门拒绝发生在「调用未发生」阶段,与 offline 同例不写 ai_call 审计;
# 策略变更本身(同意记录/案件开关)全部进审计哈希链。

CONSENT_KEY = "ai_external_consent"


def external_consent(conn: sqlite3.Connection) -> dict | None:
    """全局外发同意记录;无记录 → None(=未同意)。"""
    row = conn.execute(
        "SELECT value, updated_at, actor FROM settings WHERE key = ?",
        (CONSENT_KEY,)).fetchone()
    if row is None:
        return None
    return {"consented": row["value"] == "1",
            "updated_at": row["updated_at"], "actor": row["actor"]}


def record_external_consent(conn: sqlite3.Connection, actor: str) -> dict:
    """落外发同意(幂等)+ 审计锚人。返回同意记录。"""
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            "INSERT INTO settings (key, value, updated_at, actor)"
            " VALUES (?, '1', ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value='1', updated_at=?, actor=?",
            (CONSENT_KEY, now, actor, now, actor))
        db.append_audit(conn, "system", action="ai_external_consent",
                        scope="ai", actor=actor,
                        detail={"consent": True})
    return external_consent(conn)


def case_external_blocked(conn: sqlite3.Connection, case_id: str) -> bool:
    """本案件是否禁止 AI 外发(无记录 = 不禁止)。"""
    row = conn.execute(
        "SELECT ai_external_blocked FROM case_ai_policy WHERE case_id = ?",
        (case_id,)).fetchone()
    return bool(row and row["ai_external_blocked"])


def set_case_external_blocked(conn: sqlite3.Connection, case_id: str,
                              blocked: bool, actor: str) -> dict:
    """按案件设置「禁止 AI 外发」(幂等 upsert)+ 审计。返回当前状态。"""
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            "INSERT INTO case_ai_policy (case_id, ai_external_blocked,"
            " updated_at, actor) VALUES (?,?,?,?)"
            " ON CONFLICT(case_id) DO UPDATE SET ai_external_blocked=?,"
            " updated_at=?, actor=?",
            (case_id, int(blocked), now, actor, int(blocked), now, actor))
        db.append_audit(conn, case_id, action="case_ai_policy",
                        scope=case_id, actor=actor,
                        detail={"ai_external_blocked": blocked})
    return {"case_id": case_id, "ai_external_blocked": blocked,
            "updated_at": now, "actor": actor}


def _external_gate(conn: sqlite3.Connection, case_id: str | None) -> None:
    """online 档双闸(全局同意 + 按案件禁止);通过则静默返回。

    case_id=None(无 run 语境的直调)只过全局闸。
    """
    if external_consent(conn) is None:
        raise AIError(KIND_CONSENT_REQUIRED,
                      "在线 AI 将外发案件数据到第三方模型服务,需先在 AI 设置中"
                      "显式勾选外发同意(一次同意,全程可审计)")
    if case_id and case_external_blocked(conn, case_id):
        raise AIError(KIND_EXTERNAL_BLOCKED,
                      "本案件已设置「禁止 AI 外发」;可改用本地 Ollama 模型,"
                      "或由有权限的人在案件设置中解除该开关")


# ==================== .env 读取(key 唯一落点) ====================

def _env_file() -> Path:
    """项目根 .env(gitignored,凭据所在)。"""
    return config.REPO_ROOT / ".env"


def _read_env_file() -> dict[str, str]:
    """极简 .env 解析:KEY=VALUE,忽略空行/# 注释,值去首尾空白与成对引号。

    只在内存返回 dict,调用方不得打印其中值(测试 monkeypatch 本函数禁读
    .env,同主机取证平台测试纪律)。
    """
    path = _env_file()
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if key:
            out[key] = val
    return out


def _conf(key: str, default: str | None = None) -> str | None:
    """配置读取:环境变量优先,.env 兜底(每次现读,测试可 monkeypatch)。"""
    val = os.environ.get(key)
    if val:
        return val
    return _read_env_file().get(key, default)


def _write_env_file(updates: dict[str, str]) -> None:
    """把 updates 写回项目根 .env:已有键原位替换,新键追加,其余行(注释/
    空行/无关键)原样保留。值含空白/# 时加双引号(移植自主机取证平台)。"""
    path = _env_file()
    lines: list[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()
    remaining = dict(updates)

    def _fmt(key: str, val: str) -> str:
        if val and (val != val.strip() or any(c in val for c in " #\"'")):
            val = '"' + val.replace('"', '\\"') + '"'
        return f"{key}={val}"

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.partition("=")[0].strip()
        if key in remaining:
            lines[i] = _fmt(key, remaining.pop(key))
    for key, val in remaining.items():
        lines.append(_fmt(key, val))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ==================== 配置解析(每次调用动态重读) ====================

def _preset(provider: str | None) -> dict | None:
    for p in AI_PRESETS:
        if p["id"] == provider:
            return p
    return None


def _resolve_config() -> dict:
    """解析当前 AI 配置(每次调用现读环境变量 + .env,改完即生效)。

    优先级:AI_* 规范键 → 旧 DEEPSEEK_* 兼容键 → 厂商预设默认。
    返回 {provider, base_url, model, api_key};api_key 只在内存,绝不外发。
    """
    preset = _preset(_conf("AI_PROVIDER"))
    # 只有旧 DEEPSEEK_* 键的历史部署:零迁移按 deepseek 处理
    legacy = preset is None and bool(
        _conf("DEEPSEEK_API_KEY") or _conf("DEEPSEEK_BASE_URL"))
    provider = preset["id"] if preset else ("deepseek" if legacy else "custom")
    eff = preset if preset else (_preset("deepseek") if legacy else None)
    base_url = (_conf("AI_BASE_URL") or _conf("DEEPSEEK_BASE_URL")
                or (eff["base_url"] if eff else "") or None)
    model = (_conf("AI_MODEL") or _conf("DEEPSEEK_MODEL")
             or (eff["recommended_models"][0]
                 if eff and eff["recommended_models"] else None)
             or (_DEFAULT_MODEL if provider == "deepseek" else None))
    api_key = _conf("AI_API_KEY") or _conf("DEEPSEEK_API_KEY")
    return {"provider": provider, "base_url": base_url,
            "model": model, "api_key": api_key}


def profile() -> str:
    """当前档位(索图两档取舍):ollama → online(本地免 key);
    其余有 key → online;无 key 且非 ollama → offline_lite(诚实降级)。"""
    cfg = _resolve_config()
    if cfg["provider"] == "ollama":
        return "online"
    return "online" if cfg["api_key"] else "offline_lite"


def ai_available() -> bool:
    """是否有可用 AI 通道(= online 档;只报配置在不在,不测活)。"""
    return profile() == "online"


def status() -> dict:
    """AI 状态:只报配置在不在,不测活(诚实:配置≠服务可用)。"""
    cfg = _resolve_config()
    prof = profile()
    online = prof == "online"
    if online and cfg["provider"] == "ollama":
        note = "本地 Ollama 免 key:仅表示已配置端点与模型,不代表实测连通"
    elif online:
        note = "仅表示已配置凭据,不代表服务实测连通"
    else:
        note = ("未配置 API key:L3 AI 精读不可用,L1/L2 确定性分析"
                "不受影响(诚实降级)")
    return {
        "profile": prof,
        "available": online,
        "provider": cfg["provider"] if online else None,
        "model": cfg["model"] if online else None,
        "base_url": cfg["base_url"] if online else None,
        "key_configured": bool(cfg["api_key"]),
        "note": note,
    }


# ==================== 设置面板(掩码读取 / 写回 .env / 测连,移植自主机取证平台) ====================

def _mask_key(key: str | None) -> str | None:
    """掩码:前后各留 2~4 位,中间省略;过短宁可全掩,也不多露。"""
    if not key:
        return None
    if len(key) > 8:
        return key[:4] + "…" + key[-4:]
    if len(key) > 4:
        return key[:2] + "…" + key[-2:]
    return "…"


def config_snapshot() -> dict:
    """设置面板读取:只回掩码状态,key 明文永不出本层。"""
    cfg = _resolve_config()
    return {
        "provider": cfg["provider"],
        "base_url": cfg["base_url"],
        "model": cfg["model"],
        "key_configured": bool(cfg["api_key"]),
        "key_hint": _mask_key(cfg["api_key"]),
        "presets": copy.deepcopy(AI_PRESETS),
    }


def save_config(provider: str, base_url: str | None, model: str | None,
                api_key: str | None) -> dict:
    """把 AI 设置写回项目根 .env(保留无关行;系统级一份,任何登录用户可改)。

    api_key 为 None/空串 = 不动现有 key;返回写后的 config_snapshot()。
    未知 provider 抛 ValueError;needs_key 厂商无新 key 且无已存 key 同样
    ValueError(由端点如实 422;ollama 本地免 key)。
    """
    preset = _preset(provider)
    if preset is None:
        raise ValueError(f"未知厂商: {provider}")
    new_key = (api_key or "").strip()
    if preset["needs_key"] and not new_key \
            and not _resolve_config()["api_key"]:
        raise ValueError(f"{preset['name']} 需要 API key:请填写"
                         "(或先保存过 key 后可留空沿用)")
    base = (base_url or "").strip() or preset["base_url"]
    mdl = ((model or "").strip()
           or (preset["recommended_models"][0]
               if preset["recommended_models"] else ""))
    updates = {"AI_PROVIDER": provider, "AI_BASE_URL": base, "AI_MODEL": mdl}
    if new_key:
        updates["AI_API_KEY"] = new_key
    _write_env_file(updates)
    return config_snapshot()


def resolve_form_config(provider: str, base_url: str | None, model: str | None,
                        api_key: str | None) -> dict:
    """测连表单值 → 生效配置(只在内存,绝不写 .env、不写审计)。

    与 save_config 同一套兜底:base_url/model 缺省取厂商预设;
    api_key 缺省/空串 = 沿用**已保存**的 key(设置面板 key 栏留空即
    「不动现有 key」,测表单值时同理)。未知 provider 抛 ValueError。
    """
    preset = _preset(provider)
    if preset is None:
        raise ValueError(f"未知厂商: {provider}")
    saved = _resolve_config()
    base = (base_url or "").strip() or preset["base_url"] or None
    mdl = ((model or "").strip()
           or (preset["recommended_models"][0]
               if preset["recommended_models"] else None))
    key = (api_key or "").strip() or saved["api_key"]
    return {"provider": provider, "base_url": base, "model": mdl,
            "api_key": key}


def test_config(timeout: float = 15.0, override: dict | None = None) -> dict:
    """测连(至多 1 次真实调用,结果如实返回,不写审计、不持久化)。

    - override=None(空 body)→ 测**已保存**配置(_resolve_config 现读);
      override 带表单值 → 测**表单**配置(resolve_form_config,只在内存);
      两条路都不写 .env、不写审计——测连不是保存;
    - 未配置 → ok=False,kind=offline;
    - ollama → GET {base 去 /v1}/api/tags,返回本地模型清单;
    - 云端 → 1-token chat(max_tokens=1,成本最低),返回 ok/延迟/模型;
    - 失败分类:network / auth(401/403)/ not_found(404)/ rate_limit / server。
    """
    cfg = override if override is not None else _resolve_config()
    t0 = time.monotonic()

    def _lat() -> int:
        return int((time.monotonic() - t0) * 1000)

    if cfg["provider"] == "ollama":
        root = (cfg["base_url"] or "").rstrip("/")
        if root.endswith("/v1"):                    # api/tags 挂在 v1 之外
            root = root[:-3]
        req = urllib.request.Request(root.rstrip("/") + "/api/tags",
                                     method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err = _classify_http_error(e)
            return {"ok": False, "kind": err.kind, "error": str(err),
                    "provider": "ollama", "latency_ms": _lat()}
        except (urllib.error.URLError, socket.timeout, TimeoutError,
                OSError) as e:
            return {"ok": False, "kind": KIND_NETWORK,
                    "error": f"Ollama 不可达/超时({type(e).__name__})",
                    "provider": "ollama", "latency_ms": _lat()}
        models = sorted(m.get("name", "") for m in payload.get("models", [])
                        if m.get("name"))
        return {"ok": True, "kind": None, "provider": "ollama",
                "latency_ms": _lat(), "model": cfg["model"],
                "local_models": models,
                "model_present": (cfg["model"] in models
                                  if cfg["model"] else None)}

    if not (cfg["api_key"] and cfg["model"]):
        return {"ok": False, "kind": KIND_OFFLINE,
                "error": "未配置 API key 或模型,无可测的云端通道",
                "provider": cfg["provider"], "latency_ms": _lat()}
    try:
        result = _call_api([{"role": "user", "content": "ping"}],
                           model=cfg["model"], base_url=cfg["base_url"],
                           api_key=cfg["api_key"], timeout=timeout,
                           thinking=False, max_tokens=1)
    except AIError as e:
        return {"ok": False, "kind": e.kind, "error": str(e),
                "provider": cfg["provider"], "latency_ms": _lat()}
    return {"ok": True, "kind": None, "provider": cfg["provider"],
            "latency_ms": _lat(), "model": result["model"]}


def token_budget() -> int:
    """每 run 的 token 预算(AI_TOKEN_BUDGET,缺省 200000)。"""
    try:
        return int(_conf("AI_TOKEN_BUDGET", str(DEFAULT_TOKEN_BUDGET)))
    except ValueError:
        return DEFAULT_TOKEN_BUDGET


def _int_conf(key: str, default: int) -> int:
    try:
        return int(_conf(key, str(default)))
    except ValueError:
        return default


# ==================== OpenAI 兼容调用 ====================

def _classify_http_error(e: urllib.error.HTTPError) -> AIError:
    if e.code in (401, 403):
        return AIError(KIND_AUTH, f"AI 鉴权失败(HTTP {e.code}):检查 API key")
    if e.code == 404:
        return AIError(KIND_NOT_FOUND,
                       "AI 端点/模型不存在(HTTP 404):检查 base_url 与模型名")
    if e.code == 429:
        return AIError(KIND_RATE_LIMIT, "AI 服务限流(HTTP 429),稍后重试")
    if e.code >= 500:
        return AIError(KIND_SERVER, f"AI 服务端错误(HTTP {e.code})")
    return AIError(KIND_CLIENT, f"AI 请求被拒(HTTP {e.code})")


def _parse_tool_calls(raw_calls) -> list[dict] | None:
    """响应里的 tool_calls 归一化(无则 None);arguments 坏 JSON → None,
    由调用方把错误喂回 AI 自纠(不臆造参数)。"""
    if not raw_calls:
        return None
    out = []
    for i, tc in enumerate(raw_calls):
        fn = (tc or {}).get("function") or {}
        args_raw = fn.get("arguments")
        if args_raw is None:
            args_raw = "{}"
        if not isinstance(args_raw, str):
            args_raw = json.dumps(args_raw, ensure_ascii=False)
        try:
            args = json.loads(args_raw)
        except json.JSONDecodeError:
            args = None
        tid = tc.get("id") or f"call_{i}"
        out.append({"id": tid, "name": fn.get("name") or "",
                    "arguments": args if isinstance(args, dict) else None,
                    "arguments_raw": args_raw,
                    "raw": {"id": tid, "type": "function",
                            "function": {"name": fn.get("name") or "",
                                         "arguments": args_raw}}})
    return out


def _call_api(messages: list[dict], *, model: str, base_url: str,
              api_key: str | None, timeout: float, thinking: bool,
              max_tokens: int | None = None,
              tools: list[dict] | None = None) -> dict:
    """裸 HTTP 调用(OpenAI 兼容 chat/completions)。

    返回 {content, tool_calls, model, usage};错误分类抛 AIError,
    异常消息绝不带凭据。tools 非 None 时按 OpenAI tools 协议下发;
    max_tokens 缺省 8192(测连传 1,成本最低)。
    """
    body_dict: dict = {"model": model, "messages": messages, "stream": False,
                       # 显式输出上限(2026-08-05 实测:缺省 4096,大窗口的
                       # findings JSON 被截断成非法 JSON → ai_error)
                       "max_tokens": max_tokens if max_tokens is not None
                       else 8192}
    if thinking:
        body_dict["thinking"] = {"type": "enabled"}
    if tools is not None:
        body_dict["tools"] = tools
    body = json.dumps(body_dict).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions",
                                 data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise _classify_http_error(e) from e
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as e:
        raise AIError(KIND_NETWORK,
                      f"AI 服务不可达/超时({type(e).__name__})") from e
    try:
        message = payload["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as e:
        raise AIError(KIND_BAD_RESPONSE,
                      "AI 响应结构不符(缺 choices/message)") from e
    if not isinstance(message, dict):
        raise AIError(KIND_BAD_RESPONSE, "AI 响应结构不符(message 非对象)")
    usage = payload.get("usage") or {}
    return {"content": message.get("content"),
            "tool_calls": _parse_tool_calls(message.get("tool_calls")),
            "model": payload.get("model") or model,
            "usage": {
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "total_tokens": usage.get("total_tokens"),
            }}


# ==================== run 台账(usage 累进 / tool_log / abort 检查) ====================

def _get_run(conn: sqlite3.Connection, run_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM analysis_runs WHERE id = ?",
                        (run_id,)).fetchone()


def _accumulate_usage(conn: sqlite3.Connection, run_id: str,
                      usage: dict) -> dict:
    """把一次调用的 usage 累进 run.usage_json,返回累进后总量。

    预算闸:累进前已超 → 不调;(调用方在调用前查)累进后超 → 调用方
    如实标 budget_exceeded 停机。budget 取 run 建时快照,None → 环境缺省。
    """
    row = _get_run(conn, run_id)
    if row is None:
        raise AIError(KIND_CLIENT, f"分析 run 不存在: {run_id}")
    acc = json.loads(row["usage_json"]) if row["usage_json"] else {
        "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
        "calls": 0}
    for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
        acc[k] += int(usage.get(k) or 0)
    acc["calls"] += 1
    with conn:
        conn.execute("UPDATE analysis_runs SET usage_json = ? WHERE id = ?",
                     (json.dumps(acc, ensure_ascii=False), run_id))
    # budget 取 run 建时快照,None → 环境缺省(不入 usage_json,只回给调用方)
    # 注意:0 是合法值(不限预算),不能用 falsy 判断
    acc["budget"] = row["budget"] if row["budget"] is not None else token_budget()
    return acc


def run_usage(run_id: str) -> dict:
    """读 run 当前 usage 累进(预算检查用);run 不存在 → AIError。"""
    conn = db.connect()
    try:
        row = _get_run(conn, run_id)
        if row is None:
            raise AIError(KIND_CLIENT, f"分析 run 不存在: {run_id}")
        acc = json.loads(row["usage_json"]) if row["usage_json"] else {
            "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
            "calls": 0}
        acc["budget"] = row["budget"] if row["budget"] is not None else token_budget()
        return acc
    finally:
        conn.close()


def check_budget(run_id: str) -> None:
    """预算已超 → CircuitStop(budget_exceeded);未超 → 无操作。
    budget=0 = 不限预算(用户显式选择,2026-08-05 拍板:全程跑完优先;
    循环检测与用户中断两条保险不受影响)。"""
    acc = run_usage(run_id)
    if acc["budget"] == 0:
        return
    if acc["total_tokens"] >= acc["budget"]:
        raise CircuitStop(
            STOP_BUDGET,
            f"token 预算耗尽({acc['total_tokens']}/{acc['budget']}),"
            "本 run 停机,已完成部分如实保留")


def append_tool_log(run_id: str, entry: dict) -> None:
    """追加一条工具调用台账 {tool, args 摘要, result_count, truncated}。"""
    conn = db.connect()
    try:
        row = _get_run(conn, run_id)
        if row is None:
            return
        log = json.loads(row["tool_log_json"]) if row["tool_log_json"] else []
        log.append(entry)
        with conn:
            conn.execute(
                "UPDATE analysis_runs SET tool_log_json = ? WHERE id = ?",
                (json.dumps(log, ensure_ascii=False), run_id))
    finally:
        conn.close()


def is_aborted(run_id: str) -> bool:
    """run 是否已被用户中断(abort 联动,每轮/每窗前检查)。"""
    conn = db.connect()
    try:
        row = _get_run(conn, run_id)
        return bool(row and row["status"] == "aborted")
    finally:
        conn.close()


def _audit_ai_call(case_id: str, run_id: str, model: str | None, *,
                   ok: bool, usage: dict | None = None,
                   error_kind: str | None = None) -> None:
    """逐次审计(actor=ai,成功/失败都留痕,零静默;凭据永不入 detail)。"""
    conn = db.connect()
    try:
        with conn:
            db.append_audit(conn, case_id, actor="ai", action="ai_call",
                            scope=run_id,
                            detail={"run_id": run_id, "model": model, "ok": ok,
                                    "usage": usage, "error_kind": error_kind})
    finally:
        conn.close()


# ==================== 统一对话入口 ====================

def chat(messages: list[dict], *, thinking: bool = False,
         run_id: str | None = None, tools: list[dict] | None = None) -> dict:
    """统一 AI 对话入口:配置动态重读 + 预算闸 + 调用 + 审计 + usage 累进。

    - offline_lite(无 key):抛 AIError(kind=offline),调用方走兜底,不写审计
      (根本没发生调用);
    - 外发档(非 ollama 且有 key)先过合规双闸(2026-08-11):全局外发同意
      未记录 → consent_required;本案件(run_id 反查)设「禁止 AI 外发」→
      external_blocked;闸门拒绝=调用未发生,不写 ai_call 审计;
      ollama 本地档数据不出机,不受闸(索图 profile 把 ollama 也算 online,
      闸门按 provider 判定不按档位);
    - run_id 给定时:调用前查预算(已超 → CircuitStop(budget_exceeded),
      不再发生调用);调用后 usage 累进 run,累进后超预算同样
      CircuitStop(budget_exceeded)(本次结果已如实记账);
    - 成功/失败都写审计(actor=ai,scope=run_id);
    - 返回 {content, tool_calls, model, usage}。
    """
    if not ai_available():
        raise AIError(KIND_OFFLINE,
                      "当前档位无 AI(offline_lite):未配置 API key")
    cfg = _resolve_config()
    timeout = float(_conf("AI_TIMEOUT") or _conf("DEEPSEEK_TIMEOUT")
                    or _DEFAULT_TIMEOUT)
    case_id = None
    if run_id is not None:
        check_budget(run_id)                  # 预算已超:不再发生调用
        conn = db.connect()
        try:
            row = _get_run(conn, run_id)
            case_id = row["case_id"] if row else None
        finally:
            conn.close()
    if cfg["provider"] != "ollama" and cfg["api_key"]:
        conn = db.connect()                   # 合规双闸(2026-08-11)只拦外发档:
        try:                                  # 全局外发同意 + 按案件禁止;
            _external_gate(conn, case_id)     # ollama 本地数据不出机,不受闸
        finally:
            conn.close()
    t0 = time.monotonic()
    try:
        result = _call_api(messages, model=cfg["model"],
                           base_url=cfg["base_url"], api_key=cfg["api_key"],
                           timeout=timeout, thinking=thinking, tools=tools)
    except AIError as e:
        if case_id:
            _audit_ai_call(case_id, run_id, cfg["model"], ok=False,
                           error_kind=e.kind)
        # 运行日志只记元信息(模型/耗时/错误分类/调用者),不记 prompt 内容
        logging_setup.app_logger().warning(
            "AI 调用失败 run=%s provider=%s model=%s kind=%s %dms",
            run_id or "direct", cfg["provider"], cfg["model"], e.kind,
            int((time.monotonic() - t0) * 1000))
        raise
    # 运行日志摘要:模型/tokens/耗时/调用者;prompt 与回答内容永不进日志
    logging_setup.app_logger().info(
        "AI 调用 run=%s provider=%s model=%s tokens=%s %dms",
        run_id or "direct", cfg["provider"], result["model"],
        (result["usage"] or {}).get("total_tokens"),
        int((time.monotonic() - t0) * 1000))
    if run_id is not None:
        conn = db.connect()
        try:
            acc = _accumulate_usage(conn, run_id, result["usage"])
        finally:
            conn.close()
        if case_id:
            _audit_ai_call(case_id, run_id, result["model"], ok=True,
                           usage=result["usage"])
        budget = acc.pop("budget")
        if budget != 0 and acc["total_tokens"] > budget:   # 0=不限(显式选择)
            raise CircuitStop(
                STOP_BUDGET,
                f"token 预算超限({acc['total_tokens']}/{budget}),"
                "本次结果已记账,本 run 停机")
    return result


# ==================== 工具调度循环(熔断四条 + abort,硬约束) ====================

def _tool_log_entry(name: str, args: dict | None, result: dict) -> dict:
    """工具调用台账条目:{tool, args 摘要, result_count, truncated}。"""
    args_text = json.dumps(args or {}, ensure_ascii=False)
    count = 0
    for key in ("items", "lines", "sources"):
        v = result.get(key)
        if isinstance(v, list):
            count = len(v)
            break
    else:
        count = int(result.get("total") or 0)
    return {"tool": name,
            "args": args_text[:200],          # 摘要截断,台账不吃预算
            "result_count": count,
            "truncated": bool(result.get("truncated"))}


def run_agent(run_id: str, messages: list[dict], *,
              thinking: bool = False) -> dict:
    """工具调度循环:chat ↔ ai_tools.run_tool,直到 AI 不再要工具或熔断。

    熔断四条(每轮/每次调用前检查,命中即停并如实标因):
    round_limit / tool_call_limit / budget_exceeded / loop_detected;
    外加 aborted(用户中断,每轮前检查)。工具错误不炸循环:{ok:false}
    结果喂回 AI 自纠。返回 {content, stop_reason, rounds, tool_calls, usage}。
    """
    from . import ai_tools                     # 延迟导入,避免模块环
    max_rounds = _int_conf("AI_MAX_ROUNDS", DEFAULT_MAX_ROUNDS)
    max_calls = _int_conf("AI_MAX_TOOL_CALLS", DEFAULT_MAX_TOOL_CALLS)
    msgs = list(messages)
    seen: dict[str, int] = {}                 # (工具+参数) 出现次数,循环自检
    rounds = calls = 0
    stop_reason = STOP_COMPLETED
    content = None
    while True:
        if is_aborted(run_id):                # 用户中断,每轮前检查
            stop_reason, content = STOP_ABORTED, None
            break
        if rounds >= max_rounds:
            stop_reason = STOP_ROUND_LIMIT
            break
        try:
            result = chat(msgs, thinking=thinking, run_id=run_id,
                          tools=ai_tools.TOOLS)
        except CircuitStop as e:              # 预算超限(chat 内记账后抛)
            stop_reason = e.reason
            break
        rounds += 1
        if not result["tool_calls"]:
            content = result["content"]
            break
        msgs.append({"role": "assistant",
                     "content": result["content"],
                     "tool_calls": [tc["raw"] for tc in result["tool_calls"]]})
        for tc in result["tool_calls"]:
            if calls >= max_calls:
                stop_reason = STOP_TOOL_CALL_LIMIT
                break
            key = tc["name"] + "\n" + (tc["arguments_raw"] or "")
            seen[key] = seen.get(key, 0) + 1
            if seen[key] >= 3:                # 第 3 次相同调用:判循环即停
                stop_reason = STOP_LOOP       # (不再执行,防空转烧钱)
                break
            res = ai_tools.run_tool(tc["name"], tc["arguments"])
            calls += 1
            append_tool_log(run_id, _tool_log_entry(tc["name"],
                                                    tc["arguments"], res))
            msgs.append({"role": "tool", "tool_call_id": tc["id"],
                         "content": json.dumps(res, ensure_ascii=False,
                                               default=str)})
        if stop_reason != STOP_COMPLETED:
            break
    return {"content": content, "stop_reason": stop_reason,
            "rounds": rounds, "tool_calls": calls, "usage": run_usage(run_id)}
