"""格式指纹探测(数据驱动,backend/kb/fingerprints.yaml)。

流程(§4 入库三段式第①步,只给建议永不静默确认):
1. 抽样前 N 行(默认 50,跳过空白行);
2. 每个候选格式:头行探测(header_patterns,如 IIS 的 #Fields)+
   特征正则(line_patterns)+ 用真实解析器试解析样本算命中率;
3. 置信度 = 试解析命中率(解析器对 spec 写,命中率是最硬信号;
   正则只做预处理参考);按置信度降序输出,附前 3 行解析预览;
4. 最高置信度 < 阈值 → 如实报 unknown,建议 raw_t0 兜底。
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from . import config
from . import formats


def _load_kb() -> list[dict]:
    kb_path = config.kb_dir() / "fingerprints.yaml"
    with kb_path.open(encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    return doc.get("formats") or []


def _read_sample(path: Path, sample_lines: int,
                 max_bytes: int = 512 * 1024) -> list[str]:
    """抽样前 sample_lines 个非空行(utf-8,坏字节 replace 不炸)。

    max_bytes 总量护栏(2026-08-14 evtx 接入):二进制文件可能整段无换行,
    不限量会把整个文件当「一行」读进内存;抽样只需头部,截断不影响
    文本格式判定(头行探测/试解析本来就只看前 N 行)。
    """
    out: list[str] = []
    with path.open("rb") as f:
        head = f.read(max_bytes)
    for line in head.decode("utf-8", errors="replace").splitlines():
        if line.strip():
            out.append(line.rstrip("\r\n"))
            if len(out) >= sample_lines:
                break
    return out


def _trial_parse_binary(mod, path: Path,
                        cap: int = 200) -> tuple[float, list[dict]]:
    """二进制格式(BINARY=True)试解析:走 parse_file 文件通道, capped 前
    cap 条记录算命中率(与文本同一「真实解析器试解析」哲学,不整文件扫)。

    ParseError/异常 → (0.0, []):魔数对不上就是别的二进制,如实 0 不猜。
    """
    parsed = bad = 0
    preview: list[dict] = []
    try:
        for o in mod.parse_file(path):
            if o.kind == "event":
                parsed += 1
                if len(preview) < 3:
                    preview.append({"line_no": o.line_no, "ts_raw": o.ts_raw,
                                    "norm": o.norm})
            elif o.kind == "bad":
                bad += 1
            if parsed + bad >= cap:
                break
    except Exception:
        return 0.0, []
    total = parsed + bad
    return (parsed / total if total else 0.0), preview


def _trial_parse(format_id: str, sample: list[str],
                 path: Path | None = None) -> tuple[float, list[dict]]:
    """用真实解析器试解析样本,返回 (命中率, 前3行解析预览)。"""
    mod = formats.find_format(format_id)
    if mod is None:
        return 0.0, []
    if getattr(mod, "BINARY", False):
        # 二进制不走文本行样本;魔数初筛由 header_patterns 完成,
        # 这里用文件通道真试解析算置信度(对得上 ElfFile 的才可能是 evtx)
        if path is None:
            return 0.0, []
        return _trial_parse_binary(mod, path)
    parsed = bad = 0
    preview: list[dict] = []
    for o in mod.parse(sample):
        if o.kind == "event":
            parsed += 1
            if len(preview) < 3:
                preview.append({"line_no": o.line_no, "ts_raw": o.ts_raw,
                                "norm": o.norm})
        elif o.kind == "bad":
            bad += 1
    total = parsed + bad
    return (parsed / total if total else 0.0), preview


def detect(path: Path, sample_lines: int = 50) -> dict:
    """对文件做指纹探测,返回 {suggestions, verdict, recommended_fallback}。

    verdict: ok(最高置信度过阈值) | unknown(如实,建议 raw_t0)。
    """
    sample = _read_sample(path, sample_lines)
    suggestions: list[dict] = []
    if sample:
        head = sample[:10]
        for entry in _load_kb():
            fid = entry.get("format_id")
            if not fid or formats.find_format(fid) is None:
                continue
            header_pats = entry.get("header_patterns") or []
            header_hit = bool(header_pats) and any(
                re.search(p, line) for p in header_pats for line in head)
            rate, preview = _trial_parse(fid, sample, path=path)
            if rate <= 0.0 and not header_hit:
                continue
            suggestions.append({
                "format_id": fid,
                "name": formats.find_format(fid).NAME,
                "confidence": round(rate, 4),
                "header_hit": header_hit,
                "sample_preview": preview,
            })
    suggestions.sort(key=lambda s: s["confidence"], reverse=True)
    threshold = config.fingerprint_threshold()
    verdict = "ok" if suggestions and suggestions[0]["confidence"] >= threshold \
        else "unknown"
    return {
        "verdict": verdict,
        "threshold": threshold,
        "suggestions": suggestions,
        # 置信度不足 → 建议 T0 兜底(建议而已,确认权在人)
        "recommended_fallback": "raw" if verdict == "unknown" else None,
    }
