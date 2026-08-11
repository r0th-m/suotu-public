"""指纹探测契约:三格式给出正确建议;置信度不足如实 unknown → 建议 raw_t0。"""
from __future__ import annotations

from backend.app import fingerprint

from conftest import (APACHE_TEXT, IIS_TEXT, NGINX_TEXT, RAW_TEXT,
                      ZERO_HIT_TEXT)


def _detect(tmp_path, text, name="sample.log"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return fingerprint.detect(p)


def test_detect_nginx(tmp_path):
    r = _detect(tmp_path, NGINX_TEXT)
    assert r["verdict"] == "ok"
    top = r["suggestions"][0]
    assert top["format_id"] == "nginx_combined"
    assert top["confidence"] >= 0.9
    # 抽样预览带前 3 行解析结果(人核对的依据)
    assert len(top["sample_preview"]) == 3
    assert top["sample_preview"][0]["norm"]["path"] == "/index.html"


def test_detect_apache(tmp_path):
    r = _detect(tmp_path, APACHE_TEXT)
    assert r["verdict"] == "ok"
    assert r["suggestions"][0]["format_id"] == "apache_common"
    # nginx_combined 解析器对 common 行同样能命中?不能:common 行缺
    # referer/ua 两段 → nginx 命中率 0;两格式应可区分
    ids = [s["format_id"] for s in r["suggestions"] if s["confidence"] > 0]
    assert "nginx_combined" not in ids


def test_detect_iis(tmp_path):
    r = _detect(tmp_path, IIS_TEXT)
    assert r["verdict"] == "ok"
    top = r["suggestions"][0]
    assert top["format_id"] == "iis_w3c"
    assert top["header_hit"] is True                 # #Software/#Fields 头行探测


def test_detect_unknown_suggests_raw(tmp_path):
    """蛮荒文本:任何格式命中率不过阈值 → 如实 unknown,建议 raw_t0 兜底。"""
    r = _detect(tmp_path, ZERO_HIT_TEXT)
    assert r["verdict"] == "unknown"
    assert r["recommended_fallback"] == "raw"
    # 建议清单仍如实给出(可能为空或低置信度),不做静默确认
    assert all(s["confidence"] < r["threshold"] for s in r["suggestions"])


def test_detect_raw_text_also_unknown(tmp_path):
    r = _detect(tmp_path, RAW_TEXT)
    assert r["verdict"] == "unknown"
    assert r["recommended_fallback"] == "raw"


def test_detect_never_confirms(tmp_path):
    """纪律断言:探测输出只有建议,没有「已确认格式」字段。"""
    r = _detect(tmp_path, NGINX_TEXT)
    assert "confirmed" not in r and "format_id" not in r
