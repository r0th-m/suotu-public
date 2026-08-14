"""关联强度(SAG 式 PageRank)契约测试:稀有共享实体浮顶/常见实体压底/
df=1 与超热门跳过/确定性/跨源命中带分且按分排序。"""
from __future__ import annotations

import pytest

from backend.app import query, rules

from conftest import register_confirm_parse


def _line(ip: str, minute: int, second: int = 0) -> str:
    return (f'{ip} - - [10/Oct/2000:13:{minute:02d}:{second:02d} +0000] '
            f'"GET /a/{ip} HTTP/1.1" 200 100 "-" "Mozilla/5.0"')


def _two_source_case(conn, case_id):
    """源 A/B 各 6 行:稀有 IP 93.184.216.7 在两源各出现 2 次(强联动),
    其余全是唯一 IP(df=1 噪声)。返回 (sid_a, sid_b)。"""
    lines_a = [_line("93.184.216.7", 1), _line("93.184.216.7", 2)] + \
              [_line(f"93.184.217.{i}", 10 + i) for i in range(4)]
    lines_b = [_line("93.184.216.7", 3), _line("93.184.216.7", 4)] + \
              [_line(f"93.184.218.{i}", 20 + i) for i in range(4)]
    sid_a, _, _ = register_confirm_parse(
        conn, case_id, "\n".join(lines_a) + "\n", "nginx_combined",
        name="a.log")
    sid_b, _, _ = register_confirm_parse(
        conn, case_id, "\n".join(lines_b) + "\n", "nginx_combined",
        name="b.log")
    return sid_a, sid_b


def test_rare_shared_entity_scores_highest(conn, case_id):
    sid_a, sid_b = _two_source_case(conn, case_id)
    scores = query.entity_linkage_scores(case_id)
    assert scores, "有跨源共享实体应出分"
    top = max(scores, key=scores.get)
    assert top in ((sid_a, 1), (sid_a, 2), (sid_b, 1), (sid_b, 2))
    # df=1 的噪声行不得分
    assert all(scores.get((sid_a, ln), 0.0) == 0.0 for ln in (3, 4, 5, 6))


def test_determinism(conn, case_id):
    _two_source_case(conn, case_id)
    a = query.entity_linkage_scores(case_id)
    b = query.entity_linkage_scores(case_id)
    assert a == b


def test_cross_source_hits_carry_score_sorted(conn, case_id):
    _two_source_case(conn, case_id)
    rules.run_rules(conn, case_id)
    hits = [h for h in rules.list_hits(conn, case_id)["items"]
            if h["rule_id"] == "cross-source-entity"]
    assert hits, "跨源联动应有命中"
    d = hits[0]["detail_json"]
    assert d["kind"] == "cross_source"
    assert d["linkage_score"] > 0
    scores = [h["detail_json"]["linkage_score"] for h in hits]
    assert scores == sorted(scores, reverse=True)     # 强关联浮顶


def test_caps_and_empty(conn, case_id):
    # df 超 max_df 的热门实体被跳过 → 零分;无实体 → 空
    monkey_lines = [_line("93.184.216.9", i % 60, i % 60) for i in range(8)]
    register_confirm_parse(conn, case_id, "\n".join(monkey_lines) + "\n",
                           "nginx_combined", name="hot.log")
    scores = query.entity_linkage_scores(case_id, max_df=3)
    assert scores == {} or all(v == 0 for v in scores.values())
