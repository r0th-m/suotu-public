"""M3 ai_tools.py 工具五件套测试(断言级;全程不触网,不调 AI)。

覆盖:
- 白名单 dispatch:未知名 → ok:false 不执行;未知参数 → ok:false;
- 参数校验:缺必填/坏类型/超范围(收敛或报错,各有明语义);
- 结果形状:五件套各自的 ok/total/items(lines) 契约;
- 跨源闸:entity_lookup cross_source 只放行 qualifier=global;
- 作用域:time_slice/read_window 校验源属于案件(防跨案串味);
- 只读:五件套全跑一遍,审计零新增(无写路径)。
"""
from __future__ import annotations

import pytest

from backend.app import ai_tools

from conftest import NGINX_TEXT, register_confirm_parse


@pytest.fixture()
def seeded(conn, case_id):
    """三条 nginx 行走真实管线入库;返回 (case_id, source_id)。"""
    sid, _, report = register_confirm_parse(conn, case_id, NGINX_TEXT,
                                            "nginx_combined")
    assert report["parsed"] == 3
    return case_id, sid


# ---------------------------------------------------------------- 白名单/参数校验

def test_unknown_tool_not_executed():
    res = ai_tools.run_tool("drop_everything", {})
    assert res["ok"] is False and "未知工具" in res["error"]


def test_unknown_param_rejected(seeded):
    case_id, _ = seeded
    res = ai_tools.run_tool("search_logs", {"case_id": case_id, "sql": "x"})
    assert res["ok"] is False and "未知参数" in res["error"]


def test_bad_params_reported(seeded):
    case_id, sid = seeded
    assert ai_tools.run_tool("search_logs", {})["ok"] is False     # 缺 case_id
    r = ai_tools.run_tool("time_slice", {"case_id": case_id,
                                         "source_id": sid, "line_no": "x"})
    assert r["ok"] is False and "line_no" in r["error"]
    r = ai_tools.run_tool("read_window", {"source_id": sid,
                                          "line_from": 3, "line_to": 1})
    assert r["ok"] is False
    r = ai_tools.run_tool("read_window", {"source_id": sid,
                                          "line_from": 1, "line_to": 600})
    assert r["ok"] is False and "500" in r["error"]                # 上限 500 行


def test_params_none_reported():
    res = ai_tools.run_tool("search_logs", None)
    assert res["ok"] is False


# ---------------------------------------------------------------- 五件套结果形状

def test_search_logs_shape_and_limit(seeded):
    case_id, sid = seeded
    res = ai_tools.run_tool("search_logs",
                            {"case_id": case_id, "q": "curl", "limit": 999})
    assert res["ok"] is True and res["tool"] == "search_logs"
    assert res["total"] == 1 and len(res["items"]) == 1            # limit 收敛 ≤50
    item = res["items"][0]
    for key in ("source_id", "line_no", "raw", "sha256"):          # 锚点齐全
        assert item[key]
    assert item["source_id"] == sid
    # 全文面:q 无命中如实空;q=None 全量可达(契约)
    assert ai_tools.run_tool("search_logs",
                             {"case_id": case_id, "q": "不存在的词"}
                             )["total"] == 0
    assert ai_tools.run_tool("search_logs",
                             {"case_id": case_id})["total"] == 3


def test_field_stats_shape(seeded):
    case_id, sid = seeded
    res = ai_tools.run_tool("field_stats",
                            {"case_id": case_id, "source_id": sid})
    assert res["ok"] is True
    assert res["by_source"][sid]["events"] == 3
    assert res["by_source"][sid]["top_src_ip"]


def test_entity_lookup_cross_source_gate(seeded):
    case_id, _ = seeded
    # 公网 IP 93.184.216.34 → qualifier=global,跨源闸放行
    res = ai_tools.run_tool("entity_lookup",
                            {"case_id": case_id, "value": "93.184.216.34",
                             "cross_source": True})
    assert res["ok"] is True and res["total"] >= 1
    # 私网 192.168.1.10 host_scoped:cross_source=True 查不到(闸不变),
    # 案件内(cross_source=False)如实列出
    res = ai_tools.run_tool("entity_lookup",
                            {"case_id": case_id, "value": "192.168.1.10",
                             "cross_source": True})
    assert res["ok"] is True and res["total"] == 0
    res = ai_tools.run_tool("entity_lookup",
                            {"case_id": case_id, "value": "192.168.1.10"})
    assert res["ok"] is True and res["total"] >= 1


def test_time_slice_anchor_window(seeded):
    case_id, sid = seeded
    res = ai_tools.run_tool("time_slice", {"case_id": case_id,
                                           "source_id": sid, "line_no": 2,
                                           "before": 1, "after": 1})
    assert res["ok"] is True and res["anchor_line_no"] == 2
    assert [l["line_no"] for l in res["lines"]] == [1, 2, 3]
    # 边界钳到 1;缺省 before/after=100 不炸
    res = ai_tools.run_tool("time_slice", {"case_id": case_id,
                                           "source_id": sid, "line_no": 1})
    assert res["ok"] is True
    assert min(l["line_no"] for l in res["lines"]) == 1


def test_time_slice_scope_gate(seeded, conn):
    case_id, sid = seeded
    res = ai_tools.run_tool("time_slice", {"case_id": "case-别的案件",
                                           "source_id": sid, "line_no": 1})
    assert res["ok"] is False and "防串味" in res["error"]


def test_read_window_shape_and_scope(seeded):
    case_id, sid = seeded
    res = ai_tools.run_tool("read_window", {"source_id": sid,
                                            "line_from": 1, "line_to": 3})
    assert res["ok"] is True and res["total"] == 3
    assert res["lines"][0]["line_no"] == 1 and res["lines"][0]["raw"]
    res = ai_tools.run_tool("read_window", {"source_id": sid, "line_from": 1,
                                            "line_to": 2,
                                            "case_id": "case-别的案件"})
    assert res["ok"] is False                                   # 作用域校验


# ---------------------------------------------------------------- 只读断言

def test_tools_are_readonly(conn, seeded):
    case_id, sid = seeded
    before = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
    for name, params in [
        ("search_logs", {"case_id": case_id, "q": "GET"}),
        ("field_stats", {"case_id": case_id}),
        ("entity_lookup", {"case_id": case_id, "value": "93.184.216.34"}),
        ("time_slice", {"case_id": case_id, "source_id": sid, "line_no": 2}),
        ("read_window", {"source_id": sid, "line_from": 1, "line_to": 2}),
    ]:
        assert ai_tools.run_tool(name, params)["ok"] is True
    after = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
    assert after == before        # 五件套全跑一遍,审计零新增(只读)
