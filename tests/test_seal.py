"""M4 案件封存导出:打包→独立校验全过;篡改金库原文→校验失败如实;
坏 zip→422;sealed_at 留痕(列表可见);封存不冻结如实标注;审计留痕。

独立校验走 POST /seal/verify 上传 zip(校验逻辑 seal.verify_seal_bytes
是纯函数,不依赖平台数据库);本文件同时直调纯函数验证「脱离平台也能验」。
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import db, seal
from backend.app.main import app

from conftest import NGINX_TEXT


@pytest.fixture()
def client(data_dir):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sealed(client):
    """建案 → 上传 nginx → 确认 → 解析 → 封存,返回 (case_id, seal 响应)。"""
    case_id = client.post("/cases", json={"name": "封存测试案"}).json()["id"]
    up = client.post(f"/cases/{case_id}/sources:upload",
                     files={"file": ("access.log", NGINX_TEXT.encode(),
                                     "text/plain")},
                     data={"system": "web-01"})
    sid = up.json()["sources"][0]["source_id"]
    client.post(f"/sources/{sid}/confirm",
                json={"format_id": "nginx_combined",
                      "tz_declared": "Asia/Shanghai", "log_type": "web"})
    r = client.post(f"/sources/{sid}/parse")
    assert r.status_code == 200 and r.json()["parsed"] == 3
    r = client.post(f"/cases/{case_id}:seal")
    assert r.status_code == 200
    return case_id, r.json()


def _tamper_vault(zip_bytes: bytes) -> bytes:
    """重打包:把包里第一份金库原文改成别的字节(模拟交接途中被篡改)。"""
    src = zipfile.ZipFile(io.BytesIO(zip_bytes))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            if name.startswith("vault/"):
                data = b"tampered-by-mitm\n"
            dst.writestr(name, data)
    return buf.getvalue()


def test_seal_package_and_verify_ok(client, sealed):
    case_id, body = sealed
    path = Path(body["export_file"])
    assert path.is_file() and path.suffix == ".zip"
    assert body["sources"] == 1 and body["vault_copied"] == 1
    assert body["vault_missing"] == []
    assert body["audit"]["count"] > 0 and body["audit"]["chain_ok_at_seal"]
    assert "不冻结" in body["note"]                    # 封存不冻结如实标注

    # 包内容清单齐:快照/manifest/审计链/VERIFY/原文
    names = set(zipfile.ZipFile(path).namelist())
    assert {"case.db", "manifest.json", "audit_chain.json", "VERIFY.md"} <= names
    assert any(n.startswith("vault/") for n in names)
    manifest = json.loads(zipfile.ZipFile(path).read("manifest.json"))
    assert manifest["platform"]["product"] == "索图"
    assert manifest["sources"][0]["events"] == 3       # 事件数参照进 manifest

    # API 独立校验:全过
    r = client.post("/seal/verify",
                    files={"file": ("seal.zip", path.read_bytes(),
                                    "application/zip")})
    assert r.status_code == 200
    v = r.json()
    assert v["ok"] is True and v["failures"] == []
    assert all(c["ok"] for c in v["checks"])

    # 纯函数直调:脱离平台数据库同样全过(独立校验工具精神)
    v2 = seal.verify_seal_bytes(path.read_bytes())
    assert v2["ok"] is True


def test_seal_marks_sealed_at_and_audit(client, sealed):
    case_id, _ = sealed
    items = client.get("/cases").json()["items"]
    mine = next(i for i in items if i["id"] == case_id)
    assert mine["sealed_at"] is not None               # 列表可见
    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT actor, action FROM audit_log"
            " WHERE action = 'case_seal' AND case_id = ?",
            (case_id,)).fetchone()
        assert row is not None and row["actor"] == "tester"   # 审计锚真人
        ok, msg = db.verify_audit(conn)
        assert ok, msg
    finally:
        conn.close()


def test_verify_tampered_vault_fails(client, sealed):
    """篡改金库原文 → 校验失败如实(哪份源、登记/实测哈希都列出)。"""
    _, body = sealed
    raw = Path(body["export_file"]).read_bytes()
    r = client.post("/seal/verify",
                    files={"file": ("seal.zip", _tamper_vault(raw),
                                    "application/zip")})
    v = r.json()
    assert v["ok"] is False
    assert any("原文被篡改" in f for f in v["failures"])


def test_verify_tampered_audit_chain_fails(client, sealed):
    """篡改审计链条目(改 action 不改 hash)→ entry_hash 重算即破。"""
    _, body = sealed
    raw = Path(body["export_file"]).read_bytes()
    src = zipfile.ZipFile(io.BytesIO(raw))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            if name == "audit_chain.json":
                entries = json.loads(data)
                entries[0]["action"] = "forged_action"
                data = json.dumps(entries, ensure_ascii=False).encode()
            dst.writestr(name, data)
    v = seal.verify_seal_bytes(buf.getvalue())
    assert v["ok"] is False
    assert any("被篡改" in f for f in v["failures"])


def test_verify_bad_zip_422(client):
    r = client.post("/seal/verify",
                    files={"file": ("x.zip", b"not a zip at all",
                                    "application/zip")})
    assert r.status_code == 422                        # 坏 zip 如实 422


def test_seal_unknown_case_404(client):
    assert client.post("/cases/nope:seal").status_code == 404
