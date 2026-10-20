"""A página inicial convive com todos os endpoints existentes."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_homepage_served_at_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert response.headers["Cache-Control"] == "no-store"
    assert "Central de operações" in response.text
    assert 'href="/dashboard"' in response.text
    assert 'href="/docs"' in response.text
    assert 'id="scan-form"' in response.text
    assert "'/openapi.json'" in response.text


def test_homepage_does_not_hide_api_routes():
    spec = client.get("/openapi.json").json()
    for method, path in [
        ("get", "/health"),
        ("post", "/scan"),
        ("get", "/llm/health"),
        ("post", "/scan/semantic"),
        ("post", "/scan/project"),
        ("post", "/api/scans/ingest"),
        ("get", "/api/dashboard"),
        ("get", "/api/scans"),
        ("get", "/dashboard"),
        ("get", "/reports/{scan_id}.{fmt}"),
    ]:
        assert method in spec["paths"][path]
    assert client.get("/dashboard").status_code == 200
    assert client.get("/health").json()["status"] == "ok"


def test_quick_scan_endpoint_still_works():
    res = client.post("/scan/semantic", json={
        "filename": "exemplo.py",
        "source_code": 'entrada = input("Digite: ")\nresultado = eval(entrada)',
        "use_llm": False,
    })
    assert res.status_code == 200
    assert res.json()["summary"]["total_findings"] >= 1
