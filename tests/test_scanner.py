import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.scanner import scan_source

client = TestClient(app)


def test_detects_three_initial_rules():
    code = '''
import subprocess
password = "admin123"
resultado = eval(entrada)
subprocess.run("echo " + entrada, shell=True)
'''
    findings = scan_source(code, "teste.py")
    rule_ids = {finding.rule_id for finding in findings}

    assert rule_ids == {"SAST001", "SAST002", "SAST003"}
    assert len(findings) == 3
    assert all(finding.severity == "HIGH" for finding in findings)


def test_does_not_report_environment_variable_or_shell_false():
    code = '''
import os
import subprocess
password = os.getenv("APP_PASSWORD")
subprocess.run(["echo", "ola"], shell=False)
'''
    assert scan_source(code, "seguro.py") == []


def test_detects_secret_inside_dictionary():
    code = 'settings = {"api_key": "abc123"}\n'
    findings = scan_source(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SAST001"


def test_syntax_error_is_reported_by_scanner():
    with pytest.raises(SyntaxError):
        scan_source("if True print('erro')")


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_endpoint_returns_findings():
    response = client.post(
        "/scan",
        json={
            "filename": "vulneravel.py",
            "source_code": 'password = "admin123"\nresultado = eval(entrada)\n',
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total_findings"] == 2
    assert {item["rule_id"] for item in body["findings"]} == {"SAST001", "SAST002"}


def test_scan_endpoint_rejects_invalid_python():
    response = client.post(
        "/scan",
        json={"filename": "invalido.py", "source_code": "if True print('erro')"},
    )
    assert response.status_code == 422
