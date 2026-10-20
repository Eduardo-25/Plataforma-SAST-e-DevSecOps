import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.taint import scan_taint
from app.semantic import analyze
from app.llm import review_findings, llm_health

client = TestClient(app)


@pytest.mark.parametrize("code, rule", [
    ('entrada = input()\ncopia = entrada\neval(copia)', 'TAINT001'),
    ('exec(input())', 'TAINT001'),
    ('import os\nos.system(input())', 'TAINT002'),
    ('import subprocess as sp\nx = input()\nsp.run("echo " + x, shell=True)', 'TAINT002'),
    ('from subprocess import run as rodar\nrodar(input(), shell=True)', 'TAINT002'),
    ('x = request.args.get("q")\ncursor.execute(f"SELECT {x}")', 'TAINT003'),
    ('x = request.query_params["q"]\ncursor.execute("SELECT " + x)', 'TAINT003'),
    ('import sys\nx = sys.argv[1]\neval(x)', 'TAINT001'),
    ('x = input()\ny = "SELECT {}".format(x)\ncursor.execute(y)', 'TAINT003'),
    ('x = input().strip()\neval(x)', 'TAINT001'),
    ('x = input()\ny = x.replace("a", "b")\neval(y)', 'TAINT001'),
    ('x = input()\ny = "SELECT "\ny += x\ncursor.execute(y)', 'TAINT003'),
    ('x = "fixed"\nif cond:\n    x = input()\neval(x)', 'TAINT001'),
    ('x = "fixed"\nwhile cond:\n    x = input()\neval(x)', 'TAINT001'),
    ('x = input()\ny = "fixed"\nfor i in range(3):\n    eval(y)\n    y = x', 'TAINT001'),
    ('def endpoint(user):\n    consulta = "SELECT " + user\n    cursor.execute(consulta)', 'TAINT003'),
    ('x = input()\ntry:\n    y = x\nexcept ValueError:\n    y = "0"\neval(y)', 'TAINT001'),
    ('if (x := input()):\n    eval(x)', 'TAINT001'),
])
def test_taint_flows(code, rule):
    findings = scan_taint(code)
    assert rule in {f['rule_id'] for f in findings}
    assert all(f['sources'] for f in findings)


@pytest.mark.parametrize("code", [
    'x = input()\nx = "2 + 2"\neval(x)',
    'nome = input()\ncursor.execute("SELECT id FROM usuarios WHERE nome = ?", (nome,))',
    'import subprocess\nx = input()\nsubprocess.run(["echo", x], shell=False)',
    'import ast\nx = input()\nast.literal_eval(x)',
    'x = int(input())\ncursor.execute(f"SELECT {x}")',
    'eval("2 + 2")',
    'x, y = input(), "2"\neval(y)',
    'def first():\n    x = input()\ndef second():\n    x = "2"\n    eval(x)',
])
def test_no_tainted_sink(code):
    assert scan_taint(code) == []


def test_function_parameter_is_explicit_assumption():
    finding = scan_taint('def f(x):\n    eval(x)')[0]
    assert finding['sources'][0]['kind'] == 'parameter_assumption'
    assert finding['confidence'] == 'MEDIUM'


def test_shadowed_conversion_is_not_sanitizer():
    code = 'int = custom\nx = int(input())\neval(x)'
    assert scan_taint(code)


def test_union_contains_both_branch_sources():
    result = scan_taint('if cond:\n    x = input()\nelse:\n    x = request.args["q"]\neval(x)')
    assert len(result[0]['sources']) == 2


def test_cp1_and_cp2_findings_are_merged():
    result = analyze('x = input()\neval(x)', 'demo.py', False)
    assert result['summary']['total_findings'] == 1
    assert result['findings'][0]['related_rules'] == ['SAST002']
    assert result['findings'][0]['propagation'][0]['variable'] == 'x'


def test_api_semantic_and_invalid_input():
    response = client.post('/scan/semantic', json={'source_code': 'eval(input())'})
    assert response.status_code == 200
    assert response.json()['summary']['taint_findings'] == 1
    assert client.post('/scan/semantic', json={'source_code': 'if :'}).status_code == 422


def test_analyzed_code_is_never_executed(tmp_path):
    sentinel = tmp_path / 'executed.txt'
    code = f'open({str(sentinel)!r}, "w").write("bad")\neval(input())'
    assert client.post('/scan/semantic', json={'source_code': code}).status_code == 200
    assert not sentinel.exists()


def review_payload(**updates):
    review = {'finding_id': 'F1', 'severity': 'LOW', 'verdict': 'likely_false_positive',
              'explanation': 'Expressão constante, sem entrada externa.',
              'remediation_explanation': 'Faça a operação diretamente.', 'corrected_code': 'resultado = 2 + 2'}
    review.update(updates)
    return {'reviews': [review]}


def mock_post(monkeypatch, payload, status=200):
    def post(url, **kwargs):
        assert url.endswith('/api/generate')
        assert kwargs['json']['stream'] is False
        assert kwargs['json']['format']['type'] == 'object'
        return httpx.Response(status, json=payload, request=httpx.Request('POST', url))
    monkeypatch.setattr('app.llm.httpx.post', post)


def test_valid_llm_review_keeps_static_finding(monkeypatch):
    mock_post(monkeypatch, {'done': True, 'response': json.dumps(review_payload())})
    result = analyze('resultado = eval("2 + 2")', 'demo.py', True)
    assert result['llm']['status'] == 'completed'
    assert result['summary']['total_findings'] == 1
    assert result['summary']['ai_likely_false_positives'] == 1
    assert result['findings'][0]['severity'] == 'HIGH'
    assert result['findings'][0]['ai_review']['severity'] == 'LOW'
    assert result['findings'][0]['remediation']['origin'] == 'local_llm'


@pytest.mark.parametrize('payload', [
    {'done': True, 'response': 'not JSON'},
    {'done': False, 'response': json.dumps(review_payload())},
    {'done': True, 'done_reason': 'length', 'response': json.dumps(review_payload())},
    {'done': True, 'response': json.dumps({'reviews': []})},
    {'done': True, 'response': json.dumps(review_payload(finding_id='F9'))},
    {'done': True, 'response': json.dumps(review_payload(severity='BANANA'))},
    {'done': True, 'response': json.dumps({'reviews': review_payload()['reviews'] * 2})},
    {'done': True, 'response': json.dumps(review_payload(verdict='safe'))},
])
def test_bad_llm_response_falls_back(monkeypatch, payload):
    mock_post(monkeypatch, payload)
    result = analyze('eval("2")', 'demo.py', True)
    assert result['llm']['status'] == 'invalid_response'
    assert result['findings'][0]['remediation']['origin'] == 'rule_template'


def test_invalid_correction_is_not_promoted(monkeypatch):
    mock_post(monkeypatch, {'done': True, 'response': json.dumps(review_payload(corrected_code='if :'))})
    result = analyze('eval("2")', 'demo.py', True)
    assert result['findings'][0]['ai_review']['correction_syntax'] == 'invalid_python'
    assert result['findings'][0]['remediation']['origin'] == 'rule_template'


@pytest.mark.parametrize('error, expected', [
    (httpx.ConnectError('offline'), 'unavailable'),
    (httpx.ReadTimeout('slow'), 'timeout'),
])
def test_unavailable_llm_does_not_hide_results(monkeypatch, error, expected):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr('app.llm.httpx.post', fail)
    result = analyze('eval(input())', 'demo.py', True)
    assert result['llm']['status'] == expected
    assert result['summary']['total_findings'] == 1


def test_missing_model(monkeypatch):
    mock_post(monkeypatch, {'error': 'model missing'}, status=404)
    assert analyze('eval(input())', 'demo.py', True)['llm']['status'] == 'model_missing'


def test_llm_limits_and_empty_candidates():
    status, reviews = review_findings('x' * 12001, [{'id': 'F1'}])
    assert status['status'] == 'limit_exceeded'
    assert not reviews
    assert analyze('x = 1', 'demo.py', True)['llm']['status'] == 'not_needed'


def test_llm_health(monkeypatch):
    monkeypatch.setattr('app.llm.httpx.get', lambda *a, **k: httpx.Response(200,
        json={'models': [{'name': 'llama3.2:3b'}]}, request=httpx.Request('GET', 'http://localhost')))
    assert client.get('/llm/health').json()['status'] == 'ready'


def test_demo_sample_expectations():
    root = Path(__file__).resolve().parents[1] / 'samples'
    assert analyze((root / 'cp2_vulnerable.py').read_text(), 'v.py', False)['summary']['taint_findings'] == 1
    assert analyze((root / 'cp2_safe.py').read_text(), 's.py', False)['summary']['total_findings'] == 0
    assert analyze((root / 'cp2_review.py').read_text(), 'r.py', False)['summary']['total_findings'] == 1
