"""Testes da CP3: política do gate, relatórios, CLI/CI, persistência e dashboard."""
import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import gate, reports, storage
from app.main import app
from app.project_scan import analyze_files, build_report, evaluate_gate, matches, scan_project

VULN = "x = input()\neval(x)\n"                      # TAINT001, CRITICAL
SQL = "n = input()\ncursor.execute('S ' + n)\n"      # TAINT003, HIGH
PARAM = "def f(p):\n    cursor.execute('S ' + p)\n"  # taint por parâmetro: confiança MEDIUM
CLEAN = "import os\npassword = os.getenv('P')\n"


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SAST_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.delenv("SAST_INGEST_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


client = TestClient(app)


def project(tmp_path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp_path


# ---------- severidade e política ----------
def test_effective_severity_downgrades_parameter_only_flow():
    (finding,), _ = analyze_files([("a.py", PARAM)])
    assert finding["severity"] == "HIGH" and finding["effective_severity"] == "MEDIUM"
    assert finding["confidence"] == "MEDIUM"


def test_confirmed_flow_keeps_severity():
    (finding,), _ = analyze_files([("a.py", SQL)])
    assert finding["effective_severity"] == "HIGH"


def test_parameter_flow_into_eval_is_not_downgraded():
    # eval também casa com a regra de padrão SAST002: a união preserva a gravidade.
    (finding,), _ = analyze_files([("a.py", "def f(p):\n    eval(p)\n")])
    assert finding["effective_severity"] == "CRITICAL"


@pytest.mark.parametrize("fail_on, decision", [("CRITICAL", "passed"), ("HIGH", "blocked"), ("MEDIUM", "blocked"), ("NONE", "passed")])
def test_threshold_controls_decision(fail_on, decision):
    findings, errors = analyze_files([("a.py", SQL)])
    assert evaluate_gate(findings, errors, {"fail_on": fail_on})["decision"] == decision


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        evaluate_gate([], [], {"fail_on": "SEVERE"})


def test_clean_code_passes():
    findings, errors = analyze_files([("a.py", CLEAN)])
    assert findings == [] and evaluate_gate(findings, errors)["decision"] == "passed"


def test_max_active_findings_and_parse_error_policies():
    findings, errors = analyze_files([("a.py", PARAM), ("b.py", "if True print(1)")])
    assert evaluate_gate(findings, errors, {"fail_on": "CRITICAL"})["decision"] == "passed"
    assert evaluate_gate(findings, errors, {"fail_on": "CRITICAL", "max_active_findings": 0})["decision"] == "blocked"
    assert evaluate_gate(findings, errors, {"fail_on": "CRITICAL", "fail_on_parse_error": True})["decision"] == "blocked"


def test_syntax_error_is_reported_not_raised():
    findings, errors = analyze_files([("bad.py", "if True print(1)"), ("ok.py", VULN)])
    assert [e["file"] for e in errors] == ["bad.py"] and len(findings) == 1


def test_null_bytes_are_handled():
    _, errors = analyze_files([("n.py", "x = 1\x00")])
    assert errors


# ---------- supressões ----------
def test_suppression_is_kept_but_does_not_block():
    code = "x = input()\neval(x)  # sast-ignore: TAINT001 -- entrada validada upstream\n"
    findings, errors = analyze_files([("a.py", code)])
    assert findings[0]["suppressed"] and "validada" in findings[0]["suppression_reason"]
    report = build_report(findings, errors, 1)
    assert report["gate"]["decision"] == "passed" and report["summary"]["suppressed"] == 1


def test_suppression_for_other_rule_does_not_apply():
    code = "x = input()\neval(x)  # sast-ignore: SAST001\n"
    findings, _ = analyze_files([("a.py", code)])
    assert not findings[0]["suppressed"]


def test_bare_suppression_applies_to_all_rules_on_line():
    findings, _ = analyze_files([("a.py", "x = input()\neval(x)  # sast-ignore\n")])
    assert findings[0]["suppressed"]


def test_fingerprint_is_stable_across_line_moves():
    a, _ = analyze_files([("a.py", VULN)])
    b, _ = analyze_files([("a.py", "# novo comentário\n" + VULN)])
    assert a[0]["fingerprint"] == b[0]["fingerprint"] and a[0]["line"] != b[0]["line"]


# ---------- descoberta de arquivos ----------
@pytest.mark.parametrize("path, hit", [("samples/a.py", True), ("src/samples/a.py", True), ("app/x.py", False),
                                       (".venv/lib/x.py", True), ("my_samples/a.py", False)])
def test_exclude_globs(path, hit):
    assert matches(path, ["samples/**", ".venv/**"]) is hit


def test_scan_project_respects_exclude_and_extension(tmp_path):
    root = project(tmp_path, {"app/a.py": VULN, "samples/b.py": VULN, "notes.txt": "eval(input())"})
    report = scan_project(root)
    assert report["files_scanned"] == 1 and {f["file"] for f in report["findings"]} == {"app/a.py"}


def test_oversized_file_is_reported(tmp_path):
    root = project(tmp_path, {"big.py": "x = 1\n" + "#" * 200_001})
    report = scan_project(root)
    assert report["parse_errors"] and report["files_scanned"] == 1


# ---------- relatórios ----------
def sample_report():
    findings, errors = analyze_files([("src/a.py", VULN), ("src/b.py", SQL), ("src/c.py", PARAM)])
    return build_report(findings, errors, 3, project="demo", trigger={"source": "github-actions", "ref": "feat", "commit": "abc1234"})


def test_sarif_structure_and_levels():
    sarif = reports.to_sarif(sample_report())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {res["ruleId"] for res in run["results"]} <= rule_ids
    levels = {res["ruleId"]: res["level"] for res in run["results"]}
    assert levels["TAINT001"] == "error" and levels["TAINT003"] in {"error", "warning"}
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] >= 1 and not loc["artifactLocation"]["uri"].startswith("/")
    json.dumps(sarif)


def test_sarif_marks_suppressed_results():
    findings, errors = analyze_files([("a.py", "x = input()\neval(x)  # sast-ignore\n")])
    result = reports.to_sarif(build_report(findings, errors, 1))["runs"][0]["results"][0]
    assert result["suppressions"][0]["kind"] == "inSource"


def test_markdown_contains_verdict_and_locations():
    md = reports.to_markdown(sample_report())
    assert "Bloqueado" in md and "`src/a.py:2`" in md and "feat" in md


def test_markdown_escapes_table_breaking_characters():
    report = sample_report()
    report["findings"][0]["title"] = "a|b\nc"
    assert "a\\|b c" in reports.to_markdown(report)


def test_csv_prevents_formula_injection():
    report = sample_report()
    report["findings"][0]["title"] = "=HYPERLINK(\"http://x\")"
    csv_text = reports.to_csv(report)
    assert "'=HYPERLINK" in csv_text and ",=HYPERLINK" not in csv_text
    assert csv_text.splitlines()[0].startswith("arquivo,linha")


def test_standalone_html_embeds_data_and_neutralizes_script_breakout():
    report = sample_report()
    report["findings"][0]["message"] = "</script><script>alert(1)</script>"
    page = reports.to_html(report)
    assert "__SAST_DATA__" not in page and '"standalone": true' in page
    assert "</script><script>alert(1)" not in page


# ---------- CLI do gate ----------
def test_gate_blocks_with_exit_1_and_writes_all_reports(tmp_path, capsys):
    root = project(tmp_path / "proj", {"a.py": VULN})
    out = tmp_path / "out"
    code = gate.main(["--path", str(root), "--json-out", str(out / "r.json"), "--sarif-out", str(out / "r.sarif"),
                      "--markdown-out", str(out / "r.md"), "--csv-out", str(out / "r.csv"), "--html-out", str(out / "r.html")])
    assert code == 1 and "BLOQUEADO" in capsys.readouterr().out
    assert json.loads((out / "r.json").read_text())["gate"]["decision"] == "blocked"
    assert json.loads((out / "r.sarif").read_text())["version"] == "2.1.0"
    assert all((out / n).stat().st_size for n in ("r.md", "r.csv", "r.html"))


def test_gate_passes_with_exit_0(tmp_path):
    assert gate.main(["--path", str(project(tmp_path, {"a.py": CLEAN}))]) == 0


def test_gate_fail_on_flag_overrides_default(tmp_path):
    root = project(tmp_path, {"a.py": SQL})
    assert gate.main(["--path", str(root)]) == 1
    assert gate.main(["--path", str(root), "--fail-on", "CRITICAL"]) == 0


def test_gate_reads_toml_policy_and_excludes(tmp_path):
    root = project(tmp_path, {"a.py": SQL, "legacy/b.py": VULN,
                              "sast-gate.toml": '[policy]\nfail_on = "CRITICAL"\n[scan]\nexclude = ["legacy/**"]\n'})
    assert gate.main(["--path", str(root)]) == 0


def test_gate_usage_errors_return_2(tmp_path, capsys):
    assert gate.main(["--path", str(tmp_path / "nao-existe")]) == 2
    root = project(tmp_path, {"a.py": CLEAN, "sast-gate.toml": "[policy\n"})
    assert gate.main(["--path", str(root)]) == 2
    root2 = project(tmp_path / "b", {"a.py": CLEAN, "sast-gate.toml": '[policy]\nfail_on = "SEVERE"\n'})
    assert gate.main(["--path", str(root2)]) == 2


def test_gate_emits_github_annotations_and_step_summary(tmp_path, monkeypatch, capsys):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    code = gate.main(["--path", str(project(tmp_path / "p", {"a.py": VULN}))])
    out = capsys.readouterr().out
    assert code == 1 and "::error file=a.py,line=2,title=TAINT001::" in out
    assert "Bloqueado" in summary.read_text()


def test_annotation_escapes_newlines():
    assert gate._escape("a\nb%") == "a%0Ab%25"


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": __import__("os").environ["PATH"], "HOME": str(cwd)})


def test_changed_from_only_scans_files_changed_in_the_branch(tmp_path):
    root = project(tmp_path, {"old.py": VULN, "ok.py": CLEAN})
    git(root, "init", "-q", "-b", "main"); git(root, "add", "."); git(root, "commit", "-q", "-m", "base")
    git(root, "checkout", "-q", "-b", "feature")
    (root / "new.py").write_text(CLEAN)
    git(root, "add", "."); git(root, "commit", "-q", "-m", "change")
    assert gate.changed_files(root, "main") == ["new.py"]
    assert gate.main(["--path", str(root), "--changed-from", "main"]) == 0   # vulnerabilidade antiga não bloqueia
    (root / "new2.py").write_text(VULN)
    git(root, "add", "."); git(root, "commit", "-q", "-m", "vuln")
    assert gate.main(["--path", str(root), "--changed-from", "main"]) == 1   # a nova bloqueia


def test_changed_from_bad_ref_falls_back_to_full_scan(tmp_path, capsys):
    root = project(tmp_path, {"a.py": VULN})
    assert gate.main(["--path", str(root), "--changed-from", "origin/inexistente"]) == 1
    assert "analisando todos" in capsys.readouterr().err


# ---------- persistência ----------
def test_storage_roundtrip_and_history_order():
    first = storage.save(build_report(*analyze_files([("a.py", VULN)]), 1, project="p1"))
    second = storage.save(build_report(*analyze_files([("a.py", CLEAN)]), 1, project="p1"))
    storage.save(build_report(*analyze_files([("a.py", CLEAN)]), 1, project="p2"))
    assert [h["id"] for h in storage.history("p1")] == [first, second]
    assert storage.get(project="p1")["scan_id"] == second
    assert storage.get(first)["gate"]["decision"] == "blocked"
    assert storage.projects() == ["p1", "p2"] and storage.get(999) is None


# ---------- API ----------
def post_project(files, **extra):
    return client.post("/scan/project", json={"project": "demo", "files": [{"path": p, "source_code": c} for p, c in files], **extra})


def test_api_scan_project_blocks_and_persists():
    res = post_project([("a.py", VULN), ("b.py", CLEAN)])
    body = res.json()
    assert res.status_code == 200 and body["gate"]["decision"] == "blocked" and body["scan_id"] == 1
    assert body["files_scanned"] == 2 and body["summary"]["by_file"] == {"a.py": 1}


def test_api_scan_project_save_false_and_threshold():
    body = post_project([("a.py", SQL)], save=False, fail_on="CRITICAL").json()
    assert "scan_id" not in body and body["gate"]["decision"] == "passed"
    assert storage.history() == []


@pytest.mark.parametrize("path", ["../etc/passwd.py", "a/../../b.py", ""])
def test_api_rejects_path_traversal_labels(path):
    assert post_project([(path, CLEAN)]).status_code == 422


def test_api_caps_report_size(monkeypatch):
    monkeypatch.setattr("app.dashboard.MAX_FINDINGS", 1)
    res = post_project([("a.py", VULN), ("b.py", VULN)])
    assert res.status_code == 413 and storage.history() == []


def test_api_rejects_bad_project_name_and_empty_files():
    assert client.post("/scan/project", json={"project": "<script>", "files": [{"path": "a.py", "source_code": "x=1"}]}).status_code == 422
    assert client.post("/scan/project", json={"project": "p", "files": []}).status_code == 422


def test_dashboard_page_and_data_endpoints():
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Dashboard executivo" in page.text and "Content-Security-Policy" in page.text
    empty = client.get("/api/dashboard").json()
    assert empty["scan"] is None and empty["history"] == []
    post_project([("a.py", VULN)])
    post_project([("a.py", CLEAN)])
    data = client.get("/api/dashboard", params={"project": "demo"}).json()
    assert data["scan"]["scan_id"] == 2 and len(data["history"]) == 2 and data["projects"] == ["demo"]
    assert client.get("/api/dashboard", params={"scan_id": 1}).json()["scan"]["gate"]["decision"] == "blocked"
    assert len(client.get("/api/scans").json()) == 2


@pytest.mark.parametrize("fmt, needle", [("json", '"schema"'), ("csv", "arquivo,linha"), ("md", "Security Gate"),
                                         ("sarif", '"2.1.0"'), ("html", "Plataforma SAST")])
def test_report_downloads(fmt, needle):
    post_project([("a.py", VULN)])
    res = client.get(f"/reports/1.{fmt}")
    assert res.status_code == 200 and needle in res.text
    assert "attachment" in res.headers["content-disposition"]


def test_report_download_errors():
    assert client.get("/reports/1.json").status_code == 404
    post_project([("a.py", VULN)])
    assert client.get("/reports/1.exe").status_code == 404


# ---------- ingestão de CI ----------
def ci_report():
    return json.loads(json.dumps(sample_report()))


def test_ingest_stores_report_and_recomputes_verdict():
    body = ci_report()
    body["gate"] = {"decision": "passed", "policy": {"fail_on": "HIGH"}}   # tentativa de forjar aprovação
    body["summary"] = {"active": 0}
    res = client.post("/api/scans/ingest", json=body)
    assert res.status_code == 200 and res.json()["decision"] == "blocked"
    stored = client.get("/api/dashboard").json()["scan"]
    assert stored["summary"]["active"] == 3 and stored["trigger"]["source"] == "github-actions"


def test_ingest_defaults_trigger_source_to_ci():
    body = ci_report(); body["trigger"] = {}
    assert client.post("/api/scans/ingest", json=body).status_code == 200
    assert client.get("/api/dashboard").json()["scan"]["trigger"]["source"] == "ci"


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(schema="outro"),
    lambda r: r["findings"][0].update(severity="ULTRA"),
    lambda r: r["findings"][0].update(line="abc"),
    lambda r: r.update(project="<img src=x onerror=alert(1)>"),
    lambda r: r.pop("findings"),
])
def test_ingest_validates_input(mutate):
    body = ci_report(); mutate(body)
    assert client.post("/api/scans/ingest", json=body).status_code == 422


def test_ingest_token_when_configured(monkeypatch):
    monkeypatch.setenv("SAST_INGEST_TOKEN", "segredo")
    assert client.post("/api/scans/ingest", json=ci_report()).status_code == 401
    assert client.post("/api/scans/ingest", json=ci_report(), headers={"Authorization": "Bearer errado"}).status_code == 401
    assert client.post("/api/scans/ingest", json=ci_report(), headers={"Authorization": "Bearer segredo"}).status_code == 200


def test_cp1_and_cp2_endpoints_still_work():
    assert client.get("/health").json()["status"] == "ok"
    assert client.post("/scan", json={"source_code": "eval(input())"}).status_code == 200
    assert client.post("/scan/semantic", json={"source_code": VULN}).json()["summary"]["taint_findings"] == 1


def test_repository_passes_its_own_gate(capsys):
    """O próprio projeto (sem samples/) precisa passar pelo gate configurado em sast-gate.toml."""
    root = Path(__file__).resolve().parents[1]
    assert gate.main(["--path", str(root)]) == 0
