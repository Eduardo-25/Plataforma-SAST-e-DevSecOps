"""CP3: endpoints do dashboard executivo, varredura de projeto, ingestão de CI e relatórios."""
from __future__ import annotations

import hmac
import json
import os
import re
from pathlib import PurePosixPath
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from app import reports, storage
from app.project_scan import MAX_FILES, MAX_FILE_BYTES, POLICY_DEFAULTS, analyze_files, build_report

router = APIRouter()
Sev = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
MAX_TOTAL_CHARS = 5_000_000
MAX_FINDINGS = 5000
SAFE_NAME = re.compile(r"^[\w .@+=:-]{1,100}$")


# ---------- Entrada: varredura de projeto ----------
class FileIn(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    source_code: str = Field(max_length=MAX_FILE_BYTES)


class ProjectScanRequest(BaseModel):
    project: str = Field(default="projeto", pattern=SAFE_NAME.pattern)
    files: list[FileIn] = Field(min_length=1, max_length=MAX_FILES)
    fail_on: Sev | Literal["NONE"] = "HIGH"
    save: bool = True


def _clean_path(raw: str) -> str:
    path = PurePosixPath(raw.replace("\\", "/").lstrip("/"))
    if ".." in path.parts or not path.parts:
        raise HTTPException(422, detail={"message": f"Caminho inválido: {raw!r}"})
    return path.as_posix()


@router.post("/scan/project", tags=["CP3 - Gate e dashboard"])
def scan_project_endpoint(request: ProjectScanRequest) -> dict:
    if sum(len(f.source_code) for f in request.files) > MAX_TOTAL_CHARS:
        raise HTTPException(413, detail={"message": "Total de código acima do limite de 5 MB."})
    files = [(_clean_path(f.path), f.source_code) for f in request.files]
    findings, errors = analyze_files(files)
    if len(findings) > MAX_FINDINGS:
        raise HTTPException(413, detail={"message": f"Mais de {MAX_FINDINGS} achados; divida a análise em partes menores."})
    report = build_report(findings, errors, len(files), project=request.project,
                          trigger={"source": "api"}, policy={"fail_on": request.fail_on})
    if request.save:
        report["scan_id"] = storage.save(report)
    return report


# ---------- Entrada: relatório vindo do CI ----------
class _Loose(BaseModel):
    model_config = ConfigDict(extra="ignore")


class FindingIn(_Loose):
    file: str = Field(max_length=300)
    line: int = Field(ge=0, le=10_000_000)
    rule_id: str = Field(max_length=40)
    related_rules: list[str] = Field(default_factory=list, max_length=10)
    title: str = Field(max_length=300)
    message: str = Field(default="", max_length=1000)
    cwe: str = Field(max_length=20)
    severity: Sev
    effective_severity: Sev
    confidence: str = Field(default="HIGH", max_length=10)
    analysis: str = Field(default="pattern", max_length=20)
    sink: str | None = Field(default=None, max_length=200)
    sources: list[dict] = Field(default_factory=list, max_length=20)
    propagation: list[dict] = Field(default_factory=list, max_length=50)
    remediation: dict = Field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: str = Field(default="", max_length=300)
    fingerprint: str = Field(default="", max_length=64)


class ErrorIn(_Loose):
    file: str = Field(max_length=300)
    line: int | None = None
    message: str = Field(max_length=300)


class ReportIn(_Loose):
    schema_: Literal["sast-report/1"] = Field(alias="schema")
    project: str = Field(pattern=SAFE_NAME.pattern)
    files_scanned: int = Field(ge=0, le=1_000_000)
    trigger: dict = Field(default_factory=dict)
    parse_errors: list[ErrorIn] = Field(default_factory=list, max_length=MAX_FILES)
    findings: list[FindingIn] = Field(max_length=MAX_FINDINGS)
    gate: dict = Field(default_factory=dict)


def _authorize(authorization: str | None) -> None:
    token = os.environ.get("SAST_INGEST_TOKEN")
    if token and not hmac.compare_digest(authorization or "", f"Bearer {token}"):
        raise HTTPException(401, detail={"message": "Token de ingestão ausente ou inválido."})


@router.post("/api/scans/ingest", tags=["CP3 - Gate e dashboard"])
def ingest(report: ReportIn, authorization: str | None = Header(default=None)) -> dict:
    _authorize(authorization)
    findings = [f.model_dump() for f in report.findings]
    for index, finding in enumerate(findings, 1):
        finding["id"] = f"F{index}"
        finding["remediation"] = {k: str(finding["remediation"].get(k, ""))[:2000]
                                  for k in ("origin", "explanation", "code")}
    trigger = {k: str(v)[:300] for k, v in report.trigger.items() if isinstance(v, (str, int))}
    policy = {k: v for k, v in (report.gate.get("policy") or {}).items() if k in POLICY_DEFAULTS}
    # Resumo e veredito são recalculados aqui, não aceitos do cliente.
    clean = build_report(findings, [e.model_dump() for e in report.parse_errors], report.files_scanned,
                         project=report.project, trigger={"source": "ci", **trigger}, policy=policy)
    return {"scan_id": storage.save(clean), "decision": clean["gate"]["decision"]}


# ---------- Leitura: dashboard e relatórios ----------
@router.get("/api/dashboard", tags=["CP3 - Gate e dashboard"])
def dashboard_data(project: str | None = None, scan_id: int | None = None) -> dict:
    scan = storage.get(scan_id, project)
    return {"standalone": False, "projects": storage.projects(),
            "history": storage.history(project or (scan or {}).get("project")), "scan": scan}


@router.get("/api/scans", tags=["CP3 - Gate e dashboard"])
def list_scans(project: str | None = None, limit: int = Query(30, ge=1, le=200)) -> list[dict]:
    return storage.history(project, limit)


@router.get("/dashboard", response_class=HTMLResponse, tags=["CP3 - Gate e dashboard"])
def dashboard_page() -> HTMLResponse:
    page = (reports.STATIC_DIR / "dashboard.html").read_text(encoding="utf-8")
    return HTMLResponse(page, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


_FORMATS = {
    "json": ("application/json", lambda r: json.dumps(r, ensure_ascii=False, indent=2)),
    "csv": ("text/csv; charset=utf-8", reports.to_csv),
    "md": ("text/markdown; charset=utf-8", reports.to_markdown),
    "sarif": ("application/sarif+json", lambda r: json.dumps(reports.to_sarif(r), ensure_ascii=False, indent=2)),
    "html": ("text/html; charset=utf-8", reports.to_html),
}


@router.get("/reports/{scan_id}.{fmt}", tags=["CP3 - Gate e dashboard"])
def download_report(scan_id: int, fmt: str) -> Response:
    if fmt not in _FORMATS:
        raise HTTPException(404, detail={"message": f"Formato desconhecido. Use: {', '.join(_FORMATS)}."})
    report = storage.get(scan_id)
    if not report:
        raise HTTPException(404, detail={"message": "Análise não encontrada."})
    media, render = _FORMATS[fmt]
    return Response(render(report), media_type=media, headers={
        "Content-Disposition": f'attachment; filename="sast-{scan_id}.{fmt}"', "X-Content-Type-Options": "nosniff"})
