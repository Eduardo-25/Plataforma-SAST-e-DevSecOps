"""API HTTP do protótipo SAST do Checkpoint 1."""

from collections import Counter

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.scanner import scan_source

app = FastAPI(
    title="Plataforma SAST - CP1",
    description=(
        "Protótipo de análise estática Python. O código enviado é convertido em AST "
        "e inspecionado sem ser executado."
    ),
    version="0.1.0",
)


class ScanRequest(BaseModel):
    filename: str = Field(default="codigo.py", min_length=1, max_length=255)
    source_code: str = Field(min_length=1, max_length=200_000)


@app.get("/health", tags=["Sistema"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sast-api"}


@app.post("/scan", tags=["Análise"])
def scan(request: ScanRequest) -> dict:
    try:
        findings = scan_source(request.source_code, request.filename)
    except SyntaxError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "O código enviado não possui sintaxe Python válida.",
                "line": exc.lineno,
                "column": exc.offset,
            },
        ) from exc

    by_severity = Counter(finding.severity for finding in findings)
    return {
        "filename": request.filename,
        "language": "python",
        "status": "issues_found" if findings else "no_issues_found_by_initial_rules",
        "summary": {
            "total_findings": len(findings),
            "by_severity": dict(by_severity),
        },
        "findings": [finding.to_dict() for finding in findings],
        "notice": (
            "O resultado cobre apenas as regras iniciais do CP1; ausência de achados "
            "não garante que o código esteja livre de vulnerabilidades."
        ),
    }
