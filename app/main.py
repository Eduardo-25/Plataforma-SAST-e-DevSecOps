"""API SAST: CP1 preservada e CP2 com fluxo de dados e LLM local."""

from collections import Counter

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from app import reports
from pydantic import BaseModel, Field

from app.dashboard import router as dashboard_router
from app.scanner import scan_source

app = FastAPI(
    title="Plataforma SAST - CP1 + CP2 + CP3",
    description=(
        "Protótipo de análise estática Python. O código enviado é convertido em AST "
        "e inspecionado sem ser executado."
    ),
    version="0.3.0",
)

app.include_router(dashboard_router)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home_page() -> HTMLResponse:
    """Central de acesso ao dashboard, scanner e endpoints documentados."""
    page = (reports.STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(page, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


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


class SemanticScanRequest(ScanRequest):
    use_llm: bool = Field(default=False, description="Ative para solicitar revisão real ao Ollama local.")


@app.get("/llm/health", tags=["CP2 - IA local"])
def ollama_health() -> dict:
    from app.llm import llm_health
    return llm_health()


@app.post("/scan/semantic", tags=["CP2 - IA local"])
def semantic_scan(request: SemanticScanRequest) -> dict:
    from app.semantic import analyze
    try:
        return analyze(request.source_code, request.filename, request.use_llm)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=422, detail={
            "message": "Código Python inválido ou complexo demais para este protótipo.",
            "line": getattr(exc, "lineno", None),
        }) from exc
