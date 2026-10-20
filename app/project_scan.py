"""CP3: varredura de vários arquivos, severidade efetiva, supressões e política do gate.

Reaproveita os motores da CP1 (regras AST) e da CP2 (taint) sem alterá-los.
O código analisado é apenas convertido em AST; nunca é executado.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.semantic import candidates

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
DEFAULT_EXCLUDE = (".git/**", ".venv/**", "venv/**", "node_modules/**", "__pycache__/**",
                   "reports/**", "samples/**")
MAX_FILES = 500
MAX_FILE_BYTES = 200_000
SUPPRESSION = re.compile(r"#\s*sast-ignore(?::\s*(?P<rules>[A-Za-z0-9_,\s-]*?))?(?:\s+--\s*(?P<why>.+))?\s*$")

POLICY_DEFAULTS = {"fail_on": "HIGH", "fail_on_parse_error": False, "max_active_findings": None}


def effective_severity(finding: dict) -> str:
    """Severidade usada pelo gate e pelo dashboard.

    Parte da severidade estática. Um fluxo de taint cuja origem é só um parâmetro
    de função assumido como externo (confiança MEDIUM) e que NÃO coincide com uma
    regra de padrão perigoso desce um nível, pois é o caso mais sujeito a falso positivo.
    A severidade estática original continua no relatório.
    """
    base = finding["severity"]
    if finding.get("confidence") == "MEDIUM" and not finding.get("related_rules") and base in RANK:
        return SEVERITIES[max(RANK[base] - 1, 0)]
    return base


def matches(path: str, patterns: Iterable[str]) -> bool:
    path = path.replace("\\", "/").lstrip("./")
    for pattern in patterns:
        pattern = pattern.replace("\\", "/").lstrip("./")
        if pattern.endswith("/**"):
            prefix = pattern[:-3]
            if path == prefix or path.startswith(prefix + "/") or ("/" + prefix + "/") in ("/" + path):
                return True
        elif fnmatch.fnmatch(path, pattern.replace("**", "*")):
            return True
    return False


def discover(root: Path, exclude: Iterable[str] = DEFAULT_EXCLUDE, only: Iterable[str] | None = None):
    """Lista arquivos .py sob root (caminhos relativos em formato POSIX)."""
    root = Path(root)
    exclude = list(exclude)
    if only is not None:
        names = sorted({p.replace("\\", "/").lstrip("./") for p in only})
    else:
        names = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.py") if p.is_file())
    return [n for n in names if n.endswith(".py") and not matches(n, exclude) and (root / n).is_file()]


def _suppressions(source: str) -> dict[int, tuple[set[str], str]]:
    """Mapeia linha -> (regras ou vazio para todas, motivo) a partir de '# sast-ignore'."""
    found = {}
    for number, text in enumerate(source.splitlines(), 1):
        if "sast-ignore" not in text:
            continue
        match = SUPPRESSION.search(text)
        if match:
            rules = {r.strip().upper() for r in (match.group("rules") or "").split(",") if r.strip()}
            found[number] = (rules, (match.group("why") or "").strip())
    return found


def _fingerprint(rule_id: str, path: str, line_text: str) -> str:
    raw = f"{rule_id}|{path}|{' '.join(line_text.split())}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def analyze_files(files: Iterable[tuple[str, str]]) -> tuple[list[dict], list[dict]]:
    """Analisa pares (caminho, código). Retorna (achados, erros de leitura/sintaxe)."""
    findings: list[dict] = []
    errors: list[dict] = []
    for path, source in files:
        try:
            if "\x00" in source:
                raise ValueError("arquivo contém bytes nulos")
            found = candidates(source, path)
        except (SyntaxError, ValueError, RecursionError) as exc:
            errors.append({"file": path, "line": getattr(exc, "lineno", None),
                           "message": f"Não foi possível analisar: {exc.__class__.__name__}"})
            continue
        lines = source.splitlines()
        suppressed_at = _suppressions(source)
        for item in found:
            rules = item.get("related_rules") or [item["rule_id"]]
            line_text = lines[item["line"] - 1] if 0 < item["line"] <= len(lines) else ""
            sup = suppressed_at.get(item["line"])
            is_sup = bool(sup) and (not sup[0] or item["rule_id"] in sup[0] or any(r in sup[0] for r in rules))
            findings.append({
                "file": path, "line": item["line"], "rule_id": item["rule_id"], "related_rules": rules,
                "title": item["title"], "message": item["message"], "cwe": item["cwe"],
                "severity": item["severity"], "effective_severity": effective_severity(item),
                "confidence": item.get("confidence", "HIGH"), "analysis": item["analysis"],
                "sink": item.get("sink"), "sources": item.get("sources", []),
                "propagation": item.get("propagation", []),
                "remediation": {"origin": item["remediation"]["origin"],
                                "explanation": item["remediation"]["explanation"],
                                "code": item["remediation"]["code"]},
                "suppressed": is_sup, "suppression_reason": sup[1] if is_sup else "",
                "fingerprint": _fingerprint(item["rule_id"], path, line_text),
            })
    findings.sort(key=lambda f: (-RANK.get(f["effective_severity"], 0), f["file"], f["line"], f["rule_id"]))
    for index, finding in enumerate(findings, 1):
        finding["id"] = f"F{index}"
    return findings, errors


def evaluate_gate(findings: list[dict], errors: list[dict], policy: dict | None = None) -> dict:
    """Decide se o PR/commit passa. Achados suprimidos não bloqueiam, mas continuam listados."""
    policy = {**POLICY_DEFAULTS, **(policy or {})}
    threshold = str(policy["fail_on"]).upper()
    if threshold not in RANK and threshold != "NONE":
        raise ValueError(f"fail_on inválido: {policy['fail_on']!r}. Use {', '.join(SEVERITIES)} ou NONE.")
    active = [f for f in findings if not f["suppressed"]]
    blocking = [] if threshold == "NONE" else [f for f in active if RANK[f["effective_severity"]] >= RANK[threshold]]
    reasons = []
    if blocking:
        reasons.append(f"{len(blocking)} achado(s) ativo(s) com severidade {threshold} ou superior.")
    limit = policy["max_active_findings"]
    if limit is not None and len(active) > int(limit):
        reasons.append(f"{len(active)} achados ativos excedem o limite de {limit}.")
    if policy["fail_on_parse_error"] and errors:
        reasons.append(f"{len(errors)} arquivo(s) não puderam ser analisados.")
    return {"decision": "blocked" if reasons else "passed", "reasons": reasons,
            "blocking_ids": [f["id"] for f in blocking], "policy": {**policy, "fail_on": threshold}}


def build_report(findings: list[dict], errors: list[dict], files_scanned: int, *, project: str = "projeto",
                 trigger: dict | None = None, policy: dict | None = None) -> dict:
    active = [f for f in findings if not f["suppressed"]]
    by_file = Counter(f["file"] for f in active)
    return {
        "schema": "sast-report/1", "project": project,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "trigger": {"source": "manual", **(trigger or {})},
        "files_scanned": files_scanned,
        "files_with_findings": len(by_file),
        "parse_errors": errors,
        "summary": {
            "total": len(findings), "active": len(active), "suppressed": len(findings) - len(active),
            "by_severity": {s: sum(f["effective_severity"] == s for f in active) for s in reversed(SEVERITIES)},
            "by_cwe": dict(Counter(f["cwe"] for f in active).most_common()),
            "by_file": dict(by_file.most_common()),
        },
        "gate": evaluate_gate(findings, errors, policy),
        "findings": findings,
        "notice": "Protótipo acadêmico: ausência de achados não prova que o código é seguro.",
    }


def scan_project(root: Path, *, project: str | None = None, exclude=DEFAULT_EXCLUDE, only=None,
                 trigger: dict | None = None, policy: dict | None = None) -> dict:
    root = Path(root)
    names = discover(root, exclude, only)
    if len(names) > MAX_FILES:
        raise ValueError(f"{len(names)} arquivos excedem o limite de {MAX_FILES}.")
    files, errors = [], []
    for name in names:
        path = root / name
        if path.stat().st_size > MAX_FILE_BYTES:
            errors.append({"file": name, "line": None, "message": f"Arquivo acima de {MAX_FILE_BYTES} bytes."})
            continue
        try:
            files.append((name, path.read_text(encoding="utf-8")))
        except (UnicodeDecodeError, OSError):
            errors.append({"file": name, "line": None, "message": "Arquivo não legível como UTF-8."})
    findings, parse_errors = analyze_files(files)
    return build_report(findings, errors + parse_errors, len(names), project=project or root.resolve().name,
                        trigger=trigger, policy=policy)
