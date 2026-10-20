"""CP3: exportação de relatórios (Markdown, CSV, SARIF 2.1.0 e dashboard HTML autônomo)."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SARIF_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0"}
ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}
STATIC_DIR = Path(__file__).parent / "static"


def _cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict, limit: int = 25) -> str:
    gate, summary = report["gate"], report["summary"]
    verdict = "✅ **Aprovado**" if gate["decision"] == "passed" else "⛔ **Bloqueado**"
    trigger = report.get("trigger", {})
    lines = [f"## Security Gate — {verdict}", ""]
    ref = " · ".join(str(trigger[k]) for k in ("ref", "commit") if trigger.get(k))
    lines.append(f"Projeto `{report['project']}`" + (f" ({ref})" if ref else "")
                 + f" — {report['files_scanned']} arquivo(s) analisado(s).")
    lines.append("")
    for reason in gate["reasons"]:
        lines.append(f"- {reason}")
    lines.append(f"- Política: bloquear a partir de **{gate['policy']['fail_on']}**.")
    lines += ["", "| Severidade | Ativos |", "|---|---:|"]
    for sev, count in summary["by_severity"].items():
        if count:
            lines.append(f"| {ICON[sev]} {sev} | {count} |")
    if not summary["active"]:
        lines.append("| — | 0 |")
    if summary["suppressed"]:
        lines.append(f"\n{summary['suppressed']} achado(s) suprimido(s) com `# sast-ignore` (listados no relatório completo).")
    active = [f for f in report["findings"] if not f["suppressed"]]
    if active:
        lines += ["", "### Achados", "", "| Severidade | Local | Regra | CWE | Descrição |", "|---|---|---|---|---|"]
        for f in active[:limit]:
            lines.append(f"| {ICON[f['effective_severity']]} {f['effective_severity']} | `{_cell(f['file'])}:{f['line']}` "
                         f"| {f['rule_id']} | {f['cwe']} | {_cell(f['title'])} |")
        if len(active) > limit:
            lines.append(f"\n… e mais {len(active) - limit}. Veja o relatório completo (artefato do workflow).")
    if report["parse_errors"]:
        lines += ["", "### Arquivos não analisados", ""]
        lines += [f"- `{e['file']}`" + (f" (linha {e['line']})" if e.get("line") else "") + f": {e['message']}"
                  for e in report["parse_errors"]]
    lines += ["", "<sub>Análise estática aproximada; ausência de achados não prova segurança.</sub>"]
    return "\n".join(lines) + "\n"


def to_csv(report: dict) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["arquivo", "linha", "severidade_efetiva", "severidade_estatica", "regra", "cwe", "analise",
                     "confianca", "sink", "titulo", "suprimido", "motivo_supressao", "projeto", "gerado_em"])
    for f in report["findings"]:
        row = [f["file"], f["line"], f["effective_severity"], f["severity"], f["rule_id"], f["cwe"], f["analysis"],
               f["confidence"], f.get("sink") or "", f["title"], "sim" if f["suppressed"] else "nao",
               f["suppression_reason"], report["project"], report["generated_at"]]
        # Evita injeção de fórmula ao abrir o CSV em planilhas.
        writer.writerow(["'" + c if isinstance(c, str) and c[:1] in "=+-@" else c for c in row])
    return out.getvalue()


def to_sarif(report: dict) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in report["findings"]:
        rules.setdefault(f["rule_id"], {
            "id": f["rule_id"], "name": f["rule_id"], "shortDescription": {"text": f["title"]},
            "help": {"text": f["remediation"]["explanation"]},
            "properties": {"tags": ["security", f["cwe"]], "security-severity": SARIF_SCORE[f["effective_severity"]]},
        })
        result = {
            "ruleId": f["rule_id"], "level": SARIF_LEVEL[f["effective_severity"]],
            "message": {"text": f"{f['title']} ({f['cwe']}). {f['message']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                "region": {"startLine": f["line"]}}}],
            "partialFingerprints": {"saspFindingV1": f["fingerprint"]},
        }
        if f["suppressed"]:
            result["suppressions"] = [{"kind": "inSource", "justification": f["suppression_reason"] or "sast-ignore"}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Plataforma SAST", "informationUri":
                  "https://github.com/Eduardo-25/Plataforma-SAST-e-DevSecOps", "rules": list(rules.values())}},
                  "results": results}],
    }


def to_html(report: dict) -> str:
    """Dashboard como arquivo único, com os dados embutidos (funciona offline e como artefato de CI)."""
    page = (STATIC_DIR / "dashboard.html").read_text(encoding="utf-8")
    data = json.dumps({"standalone": True, "history": [history_row(report)], "scan": report}, ensure_ascii=False)
    data = data.replace("</", "<\\/").replace("<!--", "<\\!--")
    return page.replace("/*__SAST_DATA__*/null", data, 1)


def history_row(report: dict, scan_id: int | None = None) -> dict:
    s, g, t = report["summary"], report["gate"], report.get("trigger", {})
    return {"id": scan_id, "project": report["project"], "generated_at": report["generated_at"],
            "source": t.get("source", "manual"), "ref": t.get("ref", ""), "commit": t.get("commit", ""),
            "decision": g["decision"], "active": s["active"], "suppressed": s["suppressed"],
            "by_severity": s["by_severity"], "files_scanned": report["files_scanned"]}
