"""Combina regras da CP1, fluxo de dados da CP2 e revisão opcional de LLM."""
import ast
from collections import Counter

from app.scanner import scan_source
from app.taint import scan_taint
from app.llm import review_findings


ADVICE = {
    "CWE-798": ("Remova o literal e use uma variável de ambiente. Se a credencial era real, revogue-a.",
                'import os\npassword = os.environ["APP_PASSWORD"]'),
    "CWE-95": ("Para ler dados literais Python, use literal_eval. Não é um substituto para cálculos arbitrários; limite tamanho e trate erros.",
               'import ast\nentrada = input("Dados: ")\nif len(entrada) > 1000:\n    raise ValueError("Entrada muito longa")\ntry:\n    resultado = ast.literal_eval(entrada)\nexcept (ValueError, SyntaxError, RecursionError):\n    resultado = None'),
    "CWE-78": ("Use um executável fixo, argumentos separados e shell=False. Valide os argumentos conforme o comando escolhido.",
               'import subprocess\nentrada = input("Mensagem: ")\nsubprocess.run(["echo", entrada], shell=False, check=True)'),
    "CWE-89": ("Separe consulta e parâmetros. Este exemplo usa placeholders do SQLite; adapte ao driver real.",
               'nome = input("Nome: ")\ncursor.execute("SELECT id FROM usuarios WHERE nome = ?", (nome,))'),
}


def candidates(source_code: str, filename: str) -> list[dict]:
    initial = [f.to_dict() for f in scan_source(source_code, filename)]
    flows = scan_taint(source_code, filename)
    result = []
    # Um mesmo sink pode ser encontrado pelos dois motores: unimos as evidências.
    for flow in flows:
        matching = [f for f in initial if f["line"] == flow["line"] and f["cwe"] == flow["cwe"]]
        item = dict(flow)
        item["related_rules"] = [f["rule_id"] for f in matching]
        item["analysis"] = "taint"
        result.append(item)
    for finding in initial:
        if not any(f["line"] == finding["line"] and f["cwe"] == finding["cwe"] for f in flows):
            result.append({**finding, "analysis": "pattern", "sources": [], "propagation": [], "related_rules": []})
    result.sort(key=lambda f: (f["line"], f["rule_id"]))
    for index, finding in enumerate(result, 1):
        finding["id"] = f"F{index}"
        advice, example = ADVICE[finding["cwe"]]
        finding["remediation"] = {
            "origin": "rule_template", "explanation": advice, "code": example,
            "scope": "Exemplo de padrão seguro; adapte ao contexto. Não é patch aplicado ao arquivo.",
        }
        finding["ai_review"] = {"status": "not_requested"}
    return result


def analyze(source_code: str, filename: str, use_llm: bool) -> dict:
    findings = candidates(source_code, filename)
    llm = {"status": "not_requested", "message": "Análise determinística; IA não solicitada."}
    if use_llm and findings:
        llm, reviews = review_findings(source_code, findings)
        for finding in findings:
            review = reviews.get(finding["id"])
            if review:
                finding["ai_review"] = {"status": "reviewed", **review}
                # Mantém severidade original e todos os achados para auditoria humana.
                if review["corrected_code"]:
                    try:
                        ast.parse(review["corrected_code"])
                        syntax = "valid_python"
                    except (SyntaxError, ValueError, RecursionError):
                        syntax = "invalid_python"
                    finding["ai_review"]["correction_syntax"] = syntax
                    if syntax == "valid_python":
                        finding["remediation"] = {
                            "origin": "local_llm", "explanation": review["remediation_explanation"],
                            "code": review["corrected_code"], "syntax": syntax,
                            "scope": "Sugestão contextual do modelo, não aplicada. Sintaxe válida não comprova segurança nem equivalência funcional.",
                        }
            else:
                finding["ai_review"] = {"status": llm["status"]}
    elif use_llm:
        llm = {"status": "not_needed", "message": "Sem candidatos nas regras implementadas; LLM não foi chamado."}
    possible_fp = sum(f["ai_review"].get("verdict") == "likely_false_positive" for f in findings)
    return {
        "filename": filename, "language": "python", "checkpoint": "CP2",
        "status": "issues_found" if findings else "no_issues_found_by_implemented_rules",
        "summary": {"total_findings": len(findings),
                    "by_static_severity": dict(Counter(f["severity"] for f in findings)),
                    "taint_findings": sum(f["analysis"] == "taint" for f in findings),
                    "ai_likely_false_positives": possible_fp},
        "llm": llm, "findings": findings,
        "notice": "Protótipo acadêmico. Todos os achados são preservados; a IA auxilia a triagem e não prova segurança. O código analisado e as sugestões não são executados.",
    }
