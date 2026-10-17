"""Motor inicial de análise estática para código Python usando AST.

O código recebido é analisado sintaticamente; ele nunca é executado.
"""

from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable


_SECRET_NAME = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_DANGEROUS_DYNAMIC_CALLS = {"eval", "exec"}
_SHELL_COMMAND_CALLS = {"run", "Popen", "call", "check_call", "check_output"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    line: int
    message: str
    cwe: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _target_names(target: ast.AST) -> Iterable[str]:
    """Retorna nomes de variáveis/atributos à esquerda de uma atribuição."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Attribute):
        yield target.attr
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _target_names(element)


def _function_name(function: ast.AST) -> str | None:
    """Extrai o nome final de uma chamada, como eval ou run."""
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


def _is_nonempty_string(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(node.value.strip())
    )


def scan_source(source_code: str, filename: str = "codigo.py") -> list[Finding]:
    """Analisa código Python e retorna achados ordenados por linha.

    Pode lançar SyntaxError caso o código-fonte seja sintaticamente inválido.
    """
    tree = ast.parse(source_code, filename=filename, mode="exec")
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add_finding(finding: Finding) -> None:
        # Evita duplicar a mesma regra na mesma linha.
        key = (finding.rule_id, finding.line)
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for node in ast.walk(tree):
        # Regra SAST001: atribuição de literal de texto a variável sensível.
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets: list[ast.AST]
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            else:
                targets = [node.target]

            if _is_nonempty_string(value):
                for target in targets:
                    if any(_SECRET_NAME.search(name) for name in _target_names(target)):
                        add_finding(
                            Finding(
                                rule_id="SAST001",
                                title="Possível segredo hardcoded",
                                severity="HIGH",
                                line=getattr(value, "lineno", getattr(node, "lineno", 1)),
                                message=(
                                    "Uma variável com nome associado a credenciais ou segredos "
                                    "recebe um texto literal. O valor não é exibido no relatório."
                                ),
                                cwe="CWE-798",
                                recommendation=(
                                    "Leia o segredo de uma variável de ambiente ou de um serviço "
                                    "de segredos; não armazene credenciais no código versionado."
                                ),
                            )
                        )

        # A mesma regra também identifica dicionários como {"api_key": "..."}.
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if (
                    isinstance(key_node, ast.Constant)
                    and isinstance(key_node.value, str)
                    and _SECRET_NAME.search(key_node.value)
                    and _is_nonempty_string(value_node)
                ):
                    add_finding(
                        Finding(
                            rule_id="SAST001",
                            title="Possível segredo hardcoded",
                            severity="HIGH",
                            line=getattr(value_node, "lineno", getattr(node, "lineno", 1)),
                            message=(
                                "Uma chave de dicionário associada a credenciais ou segredos "
                                "contém um texto literal. O valor não é exibido no relatório."
                            ),
                            cwe="CWE-798",
                            recommendation=(
                                "Leia o segredo de uma variável de ambiente ou de um serviço "
                                "de segredos; não armazene credenciais no código versionado."
                            ),
                        )
                    )

        if isinstance(node, ast.Call):
            called_name = _function_name(node.func)

            # Regra SAST002: eval/exec permitem executar código construído dinamicamente.
            if called_name in _DANGEROUS_DYNAMIC_CALLS:
                add_finding(
                    Finding(
                        rule_id="SAST002",
                        title="Execução dinâmica de código",
                        severity="HIGH",
                        line=getattr(node, "lineno", 1),
                        message=f"Chamada a {called_name}() detectada.",
                        cwe="CWE-95",
                        recommendation=(
                            "Evite eval/exec. Prefira alternativas explícitas e valide os dados "
                            "de entrada antes de processá-los."
                        ),
                    )
                )

            # Regra SAST003: comandos de shell podem permitir injeção de comandos.
            shell_is_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if called_name in _SHELL_COMMAND_CALLS and shell_is_true:
                add_finding(
                    Finding(
                        rule_id="SAST003",
                        title="Execução de comando com shell=True",
                        severity="HIGH",
                        line=getattr(node, "lineno", 1),
                        message=(
                            "Uma chamada de execução de processo utiliza shell=True, "
                            "o que pode abrir espaço para injeção de comandos."
                        ),
                        cwe="CWE-78",
                        recommendation=(
                            "Prefira passar o executável e os argumentos em uma lista para "
                            "subprocess, mantendo shell=False e evitando concatenar entrada do usuário."
                        ),
                    )
                )

    return sorted(findings, key=lambda item: (item.line, item.rule_id))
