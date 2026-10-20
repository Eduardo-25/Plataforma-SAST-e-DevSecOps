"""Fluxo de dados intraprocedural: origem -> atribuições -> função sensível.

A AST é inspecionada, nunca executada. É uma aproximação didática, não uma
análise completa de Python. Veja docs/CP2.md para as limitações.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class Origin:
    line: int
    name: str
    kind: str = "external_input"


@dataclass(frozen=True)
class Value:
    origins: frozenset[Origin] = frozenset()
    via: frozenset[tuple[int, str]] = frozenset()

    def join(self, other: "Value") -> "Value":
        return Value(self.origins | other.origins, self.via | other.via)


CLEAN = Value()


def qualified(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return qualified(node.value) + "." + node.attr
    return ""


class TaintAnalyzer:
    def __init__(self):
        self.findings: dict[tuple[str, int], dict] = {}
        self.aliases: dict[str, str] = {}

    def name(self, node: ast.AST) -> str:
        name = qualified(node)
        root, dot, tail = name.partition(".")
        return self.aliases.get(root, root) + (dot + tail if dot else "")

    def source(self, node: ast.AST) -> Value:
        name = self.name(node.func) if isinstance(node, ast.Call) else self.name(node)
        line = getattr(node, "lineno", 1)
        if name == "input" and isinstance(node, ast.Call):
            return Value(frozenset({Origin(line, "input()")}))
        if name == "sys.argv" or name.startswith("sys.argv."):
            return Value(frozenset({Origin(line, "sys.argv")}))
        # Flask e Starlette/FastAPI: acesso direto e getters de entrada HTTP.
        for prefix in ("request.args", "request.form", "request.values", "request.json",
                       "request.get_json", "request.query_params", "request.path_params"):
            if name == prefix or name.startswith(prefix + "."):
                return Value(frozenset({Origin(line, prefix)}))
        return CLEAN

    def expression(self, node: ast.AST | None, env: dict[str, Value]) -> Value:
        if node is None:
            return CLEAN
        if isinstance(node, ast.Name):
            return env.get(node.id, CLEAN).join(self.source(node))
        if isinstance(node, ast.Constant):
            return CLEAN
        if isinstance(node, ast.Lambda):
            return CLEAN  # Corpos de lambdas não são modelados nesta versão.
        if isinstance(node, ast.NamedExpr):
            value = self.expression(node.value, env)
            self.assign(node.target, value, env, node.lineno)
            return value
        if isinstance(node, ast.Call):
            args = [self.expression(arg, env) for arg in node.args]
            kwargs = {kw.arg: self.expression(kw.value, env) for kw in node.keywords}
            self.check_sink(node, args, kwargs)
            # Conversão numérica restringe o valor, mas só com built-ins não sombreados.
            if self.name(node.func) in {"int", "float"} and self.name(node.func) not in env:
                return CLEAN
            value = self.source(node)
            # Métodos como texto.strip()/format()/replace() propagam contaminação.
            if isinstance(node.func, ast.Attribute):
                value = value.join(self.expression(node.func.value, env))
            for arg in args + list(kwargs.values()):
                value = value.join(arg)
            return value
        value = self.source(node)
        for child in ast.iter_child_nodes(node):
            value = value.join(self.expression(child, env))
        return value

    def check_sink(self, node: ast.Call, args: list[Value], kwargs: dict) -> None:
        name = self.name(node.func)
        first = args[0] if args else kwargs.get("args", kwargs.get("command", kwargs.get("source", CLEAN)))
        rule = None
        if name in {"eval", "exec"}:
            rule = ("TAINT001", "Entrada externa em execução dinâmica", "CWE-95", "CRITICAL")
        elif name in {"os.system", "os.popen"}:
            rule = ("TAINT002", "Entrada externa em comando de shell", "CWE-78", "CRITICAL")
        elif name in {"subprocess.run", "subprocess.Popen", "subprocess.call",
                      "subprocess.check_call", "subprocess.check_output"}:
            # shell=False/ausente não é considerado injeção de shell por esta regra.
            shell = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
            if shell is not None and not (isinstance(shell, ast.Constant) and shell.value is False):
                rule = ("TAINT002", "Entrada externa em possível comando de shell", "CWE-78", "CRITICAL")
        elif name.endswith((".execute", ".executemany", ".executescript")):
            # O primeiro argumento é a consulta; os parâmetros separados não são SQL.
            first = args[0] if args else kwargs.get("query", kwargs.get("sql", CLEAN))
            rule = ("TAINT003", "Entrada externa na construção de SQL", "CWE-89", "HIGH")
        if not rule or not first.origins:
            return
        rule_id, title, cwe, severity = rule
        key = (rule_id, node.lineno)
        old = self.findings.get(key)
        sources = [vars(origin) for origin in sorted(first.origins, key=lambda x: (x.line, x.name))]
        steps = [{"line": line, "variable": var} for line, var in sorted(first.via)]
        finding = {
            "rule_id": rule_id, "title": title, "severity": severity, "line": node.lineno,
            "cwe": cwe, "message": "Um valor de origem externa ou parâmetro alcança uma função sensível.",
            "sources": sources, "propagation": steps, "sink": name,
            "confidence": "MEDIUM" if any(s["kind"] == "parameter_assumption" for s in sources) else "HIGH",
        }
        if old:
            for field in ("sources", "propagation"):
                finding[field] = old[field] + [x for x in finding[field] if x not in old[field]]
        self.findings[key] = finding

    def assign(self, target: ast.AST, value: Value, env: dict, line: int):
        if isinstance(target, ast.Name):
            env[target.id] = Value(value.origins, value.via | {(line, target.id)}) if value.origins else CLEAN
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self.assign(child, value, env, line)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            # Aproximação conservadora: contamina o objeto inteiro.
            root = target.value
            while isinstance(root, (ast.Subscript, ast.Attribute)):
                root = root.value
            if isinstance(root, ast.Name):
                self.assign(root, env.get(root.id, CLEAN).join(value), env, line)

    @staticmethod
    def merge(left: dict, right: dict) -> dict:
        return {key: left.get(key, CLEAN).join(right.get(key, CLEAN)) for key in left.keys() | right.keys()}

    def block(self, statements: list, env: dict):
        for node in statements:
            if isinstance(node, ast.Import):
                for item in node.names:
                    self.aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    self.aliases[item.asname or item.name] = (node.module or "") + "." + item.name
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local = dict(env)
                params = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                params += [x for x in (node.args.vararg, node.args.kwarg) if x]
                for arg in params:
                    local[arg.arg] = Value(frozenset({Origin(node.lineno, arg.arg, "parameter_assumption")}))
                aliases_before = dict(self.aliases)
                self.block(node.body, local)
                self.aliases = aliases_before
            elif isinstance(node, ast.ClassDef):
                self.block(node.body, dict(env))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = self.expression(node.value, env)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                # Desempacotamento literal mantém cada posição separada.
                if len(targets) == 1 and isinstance(targets[0], (ast.Tuple, ast.List)) and isinstance(node.value, (ast.Tuple, ast.List)) and len(targets[0].elts) == len(node.value.elts):
                    for target, item in zip(targets[0].elts, node.value.elts):
                        self.assign(target, self.expression(item, env), env, node.lineno)
                else:
                    for target in targets:
                        self.assign(target, value, env, node.lineno)
            elif isinstance(node, ast.AugAssign):
                value = self.expression(node.target, env).join(self.expression(node.value, env))
                self.assign(node.target, value, env, node.lineno)
            elif isinstance(node, ast.If):
                self.expression(node.test, env)
                left, right = dict(env), dict(env)
                self.block(node.body, left)
                self.block(node.orelse, right)
                env.update(self.merge(left, right))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                # União até ponto fixo, limitada a 8 passagens para manter custo previsível.
                for _ in range(8):
                    body = dict(env)
                    if isinstance(node, (ast.For, ast.AsyncFor)):
                        self.assign(node.target, self.expression(node.iter, body), body, node.lineno)
                    else:
                        self.expression(node.test, body)
                    self.block(node.body, body)
                    merged = self.merge(env, body)
                    if merged == env:
                        break
                    env.update(merged)
                self.block(node.orelse, env)
            elif isinstance(node, ast.Try):
                original = dict(env)
                self.block(node.body, env)
                self.block(node.orelse, env)
                for handler in node.handlers:
                    branch = self.merge(original, env)
                    self.block(handler.body, branch)
                    env.update(self.merge(env, branch))
                self.block(node.finalbody, env)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    value = self.expression(item.context_expr, env)
                    if item.optional_vars:
                        self.assign(item.optional_vars, value, env, node.lineno)
                self.block(node.body, env)
            else:
                # Expressões, returns e condições: apenas inspeção, sem executar.
                self.expression(node, env)


def scan_taint(source_code: str, filename: str = "codigo.py") -> list[dict]:
    tree = ast.parse(source_code, filename=filename)
    analyzer = TaintAnalyzer()
    analyzer.block(tree.body, {})
    return sorted(analyzer.findings.values(), key=lambda f: (f["line"], f["rule_id"]))
