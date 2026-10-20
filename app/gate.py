"""CP3: Security Gate para CI/CD.

Uso: python -m app.gate [--path .] [--changed-from origin/main] [--fail-on HIGH] ...
Códigos de saída: 0 = aprovado, 1 = bloqueado pela política, 2 = erro de uso/execução.
O gate não depende do Ollama: usa só os motores determinísticos (CP1 + taint da CP2),
para que o resultado seja reprodutível e o pipeline não falhe por indisponibilidade de IA.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

from app import reports
from app.project_scan import DEFAULT_EXCLUDE, RANK, SEVERITIES, scan_project

CONFIG_NAME = "sast-gate.toml"


def load_config(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


def changed_files(root: Path, ref: str) -> list[str] | None:
    """Arquivos .py adicionados/modificados desde o merge-base com ref; None se o git falhar."""
    try:
        out = subprocess.run(["git", "-C", str(root), "diff", "--name-only", "--relative",
                              "--diff-filter=ACMR", f"{ref}...HEAD"],
                             capture_output=True, text=True, check=True, timeout=60).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    return [line for line in out.splitlines() if line.endswith(".py")]


def github_trigger(env=os.environ) -> dict:
    if env.get("GITHUB_ACTIONS") != "true":
        return {"source": "cli"}
    server, repo, run = env.get("GITHUB_SERVER_URL", "https://github.com"), env.get("GITHUB_REPOSITORY", ""), env.get("GITHUB_RUN_ID", "")
    trigger = {"source": "github-actions", "event": env.get("GITHUB_EVENT_NAME", ""),
               "ref": env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME", ""),
               "commit": env.get("GITHUB_SHA", "")[:7], "repository": repo}
    if repo and run:
        trigger["run_url"] = f"{server}/{repo}/actions/runs/{run}"
    return trigger


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def print_annotations(report: dict, threshold: str) -> None:
    """Anotações de workflow: aparecem na aba 'Files changed' do Pull Request."""
    for f in report["findings"]:
        if f["suppressed"]:
            continue
        blocking = threshold != "NONE" and RANK[f["effective_severity"]] >= RANK[threshold]
        kind = "error" if blocking else "warning"
        message = _escape(f"[{f['effective_severity']}] {f['rule_id']} ({f['cwe']}): {f['title']}. {f['remediation']['explanation']}")
        print(f"::{kind} file={f['file']},line={f['line']},title={_escape(f['rule_id'])}::{message}")


def print_console(report: dict) -> None:
    gate, summary = report["gate"], report["summary"]
    print(f"Plataforma SAST — Security Gate ({report['project']})")
    print(f"Arquivos analisados: {report['files_scanned']} | achados ativos: {summary['active']} | suprimidos: {summary['suppressed']}")
    for f in report["findings"]:
        if not f["suppressed"]:
            print(f"  {f['effective_severity']:<8} {f['file']}:{f['line']:<5} {f['rule_id']:<8} {f['cwe']:<8} {f['title']}")
    for err in report["parse_errors"]:
        print(f"  (não analisado) {err['file']}: {err['message']}")
    print("RESULTADO: " + ("APROVADO" if gate["decision"] == "passed" else "BLOQUEADO"))
    for reason in gate["reasons"]:
        print(f"  - {reason}")


def write(path: str | None, content: str) -> None:
    if path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def ingest(report: dict, url: str) -> None:
    import httpx
    try:
        token = os.environ.get("SAST_API_TOKEN")
        response = httpx.post(url.rstrip("/") + "/api/scans/ingest", json=report, timeout=15,
                              headers={"Authorization": f"Bearer {token}"} if token else {})
        response.raise_for_status()
        print(f"Relatório enviado ao dashboard (scan {response.json().get('scan_id')}).")
    except Exception as exc:  # o envio nunca altera o veredito do gate
        print(f"Aviso: não foi possível enviar ao dashboard ({exc.__class__.__name__}).", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m app.gate", description="Security Gate da Plataforma SAST.")
    p.add_argument("--path", default=".", help="Raiz do projeto a analisar.")
    p.add_argument("--config", help=f"Arquivo TOML de política (padrão: <path>/{CONFIG_NAME}, se existir).")
    p.add_argument("--project", help="Nome do projeto no relatório.")
    p.add_argument("--changed-from", metavar="REF", help="Analisa só os .py alterados desde REF (ex.: origin/main).")
    p.add_argument("--fail-on", choices=[*SEVERITIES, "NONE"], help="Severidade mínima que bloqueia (padrão: HIGH).")
    p.add_argument("--exclude", action="append", default=None, help="Glob a ignorar (repetível; substitui o padrão).")
    for fmt in ("json", "sarif", "markdown", "csv", "html"):
        p.add_argument(f"--{fmt}-out", metavar="ARQUIVO", help=f"Grava o relatório em {fmt}.")
    p.add_argument("--ingest-url", default=os.environ.get("SAST_API_URL"), help="URL da API para alimentar o dashboard.")
    p.add_argument("--no-annotations", action="store_true", help="Não emite anotações ::error do GitHub.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path)
    if not root.is_dir():
        print(f"Erro: pasta não encontrada: {root}", file=sys.stderr)
        return 2
    try:
        config = load_config(Path(args.config) if args.config else root / CONFIG_NAME)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(f"Erro ao ler a configuração: {exc}", file=sys.stderr)
        return 2
    policy = dict(config.get("policy", {}))
    if args.fail_on:
        policy["fail_on"] = args.fail_on
    exclude = args.exclude if args.exclude is not None else config.get("scan", {}).get("exclude", DEFAULT_EXCLUDE)

    only = None
    if args.changed_from:
        only = changed_files(root, args.changed_from)
        if only is None:
            print(f"Aviso: git diff contra {args.changed_from} falhou; analisando todos os arquivos.", file=sys.stderr)

    trigger = github_trigger()
    try:
        report = scan_project(root, project=args.project or os.environ.get("GITHUB_REPOSITORY") or None,
                              exclude=exclude, only=only, trigger=trigger, policy=policy)
    except ValueError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2

    print_console(report)
    if trigger["source"] == "github-actions" and not args.no_annotations:
        print_annotations(report, report["gate"]["policy"]["fail_on"])
    markdown = reports.to_markdown(report)
    write(args.json_out, json.dumps(report, ensure_ascii=False, indent=2))
    write(args.sarif_out, json.dumps(reports.to_sarif(report), ensure_ascii=False, indent=2))
    write(args.markdown_out, markdown)
    write(args.csv_out, reports.to_csv(report))
    if args.html_out:
        write(args.html_out, reports.to_html(report))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(markdown)
    if args.ingest_url:
        ingest(report, args.ingest_url)
    return 1 if report["gate"]["decision"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main())
