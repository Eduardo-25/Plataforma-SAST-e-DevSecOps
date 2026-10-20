"""Executa varreduras HTTP e salva as respostas reais; não executa os samples."""
import argparse
import json
from pathlib import Path
import httpx

parser = argparse.ArgumentParser()
parser.add_argument("--llm", action="store_true", help="Solicita Ollama real; não usa mock")
parser.add_argument("--url", default="http://localhost:8000")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
output = root / "reports"
output.mkdir(exist_ok=True)
failed = False
for name in ("cp2_vulnerable", "cp2_safe", "cp2_review"):
    source = (root / "samples" / (name + ".py")).read_text(encoding="utf-8")
    try:
        response = httpx.post(args.url + "/scan/semantic", json={
            "filename": name + ".py", "source_code": source, "use_llm": args.llm,
        }, timeout=600, trust_env=False)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise SystemExit(f"Falha ao chamar a API. Verifique docker compose ps. Detalhe: {exc}")
    result = response.json()
    path = output / (name + ("_llm" if args.llm else "_static") + ".json")
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{name}: {result['summary']['total_findings']} achado(s); LLM={result['llm']['status']}; {path.name}")
    if args.llm and result["llm"]["status"] not in {"completed", "not_needed"}:
        failed = True
if failed:
    raise SystemExit("A demonstração de LLM NÃO foi concluída. Consulte /llm/health; os JSON registram a falha real.")
print("Demonstração concluída. Relatórios salvos em reports/.")
