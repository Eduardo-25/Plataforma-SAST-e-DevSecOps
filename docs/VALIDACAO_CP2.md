# Validação da CP2 — 19/10/2026

## Resultado observado

- `python -m pytest -q -p no:cacheprovider`: **55 testes aprovados**, um aviso de depreciação do adaptador TestClient/httpx (sem falha).
- Inclui os sete testes originais da CP1.
- `git diff --check`: sem erros de whitespace.
- API iniciada com Uvicorn em localhost; Swagger retornou HTTP 200.
- `python scripts/demo_cp2.py` executado contra a API HTTP real: um achado de taint no exemplo SQL vulnerável, zero no SQL parametrizado e um achado de padrão no exemplo constante de eval.
- Chamada HTTP com `use_llm=true` e Ollama ausente: `llm.status=unavailable`, mantendo o achado estático. Não houve simulação de sucesso nessa chamada.

## Limite da verificação

O ambiente de preparação tinha Python 3.12, mas não Docker/Ollama. **Não foram executados o build do Docker Compose nem inferência real de Llama.** Os testes de respostas bem-sucedidas do cliente Ollama usam mocks declarados em `tests/test_cp2.py`. Não existe aqui evidência de precisão do modelo nem redução medida de falsos positivos.

## Validação final na máquina do grupo

1. `docker compose up --build -d`
2. `docker compose exec ollama ollama pull llama3.2:3b`
3. Confirmar `ready` em `GET /llm/health`.
4. `docker compose exec sast-api python -m pytest -q -p no:cacheprovider`
5. `docker compose exec sast-api python scripts/demo_cp2.py --llm`
6. Conferir `completed` nos JSONs dos exemplos vulnerável e constante, e revisar as correções/justificativas efetivamente geradas.
7. Guardar os relatórios reais ou gravar o Swagger para demonstrar a CP2.

Se algum modelo não devolver uma correção válida, o relatório identifica o problema. A demonstração deve mostrar o resultado real, sem alterar manualmente o veredito.
