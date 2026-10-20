# Mudanças sobre a CP1

Base: `710c9cdcbe7840de356ad7222ed50b94f907f69f`, baixada do repositório do grupo em 19/10/2026.

## Arquivos adicionados

- `app/taint.py`: rastreamento estático intraprocedural.
- `app/llm.py`: cliente Ollama e validação de respostas.
- `app/semantic.py`: consolidação dos achados e remediações.
- `tests/test_cp2.py`: testes da CP2 e da integração com mocks.
- `samples/cp2_vulnerable.py`, `cp2_safe.py`, `cp2_review.py`: três cenários de demo.
- `scripts/demo_cp2.py`: demo HTTP com gravação de relatórios reais.
- `.env.example`: configuração do modelo e timeout.
- `COMECE_AQUI_CP2.md`: guia de execução e envio.
- `docs/CP2.md`, `ALTERACOES_CP2.md`, `VALIDACAO_CP2.md`: documentação.

## Arquivos compartilhados modificados

- `app/main.py`: acrescenta dois endpoints, sem remover `/scan` ou `/health`; título e versão atualizados.
- `compose.yaml`: acrescenta Ollama e volume persistente, configura conexão interna e restringe a publicação da API a localhost.
- `requirements.txt`: explicita dependência de Pydantic 2 para o contrato do LLM.
- `README.md`: acrescenta orientação CP2 antes da documentação original.
- `.gitignore`: ignora `.env` e relatórios locais.

## Preservado

Motor `app/scanner.py`, testes da CP1, amostras originais, Dockerfile e diagramas/documentação C4 da CP1. Os diagramas antigos retratam a CP1; a arquitetura adicionada na CP2 é descrita em `CP2.md` (API -> Ollama na rede Compose + volume de modelos).

Não foi implementado o escopo da CP3 nem publicado qualquer commit remoto durante a preparação deste pacote.
