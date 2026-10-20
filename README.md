# CP2 — IA e análise semântica

**Comece por [COMECE_AQUI_CP2.md](COMECE_AQUI_CP2.md):** instalação, cliques no Swagger, demonstração e envio ao GitHub.

A plataforma agora soma à CP1 um módulo de Taint Analysis, integração com Ollama local e sugestões de remediação. O endpoint `/scan` da CP1 permanece disponível; a CP2 usa `/scan/semantic`.

| Endpoint | Função |
|---|---|
| `GET /health` | Saúde da API |
| `POST /scan` | Regras originais da CP1 |
| `GET /llm/health` | Disponibilidade do Ollama/modelo |
| `POST /scan/semantic` | Regras + fluxo de dados + revisão opcional por LLM |

```bash
docker compose up --build -d
docker compose exec ollama ollama pull llama3.2:3b
```

Abra http://localhost:8000/docs. Na CP2, `use_llm` é falso por padrão; marque `true` para solicitar a IA real.

- [Documentação técnica e limites](docs/CP2.md)
- [Mudanças sobre a CP1](docs/ALTERACOES_CP2.md)
- [Validação realizada](docs/VALIDACAO_CP2.md)

A primeira execução baixa imagens/modelo; a geração em CPU pode demorar. `llm.status: completed` confirma resposta validada do modelo. Falhas ficam explícitas e preservam os resultados estáticos. Ainda não há evidência de inferência real incluída neste pacote.

---

## Documentação original da CP1

# Plataforma SAST & DevSecOps 

Protótipo didático de análise estática para **Python**, com FastAPI, AST e Docker Compose. O scanner não executa o código analisado.

## Integrantes

Eduardo da Silva Lima (RM: 554804)

Enzo Bonacasatta (RM: 555372)

Guilherme Ulacco (RM: 558418)

Matheus Hostim (RM: 556517)

Estevam Melo (RM: 555124)

## Requisitos

- Docker Desktop instalado e em execução (inclui Docker Compose).

## Estrutura

```text
Plataforma_SAST_e_DevSecOps/
├── app/
│   ├── __init__.py
│   ├── main.py
│   └── scanner.py
├── docs/
│   └── arquitetura-c4.md
├── samples/
│   ├── safe.py
│   └── vulnerable.py
├── tests/
│   └── test_scanner.py
├── .dockerignore
├── .gitignore
├── compose.yaml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Iniciar com Docker Compose

No terminal, dentro da pasta do projeto:

```bash
docker compose up --build -d
```

Verificar o estado do container:

```bash
docker compose ps
```

Verificar o endpoint de saúde:

```bash
curl http://localhost:8000/health
```

Abra `http://localhost:8000/docs` para testar a API pela interface Swagger.

## Executar uma análise

No Swagger, abra `POST /scan`, clique em **Try it out** e envie este JSON:

```json
{
  "filename": "vulnerable.py",
  "source_code": "import subprocess\npassword = \"admin123\"\nentrada = input(\"Digite: \")\nresultado = eval(entrada)\nsubprocess.run(\"echo \" + entrada, shell=True)\n"
}
```

A resposta deve conter três achados, um por regra: `SAST001`, `SAST002` e `SAST003`. O número da linha e as recomendações são incluídos no resultado. O valor do segredo não é incluído na mensagem do achado.

Para testar código com sintaxe inválida, envie, por exemplo, `if True print('erro')`. A API retorna HTTP 422 e informa que o código não pôde ser analisado.

## Executar os testes

```bash
docker compose run --rm sast-api pytest -q -p no:cacheprovider
```

Os testes cobrem as três regras, um cenário sem os padrões detectados, segredo em dicionário, erro de sintaxe e endpoints HTTP.

## Parar o ambiente

```bash
docker compose down
```

## Regras incluídas

| Regra | Padrão | Referência CWE | Severidade inicial |
|---|---|---|---|
| SAST001 | Literal de texto em variável/chave associada a senha, token ou segredo | CWE-798 | HIGH |
| SAST002 | Chamada a `eval()` ou `exec()` | CWE-95 | HIGH |
| SAST003 | Chamada de execução de processo com `shell=True` | CWE-78 | HIGH |

Esta é uma primeira versão educacional. Pode haver falsos positivos e falsos negativos; os resultados não substituem uma revisão de segurança completa.
