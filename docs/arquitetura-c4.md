# Diagrama de arquitetura — C4

Os diagramas usam Mermaid para que possam ser visualizados no GitHub e em editores compatíveis. O primeiro descreve o contexto (C4 nível 1) e o segundo os containers (C4 nível 2). Componentes marcados como futuros fazem parte da visão-alvo do projeto, mas ainda não estão implementados no CP1.

## C4 — Nível 1: Contexto do sistema

```mermaid
flowchart LR
    DEV["Pessoa: Desenvolvedor / equipe"]
    CI["Sistema externo: GitHub Actions\n(fase futura: CI/CD)"]
    SAST["Sistema: Plataforma SAST\n(escopo inicial: análise Python)"]
    DEV -->|"envia código para análise"| SAST
    SAST -->|"retorna achados, linhas e recomendações"| DEV
    CI -.->|"executará a análise em commits e PRs"| SAST
```

## C4 — Nível 2: Containers

```mermaid
flowchart TB
    DEV["Desenvolvedor / Swagger UI"]
    subgraph PLATFORM["Plataforma SAST"]
      API["Container: API REST\nFastAPI / Uvicorn"]
      ENGINE["Módulo: motor de análise\nPython ast + regras SAST001–003"]
      API -->|"source_code"| ENGINE
      ENGINE -->|"achados estruturados"| API
    end
    DEV -->|"HTTP JSON /scan"| API
    API -->|"JSON com resumo e achados"| DEV

    subgraph FUTURE["Containers/componentes planejados para próximos checkpoints"]
      QUEUE["Fila e worker assíncrono\nRedis + Celery"]
      DB[("Persistência de análises\nPostgreSQL")]
      AI["Serviço de análise semântica\nLLM local via Ollama"]
      DASH["Dashboard analítico"]
    end
    ENGINE -.->|"resultados a persistir"| DB
    API -.->|"trabalhos de análise"| QUEUE
    QUEUE -.->|"processamento"| AI
    DB -.-> DASH
```

## Responsabilidades no CP1

- **FastAPI:** recebe código por HTTP, valida a requisição e entrega um relatório JSON.
- **Motor AST:** faz parsing sintático e aplica as três regras determinísticas iniciais.
- **Docker Compose:** constrói e inicia o container da API para desenvolvimento e demonstração.
- **Testes:** verificam detecções positivas, caso sem os padrões, código com sintaxe inválida e endpoints da API.

PostgreSQL, Redis/Celery, Ollama, dashboard e pipeline CI/CD são componentes planejados; o diagrama não afirma que já estejam funcionais no CP1.

---

## CP3 — DevSecOps e entrega

A CP3 implementa a integração com GitHub Actions e o dashboard. Persistência é **SQLite** (não PostgreSQL) e a varredura é síncrona (sem Redis/Celery); veja `CP3.md` para a justificativa.

### C4 — Nível 1: Contexto

```mermaid
flowchart LR
    DEV["Pessoa: Desenvolvedor / equipe"]
    GER["Pessoa: Gestão / avaliador"]
    GH["Sistema externo: GitHub\n(Pull Requests, Actions, Code Scanning)"]
    SAST["Sistema: Plataforma SAST"]
    DEV -->|"abre PR"| GH
    GH -->|"executa o Security Gate"| SAST
    SAST -->|"veredito, anotações, SARIF"| GH
    GH -->|"bloqueia ou libera o merge"| DEV
    DEV -->|"envia arquivos .py"| SAST
    GER -->|"consulta o dashboard"| SAST
```

### C4 — Nível 2: Containers e módulos

```mermaid
flowchart TB
    subgraph CI["GitHub Actions"]
      WF["Workflow security-gate.yml\nTestes · Security gate · Build"]
      GATE["CLI: python -m app.gate\ncódigo de saída 0 / 1 / 2"]
      WF --> GATE
    end
    subgraph PLATFORM["Plataforma SAST (Docker Compose)"]
      API["API FastAPI\n/scan/project · /api/scans/ingest\n/api/dashboard · /reports"]
      DASHUI["Dashboard HTML\n/dashboard"]
      SCAN["project_scan.py\npolítica, severidade efetiva, supressões"]
      ENGINES["Motores: scanner.py (CP1)\ntaint.py (CP2)"]
      REP["reports.py\nJSON · CSV · MD · SARIF · HTML"]
      DB[("SQLite\nvolume sast-data")]
      OLLAMA["Ollama (CP2)\nrevisão semântica opcional"]
      API --> SCAN --> ENGINES
      API --> REP
      API --> DB
      DASHUI --> API
      API -.-> OLLAMA
    end
    GATE --> SCAN
    GATE -->|"SARIF, comentário, artefatos"| GHUI["Pull Request / Code Scanning"]
    GATE -.->|"opcional: ingest"| API
```

### Fluxo do Security Gate

```mermaid
flowchart LR
    A["PR aberto/atualizado"] --> B["git diff: .py alterados"]
    B --> C["Motores AST + taint"]
    C --> D["Severidade efetiva\n- supressões sast-ignore"]
    D --> E{"Achado ativo >= fail_on?"}
    E -- sim --> F["exit 1: check vermelho\nmerge bloqueado"]
    E -- não --> G["exit 0: check verde"]
    F --> H["Anotações, comentário, SARIF, artefatos"]
    G --> H
```

