
# Plataforma SAST e DevSecOps

Projeto da disciplina de **Cybersecurity da FIAP**, desenvolvido ao longo das CP1, CP2 e CP3.

A ideia é analisar código Python **sem executar o arquivo**, identificar possíveis falhas de segurança e mostrar os resultados de um jeito mais fácil de acompanhar. Além da análise pela API, o projeto conta com uma página inicial, um dashboard e um Security Gate para verificar alterações no GitHub.

![Prévia da página inicial da plataforma](docs/home-preview.png)

## Como rodar o projeto

Você só precisa ter o **Docker Desktop** instalado e aberto.

No terminal, dentro da pasta do projeto:

```bash
docker compose up --build -d
```

Depois, abra no navegador:

| Página | Link | Para que serve |
| --- | --- | --- |
| Página inicial | http://localhost:8000/ | Acesso às funcionalidades e teste rápido do scanner |
| Dashboard | http://localhost:8000/dashboard | Histórico das análises, filtros e relatórios |
| Swagger | http://localhost:8000/docs | Visualizar e testar os endpoints da API |

Na primeira vez, o Docker pode levar um pouco mais de tempo para baixar e preparar as imagens.

Para parar os containers:

```bash
docker compose down
```

## O que foi feito em cada CP

### CP1 — Análise estática

Criamos a API com **FastAPI** e o scanner usando a biblioteca **AST do Python**. Ele lê a estrutura do código e procura alguns padrões de risco, sem precisar executar o que foi enviado.

As regras iniciais são:

| Regra | O que procura | CWE |
| --- | --- | --- |
| `SAST001` | Senhas, tokens e outros possíveis segredos escritos diretamente no código | CWE-798 |
| `SAST002` | Uso de `eval()` ou `exec()` | CWE-95 |
| `SAST003` | Execução de comandos com `shell=True` | CWE-78 |

### CP2 — Análise semântica e IA local

Na segunda etapa, adicionamos **Taint Analysis** para acompanhar o caminho de dados potencialmente inseguros até operações sensíveis, como comandos e consultas SQL.

Também incluímos a possibilidade de pedir uma revisão ao **Ollama**, rodando um modelo de linguagem localmente. Essa parte é opcional: a análise estática continua funcionando mesmo sem usar IA.

Para baixar o modelo padrão no container:

```bash
docker compose exec ollama ollama pull llama3.2:3b
```

Depois, no scanner da página inicial ou no endpoint `POST /scan/semantic`, é só habilitar a revisão por IA. Como o modelo roda localmente, a resposta pode demorar dependendo do computador.

### CP3 — Dashboard e Security Gate

Na terceira etapa, fizemos a parte de acompanhamento e integração com o desenvolvimento:

- **Dashboard** para consultar análises, arquivos afetados, linhas e severidades.
- **Relatórios** em JSON, CSV, Markdown, SARIF e HTML.
- **Security Gate** para reprovar verificações quando uma alteração ultrapassar o limite de severidade configurado.
- **GitHub Actions** com testes, análise de segurança e build da imagem Docker.

O gate usa as regras estáticas e a análise de fluxo de dados. Ele **não depende do Ollama** para decidir se uma alteração passa ou não.

O workflow está no arquivo [`.github/workflows/security-gate.yml`](.github/workflows/security-gate.yml). Para o GitHub realmente impedir o merge de um PR reprovado, é necessário configurar os checks obrigatórios na proteção da branch `main`.

## Testando uma análise

O jeito mais simples é abrir a **[página inicial](http://localhost:8000/)**, colar um código Python no scanner e clicar em **Executar análise**.

Também dá para testar pelo [Swagger](http://localhost:8000/docs), usando `POST /scan` com este exemplo:

```json
{
  "filename": "teste.py",
  "source_code": "senha = 'admin123'\nentrada = input('Valor: ')\nresultado = eval(entrada)\n"
}
```

Nesse exemplo, o scanner deve encontrar a senha escrita diretamente no código e o uso de `eval()`.

Para testar o Security Gate com os arquivos de exemplo vulneráveis:

```bash
docker compose exec sast-api python -m app.gate --path samples
```

Esse comando **deve terminar com código de saída 1**: o bloqueio é intencional, justamente para mostrar o gate funcionando.

## Endpoints principais

| Método | Endpoint | Função |
| --- | --- | --- |
| `GET` | `/health` | Verifica a API |
| `POST` | `/scan` | Análise inicial da CP1 |
| `GET` | `/llm/health` | Verifica o serviço/modelo local |
| `POST` | `/scan/semantic` | Análise semântica e revisão opcional por IA |
| `POST` | `/scan/project` | Analisa vários arquivos de um projeto |
| `POST` | `/api/scans/ingest` | Recebe relatórios do CI |
| `GET` | `/api/dashboard` | Retorna os dados do dashboard |
| `GET` | `/api/scans` | Lista análises salvas |
| `GET` | `/dashboard` | Abre o dashboard |
| `GET` | `/reports/{scan_id}.{fmt}` | Baixa um relatório salvo |

A página inicial mostra as rotas automaticamente. Para ver os campos de cada requisição e testar os `POST`, use o Swagger em `/docs`.

## Testes

Para rodar os testes automatizados:

```bash
docker compose exec sast-api python -m pytest -q -p no:cacheprovider
```

## Onde estão as coisas

- `app/` — API, scanner, análise semântica, gate e relatórios.
- `app/static/` — página inicial e dashboard.
- `samples/` — códigos de exemplo para testar.
- `tests/` — testes automatizados.
- `sast-gate.toml` — configurações do Security Gate.
- `docs/` — documentação mais detalhada das entregas.

Para entender melhor cada etapa, deixamos a documentação separada: [CP2](docs/CP2.md), [CP3](docs/CP3.md) e [arquitetura C4](docs/arquitetura-c4.md).

## Limitações

Esse é um **projeto acadêmico**, não um scanner de segurança completo. Atualmente ele analisa código Python e trabalha com um conjunto limitado de regras. Pode deixar passar problemas ou apontar algo que não seja uma vulnerabilidade real. Por isso, os resultados precisam ser revisados.

A aplicação também foi preparada para **uso local**, sem sistema de login. Não é recomendado expor a API diretamente na internet.

## Integrantes

- Eduardo da Silva Lima — RM 554804
- Enzo Bonacasatta — RM 555372
- Guilherme Ulacco — RM 558418
- Matheus Hostim — RM 556517
- Estevam Melo — RM 555124
