# Defesa técnica da CP3 — roteiro e perguntas prováveis

## Antes da apresentação (checklist, 15 min)

1. `docker compose up --build -d` e abrir http://localhost:8000/dashboard.
2. Rodar uma análise para o dashboard não abrir vazio: `docker compose exec sast-api python -m app.gate --path samples --project plataforma-sast --ingest-url http://localhost:8000` (retorna código 1 de propósito: é o bloqueio).
3. No GitHub: confirmar que os checks **Testes** e **Security gate** são obrigatórios na `main` (ver [CP3.md](CP3.md), "Ativar o bloqueio de merge") e que o workflow já rodou ao menos uma vez.
4. Preparar a branch da demonstração (`demo/login-inseguro`) com o arquivo abaixo, **sem** abrir o PR ainda.
5. Ensaiar uma vez com cronômetro. Tenha o PR já aberto e o resultado aberto em outra aba como plano B se a internet falhar; o HTML autônomo (`reports/dashboard.html`) funciona offline.

`src/login.py` (vulnerável de propósito):

```python
def buscar_usuario(cursor):
    nome = input("Nome: ")
    cursor.execute("SELECT id FROM usuarios WHERE nome = '" + nome + "'")
```

Versão corrigida (para o segundo commit):

```python
def buscar_usuario(cursor):
    nome = input("Nome: ")
    cursor.execute("SELECT id FROM usuarios WHERE nome = ?", (nome,))
```

## Roteiro (cerca de 8 minutos)

**1. Contexto (40 s).** CP1: regras AST. CP2: taint e IA local. CP3: levar isso para onde o risco entra, o Pull Request, e dar visibilidade à gestão.

**2. O gate bloqueando um PR (2 min).** Abrir o PR de `demo/login-inseguro` para `main`.
- Mostrar os checks: **Security gate** vermelho, **Testes** verde.
- Aba *Files changed*: a anotação inline na linha do `cursor.execute`.
- O comentário automático do PR: veredito, tabela com arquivo:linha, regra e CWE.
- Botão de merge desabilitado pela proteção de branch.
- Dizer: o gate analisou **só os arquivos do PR**; dívida antiga não trava o time.

**3. Corrigir e liberar (1 min).** Commit com a versão parametrizada. O mesmo comentário é atualizado (não duplica) e o check fica verde. Dizer: o motor reconhece a consulta fixa com parâmetro separado.

**4. Dashboard (2,5 min).** Abrir `/dashboard` (ou o `dashboard.html` do artefato).
- Faixa de veredito: bloqueado/aprovado e o motivo.
- Clicar numa fatia da barra de severidade: a tabela filtra. Clicar num arquivo: filtra por arquivo.
- Expandir uma linha crítica: **caminho dos dados** (origem → variáveis → destino) e a correção sugerida.
- Histórico: as colunas mostram a sequência bloqueada → aprovada.
- Exportar **SARIF** (integra ao Code Scanning) e **CSV** (planilha da gestão).

**5. Decisões de projeto (1,5 min).** Ver a seção seguinte.

**6. Limites (30 s).** Só Python, quatro classes de falha, análise intraprocedural; gate aprovado não prova segurança; dashboard sem autenticação, para uso local.

## Decisões que vale justificar

- **O gate não usa IA.** Veredito de PR precisa ser reprodutível e não pode depender de um modelo disponível; a IA fica na triagem (`/scan/semantic`).
- **Só arquivos alterados no PR.** Evita bloquear por dívida antiga; a `main` é varrida inteira a cada push.
- **Severidade efetiva.** Fluxos que dependem só de parâmetro assumido como externo descem um nível, pois geram mais falso positivo. A estática original fica visível.
- **Supressão com motivo, auditável.** `# sast-ignore` deixa rastro no relatório e no SARIF; não apaga o achado.
- **SQLite em vez de PostgreSQL/Redis.** Volume do protótipo não justifica serviços extras; troca localizada em `storage.py`.
- **HTML autônomo como artefato.** O CI não alcança o `localhost`; o dashboard completo viaja dentro do artefato do workflow.
- **Código de saída como contrato.** `0/1/2` funciona em qualquer CI (GitHub, GitLab, Jenkins), não só no GitHub Actions.

## Perguntas prováveis

**Como o gate difere de CodeQL, Bandit ou Semgrep?** Eles têm regras e linguagens muito mais amplas. Nosso objetivo é didático: construir o motor (AST + taint), a política, os relatórios e o painel. O SARIF permite conviver com eles no mesmo Code Scanning.

**E os falsos positivos?** Três mecanismos: severidade efetiva menor para fluxos por parâmetro, supressão auditável por linha e a revisão por IA da CP2 (sem ganho percentual medido; não afirme número).

**O que impede alguém de ignorar o gate?** A proteção de branch exige os checks. Sem ela o workflow apenas reprova o check. Quem tem permissão de administrador pode contornar, a menos que a regra se aplique também a administradores.

**Um PR de fork funciona?** O gate roda e bloqueia. SARIF e comentário são pulados porque o token de PRs de fork é somente leitura; o resultado fica no log, nas anotações e no resumo do job.

**O dashboard é seguro?** Dados exibidos são inseridos como texto (testamos um relatório com `<img onerror>` e `</script>`), há CSP restritiva e a ingestão valida tudo e recalcula o veredito no servidor. Mas não há login: é para `localhost`. Em produção, atrás de proxy autenticado.

**Por que um PR com achado `MEDIUM` passa?** Porque `fail_on = "HIGH"`. É política, ajustável em `sast-gate.toml` ou por `--fail-on`.

**O scanner executa o código analisado?** Não. Só `ast.parse`; há teste da CP2 que comprova isso.

**Limitações conhecidas?** Em [CP3.md](CP3.md) e [CP2.md](CP2.md): só Python; CWE-78/89/95/798; sem análise entre funções ou arquivos; sem SSRF/XSS/path traversal/dependências.

## O que ainda precisa ser confirmado pelo grupo

Estes itens **não foram executados no ambiente em que o pacote foi preparado** e devem ser verificados antes da defesa:

- Execução real do workflow no GitHub (a lógica do passo do gate foi simulada localmente com as variáveis `GITHUB_*`).
- Envio do SARIF ao Code Scanning (depende de o repositório ser público ou ter GitHub Advanced Security; o passo não derruba o pipeline se falhar).
- `docker compose up --build` e o volume `sast-data` com o usuário não-root.
- Inferência real do Llama (pendência herdada da CP2; veja [VALIDACAO_CP2.md](VALIDACAO_CP2.md)).
