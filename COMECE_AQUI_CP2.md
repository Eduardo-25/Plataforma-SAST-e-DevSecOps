# CP2 pronta para executar: guia do Matheus

Este pacote contém a CP1 do grupo + os acréscimos da CP2. O notebook da Ford foi usado como referência de explicação direta e sequencial; esta atividade pede módulos na plataforma, não treinamento de autoencoder ou entrega isolada no Colab.

## 1. Abrir o projeto

1. Baixe o ZIP e clique com o botão direito → **Extrair tudo**.
2. Abra a pasta `Plataforma-SAST-e-DevSecOps-CP2` que foi extraída. Você deve enxergar `compose.yaml`, `README.md` e as pastas `app`, `docs`, `samples`, `scripts`, `tests`.
3. Abra o **Docker Desktop** e espere o mecanismo iniciar. Se já usaram Docker na CP1, aproveite a instalação existente. Caso não tenha, use o download oficial para Windows: https://docs.docker.com/desktop/setup/install/windows-install/ . Instale com WSL 2 e reinicie se o instalador pedir.
4. Dentro da pasta, clique na barra de endereço do Explorador, digite `powershell` e pressione Enter. Isso abre o terminal na pasta certa. Não precisa de Python instalado no Windows para o caminho Docker.

O primeiro início baixa imagens e o modelo. Pode levar vários minutos, dependendo da internet e do computador; inferência em CPU também pode levar minutos. Se houver pouca memória ou pouco espaço em disco, use uma máquina do grupo com mais recursos. Não há promessa de tempo fixo.

## 2. Iniciar API + Ollama

Cole UM comando por vez no PowerShell, esperando terminar:

```powershell
docker compose up --build -d
```

```powershell
docker compose exec ollama ollama pull llama3.2:3b
```

```powershell
docker compose ps
```

O segundo comando baixa o modelo uma vez. O volume `ollama-data` conserva o download entre reinícios. A configuração padrão usa CPU e não exige configurar sua placa de vídeo. Não precisa instalar Ollama separadamente no Windows.

Abra no navegador: **http://localhost:8000/docs**.

## 3. Confirmar que a IA está disponível

No Swagger:

1. Clique em **GET /llm/health**.
2. Clique em **Try it out** → **Execute**.
3. Em **Response body**, procure `"status": "ready"` e `"model": "llama3.2:3b"`.

Se não aparecer `ready`, consulte a seção de erros abaixo. Não basta `/health` responder `ok`: isso só confirma a API.

## 4. Demonstrar a CP2 na tela

Clique em **POST /scan/semantic** → **Try it out**. Apague o exemplo inteiro e cole:

```json
{
  "filename": "demo_sql.py",
  "source_code": "nome = input('Nome: ')\nconsulta = \"SELECT id FROM usuarios WHERE nome = '\" + nome + \"'\"\ncursor.execute(consulta)\n",
  "use_llm": true
}
```

Clique em **Execute** e espere. O código enviado é analisado, não executado; por isso não precisa abrir banco nem definir `cursor` para a varredura.

Na resposta, mostre:

- `summary.taint_findings`: **1** neste exemplo.
- `sources`: origem na linha 1 (`input`).
- `propagation`: passagem pelas variáveis `nome` e `consulta`.
- `sink`: `cursor.execute`, linha 3.
- `llm.status`: precisa ser **completed** para comprovar revisão real.
- `ai_review`: severidade, avaliação e justificativa do modelo.
- `remediation`: bloco de correção e sua origem. Se o modelo fornecer Python válido, a origem será `local_llm`.

Depois troque o JSON por este controle parametrizado e clique em Execute:

```json
{
  "filename": "demo_sql_parametrizado.py",
  "source_code": "nome = input('Nome: ')\ncursor.execute('SELECT id FROM usuarios WHERE nome = ?', (nome,))\n",
  "use_llm": true
}
```

Esperado neste exemplo: **zero achados**, `llm.status: not_needed`. A consulta é fixa e a entrada vai separada como parâmetro. Isso não significa que qualquer programa sem achados seja seguro.

Terceiro exemplo, para triagem de falso positivo:

```json
{
  "filename": "demo_constante.py",
  "source_code": "resultado = eval('2 + 2')\n",
  "use_llm": true
}
```

A regra original detecta `eval`, mas não existe entrada externa rastreada. Mostre a justificativa real do LLM: ele pode indicar `likely_false_positive` ou manter cautela. **Não prometa um veredito específico e não edite a saída para aparentar sucesso.** A expressão constante continua sendo um padrão desnecessário e pode virar `resultado = 2 + 2`.

O exemplo do Swagger é curto para ajudar a inferência. Os exemplos de arquivo em `samples/` têm o mesmo propósito.

## 5. Salvar evidências automaticamente

No mesmo PowerShell:

```powershell
docker compose exec sast-api python scripts/demo_cp2.py --llm
```

A pasta `reports` será criada no seu computador, com três JSONs reais. Os cenários vulnerável e constante devem mostrar `completed`; o parametrizado deve mostrar `not_needed`. Se houver erro, o script avisa e sai com falha. Esses relatórios ainda NÃO vêm preenchidos com inferência neste pacote.

Para testar apenas os motores sem esperar pela IA:

```powershell
docker compose exec sast-api python scripts/demo_cp2.py
```

Esses JSONs têm sufixo `_static` e não comprovam o uso do LLM.

Execute os testes:

```powershell
docker compose exec sast-api python -m pytest -q -p no:cacheprovider
```

Os testes de integração do LLM usam mocks. A comprovação com modelo real é a demo `--llm`, não o número de testes aprovados.

## 6. Colocar no GitHub do grupo

Você vai acrescentar a CP2 à mesma plataforma. Não envie só o ZIP para o repositório: os arquivos precisam ficar nas pastas certas.

**Caminho pelo navegador, sem comandos Git:**

1. Abra https://github.com/Eduardo-25/Plataforma-SAST-e-DevSecOps e entre na sua conta.
2. No seletor de branch acima da lista de arquivos (normalmente `main`), digite **cp2-ia-analise-semantica** e clique para criar a branch a partir da principal. Se não houver opção, você precisa ser colaborador; peça ao Eduardo para fazer o upload ou adicionar seu acesso.
3. Na nova branch, clique **Add file → Upload files**.
4. No Explorador, entre na pasta extraída. Arraste para o GitHub as pastas **app, docs, samples, scripts e tests** e os arquivos **compose.yaml, requirements.txt, README.md e COMECE_AQUI_CP2.md**. Inclua `.env.example` e `.gitignore` se estiverem visíveis. Não arraste a pasta externa inteira, para não criar um projeto dentro de outro.
5. Confira os caminhos na prévia: por exemplo `app/taint.py`, `app/llm.py`, `app/semantic.py` e `app/main.py`. Não pode ficar `Plataforma-SAST-e-DevSecOps-CP2/app/...`.
6. Escreva a mensagem **Adiciona CP2: taint analysis, Ollama local e remediações** e clique **Commit changes**.
7. Abra **Compare & pull request**, explique a CP2 e crie o pull request. Peça ao grupo para revisar/mesclar depois da demo funcionar. Se a interface não oferecer upload sobre arquivos existentes, use o caminho pelo VS Code/Git abaixo.

Os arquivos da CP1 incluídos no pacote são iguais à base baixada, exceto os arquivos compartilhados listados em `docs/ALTERACOES_CP2.md`. Se alguém alterou o repositório depois da base `710c9cd`, compare as mudanças antes de substituir os arquivos compartilhados.

**Se você já tem o repositório clonado no VS Code:**

1. No terminal da cópia do repositório, rode `git status`; se houver trabalho local de outra pessoa, não sobreponha.
2. Com a branch principal limpa e atualizada (`git pull`), crie `git switch -c cp2-ia-analise-semantica`.
3. Copie os arquivos/pastas do pacote para a raiz desse clone, preservando a pasta `.git` existente.
4. Confira `git diff` e `git status`, faça os testes e a demo. Registre apenas os arquivos da CP2 com `git add app docs samples scripts tests compose.yaml requirements.txt README.md COMECE_AQUI_CP2.md .env.example .gitignore`.
5. Rode `git commit -m "Adiciona CP2 com taint analysis e Ollama"` e `git push -u origin cp2-ia-analise-semantica`.
6. Abra o pull request pelo GitHub.

A pasta `reports` fica ignorada por padrão. Se o professor pedir evidências, envie os JSONs ou uma gravação junto à entrega após revisar o conteúdo. Não publique código privado ou credenciais reais.

## 7. O que falar na apresentação

1. “A CP1 identifica padrões na AST. Na CP2 acrescentamos fluxo de dados: origem, propagação e função sensível.”
2. “No exemplo vulnerável, o nome entra por input, é concatenado à consulta e alcança execute.”
3. “Com SQL parametrizado, a entrada não modifica o texto da consulta; este fluxo não é sinalizado.”
4. “Ollama executa um LLM local que revisa o contexto, propõe severidade e sugere correções. Não treinamos uma rede do zero.”
5. “A IA auxilia na triagem de falsos positivos, mas não apaga os achados. As correções exigem revisão humana.”
6. “A análise é intraprocedural e aproximada, limitada a Python. Não medimos desempenho em código de produção.”

Leia `docs/CP2.md` para entender as decisões. Isso ajuda a responder às perguntas do professor sem decorar nomes.

## Erros comuns

| Sintoma | Ação |
|---|---|
| `docker` não reconhecido | Instale/abra Docker Desktop; feche e reabra o terminal |
| “Cannot connect to Docker daemon” ou erro de pipe | Espere o Docker Desktop iniciar; confira avisos de WSL/virtualização |
| Porta 8000 em uso | Pare o projeto antigo no Docker Desktop ou use `127.0.0.1:8001:8000` no compose e abra localhost:8001 |
| `model_missing` | Rode o comando de download do modelo e confira `/llm/health` |
| `unavailable` | Rode `docker compose ps` e `docker compose logs --tail=50 ollama` |
| `timeout` | Crie `.env` a partir de `.env.example`, ajuste `OLLAMA_TIMEOUT=600` e rode `docker compose up -d`; teste o exemplo curto do Swagger |
| `invalid_response` | Tente uma função menor; confira logs. O modelo respondeu fora do contrato. Isso não é demonstração concluída |
| Sugestão com `rule_template` | É exemplo fixo: confira `llm.status` e `ai_review`; não apresente como correção gerada pela IA |
| `limit_exceeded` | Divida em trechos com até 12.000 caracteres e oito achados |
| JSON inválido no Swagger | Apague o exemplo inteiro e copie o JSON completo deste guia, incluindo `\n` |

**Modelo específico Llama 3 8B:** copie `.env.example` como `.env`, mude `OLLAMA_MODEL=llama3:8b`, rode `docker compose exec ollama ollama pull llama3:8b` e `docker compose up -d`. Exige mais recursos que o modelo padrão. Confirme o nome em `/llm/health`.

Para parar, sem apagar o modelo baixado:

```powershell
docker compose down
```

## O que já foi verificado e o que falta

O pacote foi testado em Python 3.12: testes automatizados, chamadas HTTP reais à API local, demo estática e fallback real com Ollama ausente. Este ambiente de preparação não tinha Docker/Ollama; portanto, build dos containers e inferência Llama real ficam pendentes de execução na máquina do grupo. O código de integração está implementado; a evidência final depende de `ready` + `completed`.
