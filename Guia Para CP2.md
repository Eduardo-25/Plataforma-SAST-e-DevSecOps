# Guia para CP2

## 1. Iniciar API + Ollama

Cole um comando por vez no Terminal:

```bash
docker compose up --build -d
```

```bash
docker compose exec ollama ollama pull llama3.2:3b
```

```bash
docker compose ps
```

O segundo comando baixa o modelo uma vez. O volume `ollama-data` conserva o download entre reinícios. A configuração padrão usa CPU e não exige configurar sua placa de vídeo. Não precisa instalar Ollama separadamente no Windows.

Abra no navegador: **http://localhost:8000/docs**.

## 2. Confirmar que a IA está disponível

No Swagger:

1. Clique em **GET /llm/health**.
2. Clique em **Try it out** → **Execute**.
3. Em **Response body**, procure `"status": "ready"` e `"model": "llama3.2:3b"`.

Se não aparecer `ready`, consulte a seção de erros abaixo. Não basta `/health` responder `ok`: isso só confirma a API.

## 3. Demonstrar a CP2 na tela

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

## 4. Salvar evidências automaticamente

No mesmo Terminal:

```bash
docker compose exec sast-api python scripts/demo_cp2.py --llm
```

A pasta `reports` será criada no seu computador, com três JSONs reais. Os cenários vulnerável e constante devem mostrar `completed`; o parametrizado deve mostrar `not_needed`. Se houver erro, o script avisa e sai com falha. Esses relatórios ainda NÃO vêm preenchidos com inferência neste pacote.

Para testar apenas os motores sem esperar pela IA:

```bash
docker compose exec sast-api python scripts/demo_cp2.py
```

Esses JSONs têm sufixo `_static` e não comprovam o uso do LLM.

Execute os testes:

```bash
docker compose exec sast-api python -m pytest -q -p no:cacheprovider
```

Os testes de integração do LLM usam mocks. A comprovação com modelo real é a demo `--llm`, não o número de testes aprovados.

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