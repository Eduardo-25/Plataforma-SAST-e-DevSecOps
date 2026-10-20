# CP2 — IA e análise semântica

A CP2 amplia a API Python da CP1. Não treina um autoencoder: usa um LLM já treinado para revisão contextual de achados estáticos. A escolha segue o slide 7 do projeto integrador do Prof. Oerton Fernandes.

## Correspondência com o enunciado

| Entrega pedida | Implementação | Como demonstrar |
|---|---|---|
| Módulo de Taint Analysis | `app/taint.py`: AST, origens, propagação e sinks | `samples/cp2_vulnerable.py`; observar `sources`, `propagation` e `sink` |
| Integração com LLM local | `app/llm.py` + serviço Ollama em `compose.yaml` | `/llm/health` com `ready` e `/scan/semantic` com `use_llm: true` e `llm.status: completed` |
| Sugestões de remediação | `app/semantic.py`: exemplos de regras e correções contextuais do LLM | Observar `remediation.origin`, explicação e bloco Python |
| Demo de varredura semântica | Swagger + `scripts/demo_cp2.py` | Comparar exemplo vulnerável, parametrizado e candidato a falso positivo |

CP3 (dashboard executivo e security gates de CI/CD) continua sendo a próxima etapa; não está implementada neste pacote.

## Fluxo da análise

1. O usuário envia nome e texto do arquivo por `POST /scan/semantic`.
2. O motor da CP1 aplica suas três regras, sem alterações em `app/scanner.py`.
3. O motor da CP2 rastreia dados na AST, sem executar o código.
4. Achados com a mesma linha/CWE são unidos, preservando os IDs das regras originais.
5. Se `use_llm` for verdadeiro, o contexto e os candidatos são enviados ao Ollama da rede interna do Compose.
6. Uma resposta JSON estruturada é validada com Pydantic. Respostas inválidas, incompletas, com IDs extras/duplicados ou com erro ficam explicitamente marcadas.
7. São retornados severidade estática, revisão da IA e remediação. Nenhuma sugestão é executada ou aplicada automaticamente.

O endpoint `/scan` conserva o contrato da CP1, e `/health` continua disponível. O título da API agora mostra CP1 + CP2.

## Rastreamento de dados

**Origens explícitas:** `input()`, `sys.argv` e acessos às entradas HTTP `request.args`, `request.form`, `request.values`, `request.json`, `request.get_json`, `request.query_params` e `request.path_params`.

**Parâmetros de funções:** considerados potencialmente externos, marcados `parameter_assumption` e confiança `MEDIUM`. A ferramenta não afirma que toda função seja um endpoint público.

**Propagação:** atribuições, cópias, concatenação, f-strings, operações, chamadas, formatação, `.strip()`/`.replace()`, atribuição aumentada e união de caminhos de `if`. Imports com aliases comuns são resolvidos. Reatribuir uma constante limpa a variável. Uma conversão numérica com `int`/`float` built-in não sombreado restringe o valor para os sinks de injeção modelados; não é um validador universal de regras de negócio.

**Sinks:** `eval`/`exec` (CWE-95), `os.system`/`os.popen` e subprocess com shell possivelmente ativo (CWE-78), primeiro argumento de `.execute`/`.executemany`/`.executescript` (CWE-89). Uma consulta fixa com parâmetros em argumento separado não contamina o texto SQL.

**Ramos e loops:** união conservadora, sem provar condições; loops usam até oito passagens de propagação. As linhas de `propagation` representam evidências da aproximação, não um caminho executável provado.

## Papel e limites da IA

O modelo padrão é `llama3.2:3b`, da família Llama 3, executado localmente pelo Ollama. Foi escolhido para reduzir o custo de execução acadêmica. Se o professor exigir especificamente Llama 3 8B, use `llama3:8b` conforme o guia; não confunda os dois modelos.

A IA classifica a severidade e propõe `likely_vulnerable`, `likely_false_positive` ou `needs_review`, com justificativa. Isso permite priorizar a revisão e identificar candidatos a falso positivo. **Não foi medido ganho de precisão nem redução percentual de falsos positivos em um corpus real.** A demonstração com expressão constante é um caso ilustrativo, não um benchmark.

A severidade estática nunca é sobrescrita e nenhum achado é apagado. Mesmo se a IA disser “falso positivo”, o desenvolvedor vê a evidência original. `ai_review.severity` guarda a opinião do modelo separadamente.

As correções vindas do modelo são submetidas a `ast.parse`. Se a sintaxe for inválida, o relatório mantém o exemplo de regra e marca o erro. Sintaxe válida não garante correção funcional ou segurança; o bloco deve ser revisado e adaptado. O modelo pode não conseguir sugerir um bloco, mantendo `corrected_code` vazio.

A entrada do LLM é limitada a 12.000 caracteres e oito achados por requisição. Acima disso, o motor estático continua funcionando, mas a IA retorna `limit_exceeded`, sem truncar silenciosamente o arquivo. A janela e a saída também são limitadas; entradas muito grandes podem exigir dividir o código em funções menores.

## Estados da IA

| `llm.status` | Significado |
|---|---|
| `not_requested` | `use_llm` é falso; só motores estáticos |
| `not_needed` | Nenhum candidato encontrado pelas regras; modelo não chamado |
| `completed` | Resposta real do Ollama recebida e validada |
| `unavailable` | Serviço inacessível ou com erro |
| `model_missing` | Modelo ausente/endpoint não encontrado; conferir health/logs |
| `timeout` | Inferência passou do prazo |
| `invalid_response` | Resposta incompleta ou incompatível com o esquema/IDs |
| `limit_exceeded` | Entrada ultrapassou o limite da revisão local |

Em falhas, `remediation.origin: rule_template` identifica honestamente um exemplo determinístico. Somente uma correção válida recebida do modelo recebe `origin: local_llm`.

## Limitações do analisador

- Apenas Python; sem resolução completa de tipos, dependências, imports entre arquivos, análise interprocedural ou grafo de chamadas.
- Chamadas desconhecidas propagam argumentos por aproximação; não há resumo real da função chamada.
- Parâmetros assumidos externos e `.execute` reconhecido pelo nome podem gerar falsos positivos.
- Aliases de objetos, mutações por métodos, closures, decorators, dispatch dinâmico, lambdas, compreensões e `match` não são modelados de forma completa.
- Não faz análise de viabilidade: condições, código morto, `return`/`break` e exceções podem produzir caminhos aproximados.
- Escopo, shadowing e aliases de imports são parciais; não é um compilador completo nem um substituto para Bandit/Semgrep/CodeQL.
- Não cobre SSRF, XSS, path traversal, autorização, vulnerabilidades de dependências nem todos os usos de SQL/shell.
- Ausência de achados não significa “código seguro”.
- Não há autenticação, rate limiting ou fila nesta entrega. A API é ligada ao localhost no Compose para uso didático local.
- O código-fonte completo é enviado ao Ollama local quando a IA é solicitada. Os relatórios podem conter código/segredos nas sugestões: revise antes de compartilhar. A instrução de ignorar comandos no código reduz risco de prompt injection, mas não o elimina.

## Testes e evidências

Execute `docker compose exec sast-api python -m pytest -q -p no:cacheprovider`.

Os testes cobrem regressão da CP1, fluxos positivos, controles negativos, união de ramos, parâmetros assumidos, aliases, falhas do Ollama, validação de JSON/IDs, sintaxe das correções e comprovação de que o scanner não executa o arquivo recebido.

Os testes do cliente LLM usam respostas simuladas (`monkeypatch`), identificadas no código. Isso testa o contrato da integração, **não a qualidade do Llama nem inferência real**. A evidência real será gerada por `scripts/demo_cp2.py --llm`, que retorna erro se a IA não concluir. Não renomeie relatórios estáticos como se fossem de IA.

## Referências

- Enunciado fornecido: Projeto Integrador Plataforma SAST & DevSecOps, slide 7 (CP2), slide 9 (CP3) e slide 10 (avaliação).
- Base da CP1: https://github.com/Eduardo-25/Plataforma-SAST-e-DevSecOps — commit `710c9cdcbe7840de356ad7222ed50b94f907f69f`.
- API Ollama /generate: https://docs.ollama.com/api/generate
- Modelo Llama 3.2 3B: https://ollama.com/library/llama3.2:3b
- AST Python: https://docs.python.org/3/library/ast.html
