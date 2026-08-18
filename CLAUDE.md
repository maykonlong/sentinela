# Sentinela — guia operacional para IA

Leia este arquivo antes de explorar o código. Ele existe para você não precisar
reler `src/auditor.mjs` (2300+ linhas) nem redescobrir os mesmos bugs a cada sessão.
Detalhes de features/arquitetura: [README.md](README.md).

## O que é

CLI Node (ESM) de auditoria de segurança web (`sentinela.mjs`). Abre o **Microsoft
Edge de verdade** (visível, InPrivate) via Playwright, o humano loga manualmente,
e o auditor coleta achados (headers, cookies, storage, código, rede, TCP/infra,
LGPD, recon, IDOR, etc.) em 3 fases: pré-login → login → pós-login. Não é headless
— sempre precisa de um humano na janela do Edge para logar (a IA não deve e não
consegue digitar credenciais).

## Alvos autorizados

- `https://10.4.0.20:8443/` — sistema interno do próprio usuário. Testes ativos
  (`--active`) já autorizados.
- `https://bancopopular-corner-stg-col.cmsw.com` — staging Next.js + Keycloak/OIDC
  (login redireciona para `auth-stg-col.cmsw.com`). Testes ativos autorizados
  pelo usuário em 2026-08-18.

## Comandos (`node sentinela.mjs <cmd>`, cwd = raiz do projeto)

```
status [--json]              # sessão ativa. RODE SEMPRE ANTES de "start".
sessions [--json]            # lista todas as sessões
report [<id>] [--json]       # GERA relatório a partir do disco, SEM browser e SEM humano
start <url> [opções]         # nova sessão (abre o Edge, precisa de humano)
resume <session-id>          # reabre o browser numa sessão existente
done                         # sinaliza finalização (gera relatório)
cancel                       # marca sessão ativa como cancelada
```

### Para automação/IA — use isto

- **`--json`**: TODOS os comandos passam a imprimir **uma linha JSON** no stdout,
  sem cor e sem emoji. Não parseie a saída bonita; ela é para humano.
- **Exit codes**: `0` ok · `1` erro · `2` HIGH presente · `3` CRITICAL presente ·
  `4` nenhuma sessão. Dá para usar como gate direto, sem ler o relatório.
- **`report` é o caminho principal da IA**: gera do que já está em disco, em
  segundos, sem abrir browser. Se existe sessão com achados, prefira `report` a
  `resume`.
- **`--on-orphan=report|resume|discard|fail`** no `start`: decide o que fazer com
  sessão `IN_PROGRESS` órfã sem perguntar nada.

```bash
node sentinela.mjs report --json      # gera e devolve caminhos + score + counts
```

## Como LER o relatório sem queimar contexto

Cada auditoria gera 5 arquivos em `reports/`. Os tamanhos importam:

| arquivo | tamanho típico | quando usar |
|---|---|---|
| `*.summary.json` | **~23 KB** | **SEMPRE comece por aqui.** Score, categorias, counts e a lista de achados (tipo, severidade, subject, url, OWASP, nº de ocorrências). |
| `*.json` | ~300 KB | Só quando precisar do detalhe de um achado específico. |
| `*.html` | ~250 KB | Entregável para humano. Não leia. |
| `*.pdf` / `*.har` | MBs | Nunca leia. O HAR serve para importar no Burp/ZAP. |

**Nunca** faça `cat`/`Read` no `.json` completo nem no `.html` — são centenas de
KB. Para recortar campos do JSON grande, use `node -e` com `JSON.parse`.

## Princípio de qualidade (o mais importante deste projeto)

> **Ausência de evidência não é evidência de vulnerabilidade.**

Falha de rede, timeout, DNS bloqueado, resposta que não deu para ler → estado
**"não verificado"**, nunca um achado e nunca um "PASS". Vários falsos positivos
graves já vieram de violar isso. Ao mexer em regra de detecção, garanta que ela
distingue *não encontrei* de *não consegui testar*, e que só escala severidade
com **evidência positiva** (valor corroborado, assinatura de conteúdo, checksum).

## Armadilhas já resolvidas (não rediagnostique)

1. **Headers lidos de uma requisição refeita** — `collectPageData` fazia
   `fetch(url, {method:'HEAD'})` para "pegar os headers". Next.js não trata HEAD
   em rota de página e responde **404 pelado** → o auditor concluía que CSP,
   HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP e COEP
   estavam TODOS ausentes. 9 falsos positivos por página, 2 deles HIGH.
   Corrigido: os headers vêm de `documentHeaders`, preenchido em
   `page.on('response')` com a resposta de **documento 2xx** da navegação real.
   **Nunca refaça a requisição para auditar header.**
2. **Dedup só em um dos dois pipelines** — `findings.ndjson` guarda o fluxo bruto
   (um achado por resposta HTTP). O auditor ao vivo deduplicava; o
   `generateFromSession` do daemon não. A MESMA sessão dava 41 achados por um
   caminho e 351 pelo outro. Corrigido: `src/report/dedup.mjs` é fonte única,
   usada pelos dois. Cada achado carrega `occurrences[]` e `occurrenceCount`.
3. **Crash no finalize (`ERR_STREAM_PUSH_AFTER_EOF`)** — `process.stdin.push('\n')`
   sem guarda derrubava o processo antes de escrever o relatório.
4. **Prompt de crash recovery travava sem TTY** — o `readline` nunca resolvia em
   processo background e o comando pendurava para sempre. Hoje há guarda de
   `process.stdin.isTTY` + `--on-orphan`.
5. **Validação de URL no top-level do módulo** quebrava `resume` (o `process.argv`
   do `resume` não tem URL). Movida para dentro de `main()`.
6. **`fetch` sem timeout nos testes ativos** — sonda descartada por WAF pendurava
   a auditoria inteira. Hoje há `AbortController` de 8s.
7. **Comandos de verificação com URL errada** — geradores em
   `manual-verification.mjs` tinham `'https://10.4.0.20:8443'` hardcoded como
   fallback e ignoravam o `targetUrl`.

## Nota (score)

Redesenhada. Regras atuais:
- Só categorias **efetivamente avaliadas** entram no denominador (antes, 5
  categorias sem checagem entregavam 60 pontos de graça).
- Penalidade escala com `occurrenceCount`, com retorno decrescente.
- **Teto por severidade**: CRITICAL confirmado limita a nota a D, etc. O campo
  `score.gradeCap` no summary diz se o teto foi aplicado e por quê.
- `score.unmappedTypes` lista tipos sem categoria — deve estar vazio.
- `test/owasp-map-coverage.mjs` falha se alguma regra produzir um `type` sem
  OWASP/CWE mapeado. **Rode-o depois de mexer em regras.**

## Onde as coisas ficam

- `src/auditor.mjs` — orquestrador (fases, coleta, gera relatório no fim de
  `main()` e chama `process.exit(0)`).
- `src/daemon/` — `sentinela-daemon.mjs` (orquestração/timeout/finalize +
  `generateFromSession`), `session-store.mjs` (`sessions/<id>/*.ndjson`),
  `control-server.mjs` (HTTP `:3141`).
- `src/rules/` — regras de detecção. `context-rules.mjs` tem `classifyResource`
  e `sameRegistrableDomain` (use-os para 1ª vs 3ª parte).
- `src/infra/` — TCP, DNS, DNSBL, GeoIP, timing.
- `src/report/` — `dedup.mjs` (fonte única), `score-breakdown.mjs`, `labels.mjs`,
  geradores HTML/MD/PDF.
- `reports/` — entregáveis. **Nenhum código do projeto apaga esse diretório** —
  se esvaziar sozinho, é externo (OneDrive/antivírus).
- `sessions/` — estado bruto + `sessions/archived/`. Está no `.gitignore` porque
  contém achados reais dos alvos.

## Rodar em background (armadilha real)

**Não** escreva `node sentinela.mjs start ... &` *e também* marque
`run_in_background: true` — isso double-backgrounda e o processo pode morrer.
Passe o comando puro (sem `&`) como `command`, com `run_in_background: true`.

`status` tenta o daemon HTTP (`localhost:3141`) e cai para o disco se falhar —
nesse ambiente o fetch costuma falhar mesmo com o daemon vivo. Para confirmar:
```
Get-NetTCPConnection -LocalPort 3141 -ErrorAction SilentlyContinue
```

## Pegadinha de `resume`

Reusa `scope`/`activeMode`/`timeoutMs` da sessão **original** (`meta.json`). Se a
original tinha `--timeout` curto, o resume finaliza rápido. Para mais tempo,
prefira `cancel` + `start` novo com `--timeout` explícito.
