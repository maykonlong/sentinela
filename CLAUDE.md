# Sentinela — guia operacional para IA

Leia este arquivo antes de explorar o código. Ele existe para você não precisar
reler `src/auditor.mjs` (2600+ linhas) nem redescobrir os mesmos bugs a cada sessão.
Detalhes de features/arquitetura completos: [README.md](README.md).

## O que é

CLI Node (ESM) de auditoria de segurança web (`sentinela.mjs`). Abre o **Microsoft
Edge de verdade** (visível, InPrivate) via Playwright, o humano loga manualmente,
e o auditor coleta achados (headers, cookies, storage, código, rede, TCP/infra,
LGPD, recon, IDOR, etc.) em 3 fases: pré-login → login → pós-login. Não é headless
— não dá pra rodar "no escuro"; sempre precisa de um humano na janela do Edge para
logar (a IA não deve e não consegue digitar credenciais).

## Alvo autorizado

`https://10.4.0.20:8443/` — sistema interno do próprio usuário, já auditado
repetidamente (ver `sessions/`). Testes ativos (`--active`: IDOR, arquivos
sensíveis, open redirect) já são autorizados nesse alvo.

## Comandos (via `node sentinela.mjs <cmd>`, cwd = raiz do projeto)

```
status              # sessão ativa (achados/rotas atuais). RODE SEMPRE ANTES de "start".
sessions            # lista todas as sessões (IN_PROGRESS/DONE/CANCELLED)
start <url> [--active] [--crawl] [--login-only] [--timeout MIN]   # nova sessão
resume <session-id> # reabre o browser numa sessão existente (reusa scope/timeout ORIGINAIS — ver bug abaixo)
done                # sinaliza finalização (gera relatório). Também: curl -X POST http://localhost:3141/finalize
cancel              # marca sessão ativa como cancelada
```

Fluxo típico de "refazer a auditoria/relatório":
1. `node sentinela.mjs status` — se houver sessão `IN_PROGRESS` sem processo vivo
   (confira porta 3141 e processos `node`/`msedge` — ver seção abaixo), ela está
   órfã/interrompida.
2. Pergunte ao usuário (AskUserQuestion) o que fazer: gerar relatório com os
   dados já salvos (rápido, sem reabrir browser), retomar (`resume`, reabre
   Edge, precisa do humano) ou descartar e começar do zero (`start`, arquiva a
   sessão antiga em `sessions/archived/` — não destrutivo).
3. Lance `start`/`resume` como **background task real** (`run_in_background: true`
   no Bash tool, SEM `&` dentro do comando — ver "Como rodar em background").
   O processo abre o Edge e fica esperando o humano logar/navegar.
4. Avise o usuário para logar/navegar no Edge que abriu. Quando ele confirmar
   que terminou, rode `node sentinela.mjs done` (ou espere o timeout).
5. O relatório sai em `reports/security-audit-<timestamp>.{html,md,json}` +
   `reports/session-<timestamp>.har`. Verifique com `ls -lt reports` (o nome tem
   o timestamp de quando o relatório foi gerado, não de quando a sessão começou).

## Como rodar em background (armadilha real)

**Não** escreva `node sentinela.mjs start ... &` dentro da string do Bash e
*também* marque `run_in_background: true` — isso double-backgrounda: o processo
node pode morrer quando o wrapper do shell é encerrado, antes de terminar.
Passe o comando `node sentinela.mjs ...` **puro** (sem `&` no fim) direto como
`command`, com `run_in_background: true` no tool call. Assim o próprio harness
rastreia o processo até ele sair de verdade.

`node sentinela.mjs status` e afins tentam primeiro `fetch` no daemon HTTP
(`localhost:3141`) e caem pro fallback em disco se falhar — nesse ambiente o
fetch pro daemon costuma falhar mesmo com o daemon vivo (não é sinal de que o
processo morreu). Para confirmar se o daemon/browser ainda estão de pé, cheque
processos (`Get-Process node,msedge` no PowerShell) e/ou a porta:
```
Get-NetTCPConnection -LocalPort 3141 -ErrorAction SilentlyContinue
```

## Bugs já corrigidos em `src/auditor.mjs` (não precisa rediagnosticar)

1. **Crash no finalize (`ERR_STREAM_PUSH_AFTER_EOF`)** — ao finalizar,
   `runAudit()` fazia `process.stdin.push('\n')` sem proteção pra simular ENTER.
   Em processo sem TTY (rodando em background) o stdin já estava em EOF, e isso
   derrubava o processo com exceção não tratada **antes** de fechar o browser e
   escrever o relatório. Corrigido com try/catch (linha ~200). Se voltar a
   acontecer um crash logo após "🔔 Sinal de finalização recebido", é esse
   padrão de novo — procure qualquer `process.stdin`/`process.exit` sem guard
   perto do fluxo de finalize.
2. **Validação de URL no top-level do módulo quebrava `resume`** — o script
   validava `targetUrl`/`pageOrigin` assim que o módulo era importado, usando
   `process.argv` no momento do `import`. Como `sentinela.mjs resume <id>` tem
   `process.argv = ['resume', '<id>']` (sem URL), isso derrubava o processo
   inteiro antes mesmo de `runAudit()` rodar. Corrigido: validação movida pra
   dentro de `main()`, depois de `parseConfiguration()` reprocessar o argv.

## Pegadinha de `resume` (não é bug, é comportamento)

`resume` reusa `scope`/`activeMode`/`timeoutMs` **da sessão original**
(`sessions/<id>/meta.json`). Se a sessão original foi um teste rápido com
`--timeout` curto (ex.: 1 min, comum em demos), o resume finaliza sozinho
rapidinho — o relatório final ainda sai completo (usa os achados acumulados em
`findings.ndjson`/`routes.ndjson` no disco), só não dá muito tempo de navegação
livre nesse resume específico. Se precisar de mais tempo, prefira `cancel` +
`start` novo com `--timeout` explícito em vez de `resume`.

## Onde as coisas ficam

- `src/auditor.mjs` — orquestrador principal (fases, coleta, gera o relatório
  no fim de `main()` e já chama `process.exit(0)` — por isso o passo 10 do
  daemon (`generateFromSession`) só roda se `runAudit()` lançar erro).
- `src/daemon/` — `sentinela-daemon.mjs` (orquestração/timeout/finalize),
  `session-store.mjs` (persistência em `sessions/<id>/*.ndjson`+`meta.json`),
  `control-server.mjs` (HTTP `:3141`).
- `src/rules/` — regras de detecção (headers, cookies, código, libs, recon,
  active, LGPD, API/cloud).
- `src/report/` — geradores HTML/MD/PDF + score breakdown.
- `reports/` — entregáveis finais. **Não há nenhum código no projeto que apague
  esse diretório** — se ele aparecer vazio inesperadamente, é algo externo
  (OneDrive sync, antivírus removendo por conter PoCs de segurança), não o app.
- `sessions/` — estado bruto por sessão + `sessions/archived/` (sessões
  descartadas, não deletadas).
