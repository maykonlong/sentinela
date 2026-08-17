# 🛡️ Sentinela v2.0 — Enterprise Vulnerability Collector & Security Auditor

> **Auditor de Segurança Web & Diagnóstico de Infraestrutura** guiado por navegador real (Microsoft Edge InPrivate). Combina auditoria de código/DOM/rede com varredura de infraestrutura TCP, socket timing, GeoIP, reputação IP e relatórios executivos para relatórios corporativos completos.

---

## 🎯 O que é o Sentinela?

O Sentinela é uma ferramenta de auditoria de segurança web que resolve o problema de ferramentas automáticas cegas (como ZAP/Burp em modo headless) que não conseguem passar de telas de login complexas (2FA, CAPTCHA, SSO, OAuth).

**Ele abre o Microsoft Edge em uma janela InPrivate/limpa.** Você faz o login e a navegação normalmente. Em segundo plano, o Sentinela monitora, audita e analisa absolutamente tudo:
- Toda a rede, requisições, headers, cookies, tokens e APIs
- Todo o armazenamento local (localStorage, sessionStorage)
- Código-fonte, scripts, variáveis globais e bibliotecas vulneráveis
- Controle de acesso, IDOR/BOLA, session fixation, mixed content
- **[NOVO v2.0]** Port scan TCP, socket timing breakdown, GeoIP, reputação IP em blacklists DNS
- **[NOVO v2.0]** Relatório empresarial HTML com selo A-F, sumário executivo, instruções de verificação manual por achado, screenshots, timeline e export PDF automático!

---

## 🚀 Novidades da v2.0

### 🏗️ Diagnóstico de Infraestrutura (absorvido do URL Checker)
- 🔌 **TCP Port Scan:** Varredura concorrente de 30 portas enterprise (Web, DB, Cache, SSH, RDP) com detecção de portas perigosas (MySQL, PostgreSQL, Redis, MongoDB expostos).
- ⚡ **Socket Timing Breakdown:** Medição física em milissegundos por fase: `DNS Lookup → TCP Connect → TLS Handshake → TTFB → Download`.
- 📊 **Load Percentiles:** P50, P75, P90, P95, P99 sob carga concorrente.
- 🌍 **GeoIP Lookup:** Localização geográfica do servidor (País, Cidade, ISP, ASN, Organização).
- 🚫 **DNSBL Reputation Check:** Verificação do IP em 6 blacklists DNS públicas (Spamhaus, SpamCop, CBL, SORBS, Barracuda).
- 📱 **Social Cards:** Análise de meta tags Open Graph (`og:`) e Twitter Cards.

### 📄 Relatório Empresarial Completo (Deliverable para Clientes)
- 🏢 **Capa Profissional:** Selo de classificação visual (A, B, C, D, F) com cores e nota 0-100.
- 📊 **Sumário Executivo:** Visão C-level (não-técnica) com top riscos e recomendação principal.
- 📈 **Score Breakdown por Categoria:** Pontuação detalhada em 7 categorias (Headers, Cookies, TLS, Storage, Código, Rede, Infraestrutura).
- 🧪 **Como Verificar Manualmente (em TODOS os achados):** Passos detalhados para reproduzir manualmente cada achado usando DevTools, cURL ou terminal.
- 📸 **Screenshots Automáticas:** Captura visual das páginas auditadas embutidas em base64 no relatório.
- 📜 **Timeline da Auditoria:** Rastreabilidade cronológica de todos os eventos da sessão.
- 🧪 **Testes de Verificação Gerados:**
  - Suite de teste em Playwright TypeScript (`.spec.ts`)
  - Coleção Postman v2.1 (JSON)
  - Snippets cURL, Python, JavaScript, Go
  - Snippets de correção de headers para Nginx e Apache
- 📄 **Export PDF Automático:** Gera arquivo `.pdf` formatado em A4 pronto para envio a clientes.

---

## 🛠️ Como Usar

### Instalação

```bash
git clone https://github.com/maykonlong/sentinela.git
cd sentinela
npm install
npx playwright install msedge
```

### Execução

```bash
# Modo interativo (pergunta escopo e modo ativo)
npm run audit -- https://seu-alvo.com

# Audit direto na página de login
node src/auditor.mjs https://seu-alvo.com --login-only --yes

# Auditoria completa com crawl de links internos
npm run audit:crawl -- https://seu-alvo.com

# Auditoria com testes ativos (IDOR, open redirect, .git/.env)
npm run audit:active -- https://seu-alvo.com
```

---

## 📂 Estrutura do Projeto

```
sentinela/
├── iniciar.bat                          # Launcher Windows de 1 clique
├── package.json
├── README.md
├── src/
│   ├── auditor.mjs                      # Orquestrador principal
│   ├── rules/                           # Regras de auditoria
│   │   ├── context-rules.mjs
│   │   ├── header-rules.mjs
│   │   ├── storage-rules.mjs
│   │   ├── code-rules.mjs
│   │   ├── library-rules.mjs
│   │   ├── network-rules.mjs
│   │   ├── recon-rules.mjs
│   │   ├── active-rules.mjs
│   │   └── owasp-map.mjs
│   ├── infra/                           # Diagnóstico de Infraestrutura (v2.0)
│   │   ├── tcp-scanner.mjs             # Port scan TCP (30 portas)
│   │   ├── socket-timing.mjs           # DNS→TCP→TLS→TTFB→Download
│   │   ├── load-percentiles.mjs        # P50/P75/P90/P95/P99
│   │   ├── geoip.mjs                   # País, ISP, ASN
│   │   ├── dnsbl-reputation.mjs        # Blacklists DNS
│   │   └── social-cards.mjs            # Open Graph / Twitter Cards
│   ├── generators/                      # Geradores de Código e Testes (v2.0)
│   │   ├── test-generator.mjs          # Playwright, Postman, cURL, Nginx fix
│   │   └── manual-verification.mjs     # Instruções "Como Verificar Manualmente"
│   └── report/                          # Sistema de Relatório Empresarial (v2.0)
│       ├── html-report.mjs             # HTML profissional com CSS Inter
│       ├── md-report.mjs               # Markdown formatado
│       ├── pdf-export.mjs              # Export PDF via Playwright
│       └── score-breakdown.mjs         # Score por categoria + notas A-F
└── reports/                             # Relatórios salvos (JSON, MD, HTML, PDF, HAR)
```

---

## 📊 Formatos de Entrega (relatórios salvos em `./reports`)

Ao final de cada auditoria, o Sentinela gera automaticamente **5 entregáveis**:

1. **`security-audit-*.html`** — Relatório interativo empresarial com gráficos, screenshots, verificação manual e snippets de correção.
2. **`security-audit-*.pdf`** — Documento PDF formatado em A4 para apresentação a clientes e C-level.
3. **`security-audit-*.md`** — Relatório Markdown completo para repositórios Git, Jira ou documentação técnica.
4. **`security-audit-*.json`** — Dados brutos estruturados para integração em pipelines CI/CD ou SIEM.
5. **`session-*.har`** — Registro completo do tráfego de rede importável diretamente no **Burp Suite** ou **OWASP ZAP**.

---

## 🔒 Licença & Aviso Legal

Este projeto é destinado exclusivamente a testes de segurança em sistemas próprios ou devidamente autorizados. O uso em alvos sem permissão expressa é ilegal.
