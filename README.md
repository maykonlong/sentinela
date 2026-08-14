<div align="center">

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
```

# 🛡️ Sentinela — Vulnerability Collector & Security Auditor

**Auditor de segurança web guiado, baseado em Node.js + Playwright.**
Você loga e navega; o Sentinela observa tudo, testa e entrega um relatório com evidências, OWASP/CWE e sugestões.

`node` `playwright` `security` `owasp` · CLI: **`vulcoll`**

</div>

---

## ✨ O que torna o Sentinela diferente

- **Guiado por humano** — abre um navegador **InPrivate/limpo**, você faz login (inclusive 2FA) e navega. Ele audita **cada página que você abrir**, sem precisar de credenciais no código.
- **Recon autônomo em paralelo** — enquanto você navega, ele já varre `robots.txt`, `sitemap.xml`, Swagger/OpenAPI, GraphQL, CORS, etc. — sozinho, sem interação.
- **Passivo + ativo controlado** — coleta passiva por padrão; testes ativos (IDOR, arquivos sensíveis, open redirect) só com `--active` e **autorização do alvo**.
- **1ª parte × 3ª parte** — separa o **seu** código/config dos bundles e cookies de terceiros (HubSpot, LinkedIn, Cloudflare…), que **não contam na nota**. Sem enxurrada de falso-positivo.
- **Evidência de verdade** — cada achado mostra o **valor capturado** (flags de cookie, header, versão de lib, trecho de código, status HTTP).
- **Relatório apresentável** — HTML + Markdown + JSON, com **OWASP Top 10 + CWE**, nível de confiança, mapa de rotas e **comparação com a execução anterior** (regressão).
- **Export HAR** — toda a rede da sessão sai em `.har`, pronto pra abrir no **Burp Suite / OWASP ZAP**.

---

## 🔍 O que ele detecta

### Recon autônomo (roda sozinho, em paralelo)
| Check | Descrição |
|---|---|
| `robots.txt` / `sitemap.xml` | Extrai caminhos "escondidos" e mapa da superfície |
| Swagger / OpenAPI / GraphQL | Documentação/introspection de API exposta |
| CORS refletido | Envia `Origin` arbitrário e vê se volta no `Access-Control-Allow-Origin` |
| Erro verboso | Provoca 404 e detecta stack trace / versão / erro de SQL |
| Downgrade HTTP | HTTPS servindo conteúdo também em HTTP sem redirect |
| Fingerprint | Headers e cookies (`JSESSIONID`→Java, `PHPSESSID`→PHP…) → stack/CVE |
| `.well-known` | `security.txt`, `openid-configuration` |

### Controle de acesso (anônimo × autenticado)
Reprova os caminhos do recon **sem login** e **com sua sessão** e compara:
- Caminho sensível `200` **sem login** → **Broken Access Control** (A01)
- Bloqueado anônimo mas aberto autenticado em área admin → **Privilege Escalation**

### Análise passiva
- **Headers de segurança**: CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy, COOP/COEP, CORS, `Cache-Control` em página autenticada
- **Cookies**: `httpOnly` / `secure` / `SameSite`, prefixos `__Host-`/`__Secure-`, cookies sensíveis sem proteção
- **Storage**: dados sensíveis em `localStorage`/`sessionStorage`, **JWT** (decodifica, checa `exp`)
- **Código-fonte**: segredos/API keys (AWS, Google, Stripe, GitHub…), `innerHTML`/`dangerouslySetInnerHTML`/`eval` (vetores XSS), roles no frontend, **source maps** expostos
- **Bibliotecas vulneráveis** (estilo retire.js): jQuery, Bootstrap, AngularJS (EOL), Lodash, Moment, Handlebars, jQuery UI, DOMPurify — com **CVE** e versão-alvo
- **TLS/Certificado**: protocolo fraco, expiração, auto-assinado
- **Rede**: credenciais/tokens na URL, senha/token em resposta de API, mixed content, SRI ausente
- **Fluxo de login**: credenciais por HTTPS, tokens na URL/redirect, **session fixation**
- **Navegador (via CDP)**: painel *Issues* do DevTools (SameSite, CSP, mixed content, deprecações) + erros de console

### Testes ativos (`--active` — exigem autorização)
- **IDOR / BOLA** — troca IDs numéricos em requisições autenticadas
- **Open redirect** — em parâmetros `redirect`, `url`, `next`…
- **Arquivos sensíveis** — `.git`, `.env`, `.svn`, `server-status`, `actuator`, `phpinfo`
- **Arquivos de backup** — `.bak`, `.old`, `~` sobre seus JS/CSS
- **Métodos HTTP** perigosos (`TRACE`, `PUT`, `DELETE`…)

Todos os achados são mapeados para **OWASP Top 10 (2021) + CWE**.

---

## 📋 Pré-requisitos

- **Node.js 18+** (testado no 24)
- **Microsoft Edge** instalado (o Sentinela abre o Edge em janela InPrivate)

---

## 💻 Instalação

```bash
git clone https://github.com/maykonlong/sentinela.git
cd sentinela
npm install
```

> O Sentinela usa o **Microsoft Edge do sistema** (canal `msedge`). Se o Playwright reclamar do navegador, rode `npx playwright install msedge`.

---

## 🚀 Uso

### Windows (mais simples)
Dê **dois cliques** em `iniciar.bat`. Ele pede só a **URL** e, por ser um terminal real, pergunta o **modo**.

### Linha de comando
```bash
node src/auditor.mjs https://seu-alvo.com
```
Sem flags, ele pergunta interativamente o **escopo** e se roda **testes ativos**.

Exemplos:
```bash
# Navegação livre + testes ativos (auditoria completa)
node src/auditor.mjs https://seu-alvo.com --scope=navigate --active

# Só a página de login (rápido, não precisa logar)
node src/auditor.mjs https://seu-alvo.com --login-only

# Crawl automático, sem perguntar nada
node src/auditor.mjs https://seu-alvo.com --crawl --yes
```

### Modos (escopo)
| Modo | O que faz |
|---|---|
| `login` | Audita só a tela de login (não precisa logar) |
| `single` | Login + a página principal (padrão) |
| `navigate` | **Navegação livre** — audita cada página que você abrir |
| `crawl` | Login + segue os links internos automaticamente |

No modo **navigate**, ele encerra quando: você aperta **ENTER**, OU fica **`--idle` segundos sem página nova** (padrão 180s), OU atinge o teto de segurança (3h).

### Flags
| Flag | Descrição |
|---|---|
| `--scope=login\|single\|navigate\|crawl` | Define o escopo |
| `--navigate` / `--login-only` / `--crawl` | Atalhos de escopo |
| `--active` | Liga os testes ativos (**só com autorização do alvo**) |
| `--timeout N` | Tempo máximo em segundos (padrão 300) |
| `--idle N` | Navegação: encerra após N s sem página nova (padrão 180) |
| `--no-har` | Não gravar o arquivo HAR |
| `--yes` / `-y` | Não perguntar nada, usar padrões/flags |

---

## 📄 Relatórios

Gerados em `reports/` a cada execução:

| Arquivo | Conteúdo |
|---|---|
| `security-audit-<data>.html` | Relatório visual (abra no navegador) |
| `security-audit-<data>.md` | Markdown |
| `security-audit-<data>.json` | Dados estruturados |
| `session-<data>.har` | Rede completa — importável no Burp/ZAP |

A **nota (0–100)** e a contagem consideram **apenas problemas de 1ª parte** (o seu código/config). Cada execução também **compara com a anterior** do mesmo alvo (novos / corrigidos / persistentes).

---

## 🗂️ Estrutura

```
sentinela/
├── iniciar.bat              # Atalho Windows: pede a URL e inicia
├── package.json
├── src/
│   ├── auditor.mjs          # Orquestrador principal (fases, navegador, relatório)
│   └── rules/
│       ├── context-rules.mjs   # Classificação 1ª/3ª parte + minificado
│       ├── header-rules.mjs    # Headers de segurança, CORS, TLS
│       ├── storage-rules.mjs   # Cookies, localStorage/sessionStorage, JWT
│       ├── code-rules.mjs      # Segredos, XSS, source maps, SRI
│       ├── library-rules.mjs   # Bibliotecas vulneráveis (CVE)
│       ├── network-rules.mjs   # Requisições/respostas de API
│       ├── recon-rules.mjs     # Recon autônomo + diff de acesso + IDOR/redirect/backup
│       ├── active-rules.mjs    # Métodos HTTP, arquivos sensíveis, IDOR
│       └── owasp-map.mjs       # Mapeamento OWASP Top 10 + CWE
└── reports/                 # Saída (JSON, MD, HTML, HAR)
```

---

## ⚠️ Aviso legal e ético

O Sentinela é uma ferramenta de **auditoria de segurança autorizada**. Use **somente** em sistemas que você **possui** ou tem **permissão explícita e por escrito** para testar. Os testes ativos (`--active`) enviam requisições ao alvo e podem gerar logs, alertas ou disparar mecanismos de proteção. **Testar sistemas de terceiros sem autorização é ilegal.** O autor não se responsabiliza pelo uso indevido.

---

## 🧭 Roadmap

- [ ] User enumeration, rate-limit no login e política de senha
- [ ] Export PDF
- [ ] Screenshots por página no relatório
- [ ] Service Workers / IndexedDB
- [ ] CSP "profundo" (object-src / base-uri / frame-ancestors)

---

## 📜 Licença

Disponibilizado para fins **educacionais** e de **auditoria autorizada**.
