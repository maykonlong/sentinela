# 🛡️ Sentinela — Vulnerability Collector & Security Auditor

**Sentinela** é uma ferramenta de auditoria de segurança web e coleta de vulnerabilidades baseada em **Node.js** e **Playwright**.

---

## 🚀 Funcionalidades

- **Varredura Dinâmica e Estática**: Análise de páginas web com suporte a rastreamento (*crawling*).
- **Detecção de Vulnerabilidades**:
  - Injeções (SQL, XSS, Command Injection)
  - Configurações incorretas de Cabeçalhos de Segurança (CSP, HSTS, X-Frame-Options, etc.)
  - Vazamentos de informações e armazenamento inseguro (localStorage / sessionStorage / cookies)
  - Problemas de CORS e autênticação
- **Geração de Relatórios**: Exportação automatizada de relatórios em HTML com métricas e exemplos de exploração.

---

## 📋 Pré-requisitos

- **Node.js** (versão 18 ou superior)
- **NPM**

---

## 💻 Instalação e Uso

### 1. Clonar o repositório
```bash
git clone https://github.com/maykonlong/sentinela.git
cd sentinela
```

### 2. Instalar dependências
```bash
npm install
npx playwright install chromium
```

### 3. Executar Auditoria

- **Via script interativo (Windows):**
  Dê um duplo clique no arquivo `iniciar.bat`.

- **Via linha de comando:**
  ```bash
  npm run audit https://exemplo.com
  ```

- **Modo Crawling:**
  ```bash
  npm run audit:crawl https://exemplo.com
  ```

---

## 📄 Licença

Este projeto é disponibilizado para fins educacionais e de auditoria autorizada.
