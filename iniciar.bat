@echo off
chcp 65001 >nul
title Sentinela - Vulnerability Collector
cd /d "%~dp0"

echo.
echo  ============================================================
echo    SENTINELA  -  Vulnerability Collector
echo  ============================================================
echo.

REM Verifica se o Node esta instalado
where node >nul 2>nul
if errorlevel 1 (
  echo  [ERRO] Node.js nao encontrado no PATH.
  echo         Instale o Node.js e tente novamente.
  echo.
  pause
  exit /b 1
)

REM Instala dependencias na primeira execucao
if not exist "node_modules" (
  echo  Primeira execucao: instalando dependencias...
  call npm install
  echo.
)

:pedir_url
set "URL="
set /p "URL=  Cole a URL do alvo e tecle ENTER:  "

if not defined URL (
  echo  Nenhuma URL informada. Tente de novo.
  echo.
  goto pedir_url
)

echo.
echo  Iniciando auditoria em: %URL%
echo  (o programa vai perguntar o MODO a seguir)
echo.

REM Roda o auditor. Como e um terminal real, ele pergunta o modo/escopo.
node src\auditor.mjs "%URL%"

echo.
echo  ============================================================
echo    Auditoria finalizada. Relatorios em:  reports\
echo  ============================================================
echo.
pause
