@echo off
chcp 65001 > nul
title Sentinela v2.1 — Security Auditor

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║              SENTINELA v2.1 — Security Auditor           ║
echo ╠══════════════════════════════════════════════════════════╣
echo ║                                                          ║
echo ║  Comandos disponíveis:                                   ║
echo ║                                                          ║
echo ║  1. Iniciar auditoria (navegação manual + ATIVO)         ║
echo ║  2. Iniciar auditoria (só login)                         ║
echo ║  3. Iniciar auditoria (crawl automático)                 ║
echo ║  4. Finalizar sessão atual                               ║
echo ║  5. Ver status da sessão                                 ║
echo ║  6. Listar todas as sessões                              ║
echo ║  7. Sair                                                 ║
echo ║                                                          ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

set /p CHOICE="Escolha uma opção [1-7]: "

if "%CHOICE%"=="1" goto START_ACTIVE
if "%CHOICE%"=="2" goto START_LOGIN
if "%CHOICE%"=="3" goto START_CRAWL
if "%CHOICE%"=="4" goto DONE
if "%CHOICE%"=="5" goto STATUS
if "%CHOICE%"=="6" goto SESSIONS
if "%CHOICE%"=="7" goto EXIT
goto EXIT

:START_ACTIVE
set /p URL="URL alvo (ex: https://10.4.0.20:8443/login): "
echo.
echo ✅ Abrindo Edge. Faça login e navegue pelas páginas.
echo    Para finalizar: rode iniciar.bat → opção 4
echo    Ou: http://localhost:3141 → botão Finalizar
echo.
node sentinela.mjs start %URL% --active
pause
goto EXIT

:START_LOGIN
set /p URL="URL alvo: "
echo.
node sentinela.mjs start %URL% --login-only --active
pause
goto EXIT

:START_CRAWL
set /p URL="URL alvo: "
echo.
node sentinela.mjs start %URL% --crawl --active
pause
goto EXIT

:DONE
echo.
node sentinela.mjs done
pause
goto EXIT

:STATUS
echo.
node sentinela.mjs status
pause
goto EXIT

:SESSIONS
echo.
node sentinela.mjs sessions
pause
goto EXIT

:EXIT
exit
