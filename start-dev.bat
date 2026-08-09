@echo off
REM ---------------------------------------------------------------------------
REM start-dev.bat - Bring up the whole thing: backend API + frontend dev server.
REM
REM Two windows open. Both keep running until you close them. Closing this one
REM does not stop them, which is why each gets its own titled window.
REM
REM Run this from the repository root by double-clicking it, or:
REM     .\start-dev.bat
REM ---------------------------------------------------------------------------
setlocal

set ROOT=%~dp0
set ENGINE=%ROOT%out\build\x64-release\Senior-Project\sp.exe

echo ==============================================================
echo  Senior-Project - development startup
echo ==============================================================
echo.

REM --- the engine has to exist, or uploads fail with nothing to show -------
if not exist "%ENGINE%" (
    echo [!] Engine not found:
    echo     %ENGINE%
    echo.
    echo     Build it first: open the folder in Visual Studio, pick the
    echo     x64-release configuration, and build. Or set SP_BINARY in
    echo     backend\.env to wherever your sp.exe actually is.
    echo.
    pause
    exit /b 1
)
echo [ok] engine   %ENGINE%

REM --- dependencies -------------------------------------------------------
if not exist "%ROOT%backend\node_modules" (
    echo [..] installing backend dependencies
    pushd "%ROOT%backend" && call npm install --no-audit --no-fund && popd
)
if not exist "%ROOT%frontend-react\node_modules" (
    echo [..] installing frontend dependencies ^(this one takes a few minutes^)
    pushd "%ROOT%frontend-react" && call npm install --no-audit --no-fund && popd
)

REM --- .env, created on first run so SP_BINARY is never wrong by default ---
if not exist "%ROOT%backend\.env" (
    echo [..] writing backend\.env
    >  "%ROOT%backend\.env" echo SP_BINARY=%ENGINE%
    >> "%ROOT%backend\.env" echo DATA_DIR=./data
    >> "%ROOT%backend\.env" echo PORT=3000
    >> "%ROOT%backend\.env" echo # N8N_WEBHOOK_URL=http://localhost:5678/webhook/lift
)
echo [ok] config   %ROOT%backend\.env
echo.

start "Senior-Project API"      cmd /k "cd /d %ROOT%backend && npm start"
REM Give the API a moment to bind, so the frontend's first request is not a
REM connection error the user has to interpret.
timeout /t 3 /nobreak >nul
start "Senior-Project frontend" cmd /k "cd /d %ROOT%frontend-react && npm run dev"

echo.
echo   API        http://localhost:3000/api/health
echo   Frontend   http://localhost:5173
echo.
echo   Open the frontend, drop an .exe on the upload page, and watch the
echo   stages tick through as the engine works.
echo.
echo   Decompiler and finding explanations will show "not-run" until the n8n
echo   webhook is configured. Everything else is live.
echo.
pause
