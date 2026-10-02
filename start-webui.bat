@echo off
rem forjiang-crypto one-click launcher (Windows)
rem Double-click this file: checks Python, installs deps, starts the web UI and
rem opens the browser. Closing this window stops the server.
rem Custom port: set PORT env var first, e.g.  set PORT=9000 && start-webui.bat

chcp 65001 >nul
setlocal EnableExtensions
cd /d %~dp0

rem Windows 老机器上控制台代码页可能是 GBK：中文路径、中文日志会 UnicodeEncodeError
set PYTHONUTF8=1

if "%PORT%"=="" set PORT=8765
set URL=http://127.0.0.1:%PORT%/

rem ---- pick an interpreter that can already import cryptography ----
rem (project-local .venv first: it is ours and guaranteed to work)
set PY=
set READY=
if exist ".venv\Scripts\python.exe" (
  .venv\Scripts\python.exe -c "import cryptography" >nul 2>nul
  if not errorlevel 1 set READY=.venv\Scripts\python.exe
)
if "%READY%"=="" (
  where py >nul 2>nul
  if not errorlevel 1 (
    py -3 -c "import cryptography" >nul 2>nul
    if not errorlevel 1 set READY=py -3
  )
)
if "%READY%"=="" (
  where python >nul 2>nul
  if not errorlevel 1 (
    python -c "import cryptography" >nul 2>nul
    if not errorlevel 1 set READY=python
  )
)
if not "%READY%"=="" set PY=%READY%

rem ---- no ready interpreter: take any python and install into it ----
if "%PY%"=="" (
  where py >nul 2>nul && set PY=py -3
)
if "%PY%"=="" (
  where python >nul 2>nul && set PY=python
)
if "%PY%"=="" (
  echo.
  echo [ERROR] Python not found.
  echo Please install Python 3.8+ from https://www.python.org/downloads/
  echo ^(tick "Add Python to PATH" during setup^), then double-click again.
  echo.
  pause
  exit /b 1
)

rem ---- first run: install dependencies, with fallbacks for locked-down Pythons ----
%PY% -c "import cryptography" >nul 2>nul
if errorlevel 1 (
  echo First run: installing dependency cryptography ...
  call :install_deps
  %PY% -c "import cryptography" >nul 2>nul
  if errorlevel 1 (
    rem Nothing worked: build an isolated project-local .venv as the last resort.
    echo Direct installs failed - creating a project-local virtual environment .venv ...
    rmdir /s /q .venv >nul 2>nul
    %PY% -m venv .venv
    if errorlevel 1 goto :deps_failed
    .venv\Scripts\python.exe -m pip install -r requirements.txt
    if errorlevel 1 goto :deps_failed
    set PY=.venv\Scripts\python.exe
    .venv\Scripts\python.exe -c "import cryptography" >nul 2>nul
    if errorlevel 1 goto :deps_failed
    echo Virtual environment ready: %~dp0.venv
  )
)

echo.
echo ==================================================
echo   forjiang-crypto web UI is starting
echo   URL: %URL%
echo   Your browser opens automatically; if not, visit the URL above
echo   If the port is taken by another program, the server switches to the
echo   nearest free port automatically - follow the URL the browser opens.
echo   Close this window = stop the server
echo ==================================================
echo.

rem If one of our UI servers is already listening on this port (e.g. a previous
rem double-click whose window is still open), reuse it instead of fighting for it.
curl -s -m 2 %URL%api/config | findstr /C:"version" >nul
if not errorlevel 1 (
  echo An existing forjiang-crypto UI is already running at %URL%
  echo Opening it in your browser. Closing that window is what stops the server.
  start "" %URL%
  pause
  exit /b 0
)

set PYTHONPATH=%~dp0
rem -u: unbuffered output so the auto-port-switch notice and URL show up at once
%PY% -u -m webui --port %PORT% --open
if errorlevel 1 (
  echo.
  echo [HINT] Startup failed. Common cause: port %PORT% is taken by another program.
  echo Try another port:  set PORT=9000 ^&^& start-webui.bat
)

echo.
echo Server stopped.
pause
exit /b 0

rem ---------------------------------------------------------------------------
rem Dependency install: every step is verified by actually importing the module,
rem so a failed install can never be mistaken for a successful one.
rem ---------------------------------------------------------------------------
:install_deps
rem 1) uv-managed Python refuses pip (PEP 668 externally-managed); uv is the
rem    correct tool for that environment.
where uv >nul 2>nul
if errorlevel 1 goto :try_pip
echo Detected uv, installing with uv ...
uv pip install --system -r requirements.txt >nul 2>nul
%PY% -c "import cryptography" >nul 2>nul
if not errorlevel 1 goto :eof

:try_pip
rem 2) plain pip
%PY% -m pip install -r requirements.txt >nul 2>nul
%PY% -c "import cryptography" >nul 2>nul
if not errorlevel 1 goto :eof

rem 3) user site-packages (never writes to system directories)
%PY% -m pip install --user -r requirements.txt >nul 2>nul
%PY% -c "import cryptography" >nul 2>nul
if not errorlevel 1 goto :eof

rem 4) PEP 668 externally-managed: explicitly allow writing to system dirs
%PY% -m pip install --break-system-packages -r requirements.txt >nul 2>nul
%PY% -c "import cryptography" >nul 2>nul
if not errorlevel 1 goto :eof

goto :eof

:deps_failed
echo.
echo [ERROR] Dependency install failed. Please run one of these manually:
echo   uv pip install --system -r requirements.txt
echo   %PY% -m pip install --user -r requirements.txt
echo   %PY% -m pip install --break-system-packages -r requirements.txt
echo.
pause
exit /b 1
