@echo off
REM ===================================================================
REM  Start-Huginn.cmd -- open the Huginn console.
REM
REM  This is what the desktop icon points at. It starts the loopback
REM  server (hidden, via pythonw so no black window lingers) and opens
REM  the console in the default browser at http://127.0.0.1:8790.
REM
REM  Starting a second time is harmless: the new server fails to bind
REM  the port it is already using, exits in silence, and the browser
REM  opens to the instance that is already running.
REM ===================================================================
setlocal
if "%HUGINN_HOME%"=="" set "HUGINN_HOME=%LOCALAPPDATA%\Huginn"
cd /d "%HUGINN_HOME%" 2>nul || (
  echo Huginn is not installed at %HUGINN_HOME%.
  echo Run Install-Huginn.bat first.
  pause
  exit /b 1
)

REM pythonw = Python with no console window. If it is not on PATH the
REM python.org installer was told not to add it; fall back to py -w.
where pythonw >nul 2>&1 && (
  start "" pythonw -m runtime.app
) || (
  start "" pyw -m runtime.app
)

REM Give the stdlib server its moment (it needs well under a second, but
REM a browser that opens before the socket is listening shows a refusal).
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:8790
endlocal
