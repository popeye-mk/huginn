@echo off
REM ---------------------------------------------------------------------
REM  Huginn - Windows verification
REM
REM  Double-click this file, or run it from a Command Prompt.
REM  Nothing is installed. Nothing on this machine is modified.
REM
REM  The payload is extracted to %LOCALAPPDATA%\huginn-verify and a
REM  report is written to your Desktop. Delete that folder afterwards and
REM  no trace remains.
REM ---------------------------------------------------------------------
setlocal enabledelayedexpansion
cd /d "%~dp0"

set BUILD=unstamped
if exist "%~dp0BUILD.txt" set /p BUILD=<"%~dp0BUILD.txt"

echo.
echo   Huginn - Windows verification   [disc build %BUILD%]
echo   ====================================================================
echo.
echo   If that build number is not the one you expected, Windows has
echo   mounted a cached copy - eject the drive and mount the ISO again.
echo.

REM ---------------------------------------------------------------------
REM  Find a Python that actually runs.
REM
REM  `where python3` is NOT a valid test on Windows 11. The OS ships an
REM  App Execution Alias stub at
REM    %LOCALAPPDATA%\Microsoft\WindowsApps\python3.exe
REM  which exists on PATH, satisfies `where`, and then prints
REM    "Python was not found; run without arguments to install from the
REM     Microsoft Store"
REM  and exits. Trusting `where` reported "Using: python3" and then died
REM  on a machine with no Python at all - found on the first real run.
REM
REM  So each candidate is EXECUTED and has to prove itself by printing a
REM  token. The stub cannot. Presence is not capability, which is the
REM  same rule this whole platform is built on.
REM ---------------------------------------------------------------------
set PYEXE=
set PROBE="%TEMP%\anora_py_probe.txt"

call :tryPython py -3
if not "!PYEXE!"=="" goto :found
call :tryPython python
if not "!PYEXE!"=="" goto :found
call :tryPython python3
if not "!PYEXE!"=="" goto :found

echo   No working Python was found on this machine.
echo.
echo   Windows 11 may show a "python3" command that only offers to open
echo   the Microsoft Store. That is a placeholder, not an interpreter.
echo.
echo   Easiest fix, in an Administrator Command Prompt:
echo.
echo       winget install -e --id Python.Python.3.12
echo.
echo   Or download it from https://www.python.org/downloads/windows/
echo   and tick "Add python.exe to PATH" during setup.
echo.
echo   Then close this window, open a new one, and run VERIFY.cmd again.
echo.
echo   Nothing else is needed - these tests use only the Python standard
echo   library. No pip install, no internet.
echo.
pause
exit /b 1

:found
echo   Using: !PYEXE!
!PYEXE! "%~dp0verify_windows.py"
set RESULT=%ERRORLEVEL%

echo.
if "%RESULT%"=="0" (
  echo   All suites passed.
) else (
  echo   Something failed - the report on your Desktop has the detail.
)
echo.
pause
exit /b %RESULT%

REM ---------------------------------------------------------------------
:tryPython
REM  Run the candidate and require it to print ANORAPYOK. Anything that
REM  is not a real interpreter fails this, including the Store stub, a
REM  stale PATH entry, and a Python too old to matter.
%* -c "import sys; sys.stdout.write('ANORAPYOK' if sys.version_info>=(3,8) else 'OLD')" > %PROBE% 2>nul
if errorlevel 1 goto :eof
set PROBE_RESULT=
set /p PROBE_RESULT=<%PROBE%
del %PROBE% >nul 2>&1
if "!PROBE_RESULT!"=="ANORAPYOK" set PYEXE=%*
goto :eof
