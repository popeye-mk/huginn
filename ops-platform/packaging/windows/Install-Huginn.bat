@echo off
REM ====================================================================
REM  Install-Huginn.bat -- double-click to install Huginn on Windows.
REM
REM  Does the whole job a person expects from "install":
REM    1. makes sure Python is present (installs it with winget if not);
REM    2. offers the two OPTIONAL external tools (nmap, numpy);
REM    3. copies the app to %LOCALAPPDATA%\Huginn and schedules the
REM       hourly patrol  (this part is Install-Huginn.ps1, reused);
REM    4. puts a "Huginn" icon on the Desktop and in the Start Menu.
REM
REM  No administrator rights. Everything is installed for THIS user, in
REM  this user's profile -- a monitoring tool that demanded admin to watch
REM  a LAN it can already see would be asking for trust it does not need.
REM
REM  Huginn itself has NO Python dependencies -- it runs on the standard
REM  library alone. "Dependencies" here means Python itself, plus the two
REM  optional tools that make it faster or smarter and which it works
REM  without (and says so when they are absent).
REM ====================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo   Huginn -- Windows install
echo   ============================================================

REM --- 1. Python -------------------------------------------------------
REM Checked first: installing files for an interpreter that is not there
REM would leave a scheduled task that fails hourly and reports nothing,
REM which is the exact failure this tool exists to refuse.
set "PYTHON="
for %%P in (python.exe python3.exe py.exe) do (
  if not defined PYTHON (
    where %%P >nul 2>&1 && (
      for /f "delims=" %%V in ('%%P -c "import sys;print(sys.version_info[0])" 2^>nul') do (
        if "%%V"=="3" set "PYTHON=%%P"
      )
    )
  )
)

if not defined PYTHON (
  echo.
  echo   No Python 3 found.
  where winget >nul 2>&1 && (
    echo   Installing Python 3.12 for this user via winget...
    winget install --exact --id Python.Python.3.12 --scope user ^
      --accept-source-agreements --accept-package-agreements
    echo.
    echo   Python installed. CLOSE this window and run Install-Huginn.bat
    echo   again -- a new window is needed to pick up the updated PATH.
    pause
    exit /b 0
  ) || (
    echo   winget is not available. Install Python from:
    echo       https://www.python.org/downloads/windows/
    echo   Tick "Add python.exe to PATH" during setup, then re-run this.
    pause
    exit /b 1
  )
)
for /f "delims=" %%V in ('%PYTHON% -c "import sys;print(\"%%d.%%d\"%%sys.version_info[:2])" 2^>nul') do set "PYVER=%%V"
echo   python:      %PYTHON%  (%PYVER%)

REM --- 2. optional external tools -------------------------------------
echo.
echo   Optional tools (Huginn runs without them, and says so when absent):
echo     - nmap : a faster LAN sweep and port scan
echo     - numpy: semantic search over past findings
echo.
set /p WANTOPT="  Install these two now? [y/N] "
if /I "!WANTOPT!"=="y" (
  where winget >nul 2>&1 && (
    echo   installing nmap via winget...
    winget install --exact --id Insecure.Nmap --accept-source-agreements --accept-package-agreements 2>nul || echo   (nmap skipped -- install it later if you want it)
  ) || (
    echo   winget not available; skipping nmap. Get it from https://nmap.org/download
  )
  echo   installing numpy into your user site...
  %PYTHON% -m pip install --user numpy || echo   (numpy skipped -- semantic recall will degrade to substring, and say so)
)

REM --- 3. files + scheduled patrol (reuse the tested PS1) --------------
echo.
echo   installing files and scheduling the hourly patrol...
set "PS1=%~dp0Install-Huginn.ps1"
if not exist "%PS1%" (
  echo   FAILED: Install-Huginn.ps1 is missing next to this file.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
if errorlevel 1 (
  echo.
  echo   The file/scheduler step reported a problem above. Stopping so it
  echo   is not papered over. Nothing about the icon is worth doing until
  echo   the install itself succeeded.
  pause
  exit /b 1
)

REM --- 4. Desktop + Start Menu icon -----------------------------------
REM Points at Start-Huginn.cmd in the installed copy, with the raven .ico.
REM Built with WScript.Shell so it needs no admin and no extra tooling.
set "HUGINNDIR=%LOCALAPPDATA%\Huginn"
set "LAUNCH=%HUGINNDIR%\packaging\windows\Start-Huginn.cmd"
set "ICON=%HUGINNDIR%\packaging\desktop\icons\huginn.ico"

echo.
echo   creating the Desktop and Start Menu shortcuts...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$w = New-Object -ComObject WScript.Shell;" ^
  "foreach ($dir in @([Environment]::GetFolderPath('Desktop'), (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'))) {" ^
  "  $lnk = $w.CreateShortcut((Join-Path $dir 'Huginn.lnk'));" ^
  "  $lnk.TargetPath = '%LAUNCH%';" ^
  "  $lnk.WorkingDirectory = '%HUGINNDIR%';" ^
  "  if (Test-Path '%ICON%') { $lnk.IconLocation = '%ICON%' };" ^
  "  $lnk.Description = 'Open the Huginn network console';" ^
  "  $lnk.WindowStyle = 7;" ^
  "  $lnk.Save() };" ^
  "$d = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Huginn.lnk';" ^
  "if (Test-Path $d) { Write-Host '  shortcut created:' $d } else { Write-Host '  WARNING: the Desktop shortcut was not created.' }"

echo.
echo   ============================================================
echo   Done. Double-click "Huginn" on your Desktop to open the console.
echo   The hourly patrol is scheduled and will also run at logon.
echo.
pause
endlocal
