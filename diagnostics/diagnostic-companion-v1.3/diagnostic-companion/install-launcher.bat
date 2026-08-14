@echo off
REM One entry point for Windows. Everything it uses lives in launchers\.
REM
REM   install-launcher.bat   create Desktop and Start Menu shortcuts
REM
REM To remove them:
REM   powershell -ExecutionPolicy Bypass -File launchers\windows\Install-Shortcut.ps1 -Remove
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0launchers\windows\Install-Shortcut.ps1" %*
echo.
pause
