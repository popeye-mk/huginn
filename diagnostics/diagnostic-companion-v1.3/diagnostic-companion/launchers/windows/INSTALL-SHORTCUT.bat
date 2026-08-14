@echo off
REM ====================================================================
REM  Double-click wrapper for Install-Shortcut.ps1.
REM
REM  Exists because double-clicking a .ps1 opens it in Notepad rather
REM  than running it, and because PowerShell's default execution policy
REM  blocks local scripts. -ExecutionPolicy Bypass applies to this one
REM  invocation only - it changes no machine-wide setting.
REM ====================================================================

cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Shortcut.ps1"

echo.
pause
