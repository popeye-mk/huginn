@echo off
REM Double-click this file to use netdiag without typing commands.
REM It opens the guided menu; everything else is numbered choices.
title netdiag - network diagnostician
cd /d "%~dp0"
if exist netdiag.exe (
  netdiag.exe menu
) else if exist netdiag_windows_amd64.exe (
  netdiag_windows_amd64.exe menu
) else (
  echo Could not find netdiag.exe next to this file.
  echo Put netdiag.bat in the same folder as the program.
)
echo.
pause
