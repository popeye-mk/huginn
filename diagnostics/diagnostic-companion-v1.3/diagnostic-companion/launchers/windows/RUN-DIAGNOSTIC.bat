@echo off
REM ====================================================================
REM  Double-click launcher for the USB stick.
REM
REM  diag.exe already opens the menu when run with no arguments, so
REM  this only exists for two reasons:
REM
REM    1. A .bat is unmistakably "the thing to double-click" next to an
REM       .exe, a folder and a pile of reports.
REM    2. Explorer sets the working directory to the .bat's folder, and
REM       'cmd /k' keeps the window open if anything goes wrong. A bare
REM       double-click on an .exe that errors early closes the window
REM       before the message can be read.
REM ====================================================================

cd /d "%~dp0"

if not exist "diag.exe" (
  echo.
  echo   diag.exe is missing from this folder.
  echo.
  echo   This USB stick is incomplete. It needs diag.exe next to
  echo   this file - see README.txt.
  echo.
  pause
  exit /b 1
)

diag.exe

REM The menu exits cleanly on its own; this pause only catches a crash
REM before the menu ever appeared.
if errorlevel 1 pause
