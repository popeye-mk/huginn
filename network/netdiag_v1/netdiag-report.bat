@echo off
REM Double-click: runs one scan, writes an HTML report, and opens it.
cd /d "%~dp0"
set EXE=netdiag.exe
if not exist %EXE% set EXE=netdiag_windows_amd64.exe
%EXE% -html "%USERPROFILE%\Desktop\netdiag-report.html"
start "" "%USERPROFILE%\Desktop\netdiag-report.html"
