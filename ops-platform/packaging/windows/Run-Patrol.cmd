@echo off
REM  Huginn patrol -- the wrapper the Windows Scheduled Task runs.
REM
REM  This exists because of one Task Scheduler behaviour: a task does NOT
REM  reliably inherit a user environment variable set after the session
REM  began. Set HUGINN_OBSERVATIONS_DIR with SetEnvironmentVariable, and the
REM  hourly task may keep writing to the LOCAL folder anyway -- so the shared
REM  folder holds one machine's file, corroborate reports a single witness,
REM  and nothing anywhere says why. The variable is set here instead, where
REM  it is visible and cannot silently fail to apply.
REM
REM  EDIT THE TWO LINES BELOW to match this machine.

set "HUGINN_HOME=C:\ops-platform"
set "HUGINN_OBSERVATIONS_DIR=C:\huginn-shared"

REM  --------------------------------------------------------------------
REM  Nothing below normally needs changing.

cd /d "%HUGINN_HOME%" || (
    echo [huginn] HUGINN_HOME does not exist: %HUGINN_HOME%
    exit /b 2
)

if not exist "%HUGINN_OBSERVATIONS_DIR%" (
    REM  A missing shared folder is reported, not created silently. If the
    REM  share is not mounted, writing a local directory of the same name
    REM  would look like it worked while the other machine saw nothing.
    echo [huginn] observations folder missing: %HUGINN_OBSERVATIONS_DIR%
    echo [huginn] the share is probably not available. NOT writing locally --
    echo [huginn] a witness the other host cannot read is worse than none.
    exit /b 3
)

python tools\ops.py patrol
exit /b %ERRORLEVEL%
