<#
.SYNOPSIS
    Install Huginn on Windows as a second witness, with an hourly patrol.

.DESCRIPTION
    The Linux side has had scheduled patrol since chapter two item 1. Windows
    had nothing -- the platform ran there (proven by the b022 disc) but only
    when a human typed a command. That is not a witness: an observation older
    than 90 minutes stops counting, so a machine that patrols only when
    someone is watching goes stale exactly when it would have been useful.

    This installs a permanent copy and registers a Scheduled Task that runs
    hourly, plus at logon, with StartWhenAvailable -- the Task Scheduler
    equivalent of systemd's Persistent=true. A machine that was switched off
    at 03:00 runs its missed patrol when it comes back, rather than skipping
    the window in silence.

    **No administrator rights.** A user-level task, a user-level install
    directory. A monitoring tool that demanded admin to watch a LAN it can
    already see would be asking for trust it does not need.

.PARAMETER Source
    Where the platform is now -- the extracted payload from the verification
    disc, or a copy of ops-platform\. Defaults to the folder holding this
    script's grandparent.

.PARAMETER Destination
    Where to install. Default: %LOCALAPPDATA%\Huginn

.PARAMETER SharedObservations
    The folder BOTH machines use to exchange observations -- a synced folder,
    a mapped drive, a UNC path. Without it this host writes only to its own
    copy and corroborates with nobody, which the 'corroborate' verb will say.

.PARAMETER NoTask
    Install the files but do not register the scheduled task.

.EXAMPLE
    .\Install-Huginn.ps1 -SharedObservations "\\nas\huginn\observations"

.EXAMPLE
    .\Install-Huginn.ps1 -SharedObservations "C:\Users\alex\Syncthing\huginn"
#>
[CmdletBinding()]
param(
    [string]$Source,
    [string]$Destination = (Join-Path $env:LOCALAPPDATA "Huginn"),
    [string]$SharedObservations = "",
    [switch]$NoTask
)

$ErrorActionPreference = "Stop"
$TaskName = "Huginn patrol"

function Say($text) { Write-Host "  $text" }
function Fail($text) { Write-Host "  FAILED: $text" -ForegroundColor Red; exit 1 }

Say ""
Say "Huginn -- Windows install"
Say ("=" * 60)

# --- find Python ---------------------------------------------------------
# The platform is stdlib-only, so any 3.8+ will do. Checked FIRST: installing
# files for an interpreter that is not there would leave a task that fails
# hourly and reports nothing, which is the failure mode this project exists
# to refuse.
$python = $null
foreach ($candidate in @("python", "python3", "py")) {
    $found = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($found) {
        $version = & $found.Source -c "import sys;print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0 -and $version) { $python = $found.Source; break }
    }
}
if (-not $python) {
    Fail "no Python found. Install it from python.org or the Microsoft Store, then re-run."
}
Say "python:      $python ($version)"

# --- locate the source ---------------------------------------------------
if (-not $Source) {
    $Source = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}
if (-not (Test-Path (Join-Path $Source "tools\ops.py"))) {
    Fail "no ops-platform at '$Source' (expected tools\ops.py). Pass -Source."
}
Say "source:      $Source"
Say "destination: $Destination"

# --- copy ----------------------------------------------------------------
# data\ is deliberately NOT copied: it holds the other machine's device MACs,
# baselines and findings. A second witness must build its own view of the
# network, or it would "corroborate" by repeating what it was handed.
Say ""
# Installing in place is a legitimate choice -- the operator may already
# have put the platform where they want it. Copying a folder onto itself
# is not: Copy-Item -Force would either error or quietly mangle the tree.
# Detect it by RESOLVED path, so C:\ops-platform and C:\ops-platform\ and a
# relative route to the same place all count as the same folder.
$sourceFull = (Resolve-Path $Source).Path.TrimEnd('\')
$destFull = $Destination.TrimEnd('\')
if (Test-Path $destFull) { $destFull = (Resolve-Path $destFull).Path.TrimEnd('\') }

if ($sourceFull -ieq $destFull) {
    Say "source and destination are the same folder -- installing in place,"
    Say "nothing copied. (This is fine: the files are already where they go.)"
} else {
    Say "copying (excluding data\, .git\, __pycache__\)..."
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $exclude = @("data", ".git", "__pycache__", ".venv", "attic")
    Get-ChildItem -Path $Source -Force | Where-Object { $exclude -notcontains $_.Name } | ForEach-Object {
        Copy-Item $_.FullName -Destination $Destination -Recurse -Force
    }
    Say "copied."
}

# --- shared observations -------------------------------------------------
if ($SharedObservations) {
    if (-not (Test-Path $SharedObservations)) {
        New-Item -ItemType Directory -Force -Path $SharedObservations | Out-Null
    }
    [Environment]::SetEnvironmentVariable(
        "HUGINN_OBSERVATIONS_DIR", $SharedObservations, "User")
    Say "shared observations: $SharedObservations  (set for this user)"
} else {
    Say ""
    Say "NOTE: no -SharedObservations given."
    Say "      This host will witness only itself. 'corroborate' will say so."
}

# --- prove it runs before scheduling it ----------------------------------
Say ""
Say "running one patrol now, to prove it works before scheduling it..."
Push-Location $Destination
try {
    if ($SharedObservations) { $env:HUGINN_OBSERVATIONS_DIR = $SharedObservations }
    & $python "tools\ops.py" corroborate record
    if ($LASTEXITCODE -ne 0) { Fail "the platform did not run here. Nothing was scheduled." }
} finally { Pop-Location }

# --- the scheduled task --------------------------------------------------
if ($NoTask) {
    Say ""
    Say "-NoTask: files installed, nothing scheduled."
    exit 0
}

Say ""
Say "registering the hourly task..."
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Run the wrapper, not python directly, WHEN a shared folder is in use: a
# Scheduled Task does not reliably inherit a user environment variable set
# after the session began, so the task would keep writing to the LOCAL
# observations folder while the operator believed it was writing to the
# share -- one witness in the shared folder, corroborate reporting a single
# host, and nothing saying why. The wrapper sets it where it cannot fail
# silently.
$wrapper = Join-Path $Destination "packaging\windows\Run-Patrol.cmd"
if ($SharedObservations -and (Test-Path $wrapper)) {
    (Get-Content $wrapper) `
        -replace '^set "HUGINN_HOME=.*"$', "set `"HUGINN_HOME=$Destination`"" `
        -replace '^set "HUGINN_OBSERVATIONS_DIR=.*"$', "set `"HUGINN_OBSERVATIONS_DIR=$SharedObservations`"" |
        Set-Content $wrapper -Encoding ASCII
    $action = New-ScheduledTaskAction -Execute "cmd.exe" `
        -Argument "/c $wrapper" -WorkingDirectory $Destination
    Say "task will run the wrapper (carries the shared folder explicitly)."
} else {
    $action = New-ScheduledTaskAction -Execute $python `
        -Argument "tools\ops.py patrol" -WorkingDirectory $Destination
}

# Hourly forever, and once at logon. StartWhenAvailable is the important
# one: it is Task Scheduler's Persistent=true, and without it every window
# the machine spent switched off is simply lost.
# -RepetitionDuration is NOT optional in practice. Omitted, PowerShell 5.1
# registers the trigger with a bounded (often 1-day) repetition or drops the
# repetition entirely -- and the task then simply stops firing, silently,
# which is the failure this whole project refuses.
#
# 9999 days rather than [TimeSpan]::MaxValue: MaxValue is the documented way
# to say "indefinitely" and several PowerShell 5.1 builds reject it outright
# ("Cannot process argument transformation"). 27 years is forever enough for
# a home LAN, and it works everywhere.
$daily = New-ScheduledTaskTrigger -Once -At (Get-Date).Date `
    -RepetitionInterval (New-TimeSpan -Hours 1) `
    -RepetitionDuration (New-TimeSpan -Days 9999)
$logon = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName `
    -Action $action -Trigger @($daily, $logon) -Settings $settings `
    -Description "Huginn Network Guard patrol -- reads the LAN, records an observation, alerts on change. Detect and propose; never blocks." | Out-Null

# Read it back. Register-ScheduledTask can return without throwing and still
# leave nothing registered -- policy, a locked-down Task Scheduler, a Store
# Python shim. Asking Windows whether the task exists is the only version of
# "registered" worth printing, and an installer that ANNOUNCED success it had
# not confirmed would be the exact lie this tool exists to refuse.
$check = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $check) {
    Fail @"
Register-ScheduledTask did not throw, but no task exists afterwards.
Nothing is scheduled. Common causes:
  - Python is a Microsoft Store shim (WindowsApps\python.exe); Task
    Scheduler often cannot launch those. Install python.org's build.
  - Group policy or an endpoint agent blocking task creation.
Register it by hand, or re-run once Python is a real executable.
"@
}
Say "registered: '$TaskName' -- hourly, at logon, catches up if missed."
Say "confirmed with Get-ScheduledTask (state: $($check.State))."
Say ""
Say ("=" * 60)
Say "Done. Check it:"
Say "  Get-ScheduledTask '$TaskName' | Get-ScheduledTaskInfo"
Say "  cd '$Destination'; $python tools\ops.py corroborate"
Say ""
Say "Two hosts must appear in 'corroborate' before this counts as a second"
Say "witness. One name means one ARP cache, which is what an attacker"
Say "rewrites -- and the verb will tell you so."
