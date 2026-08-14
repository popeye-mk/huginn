<#
.SYNOPSIS
    Create Desktop and Start Menu shortcuts for Diagnostic Companion.

.DESCRIPTION
    Windows counterpart to install-desktop-entry.sh.

    Three details this gets right that a hand-made shortcut usually
    does not:

    * The Desktop path is asked for, not assumed. It is localised, and
      on a machine with OneDrive Backup enabled it is redirected inside
      the OneDrive folder entirely. Hardcoding "$env:USERPROFILE\Desktop"
      produces a shortcut nobody ever sees. GetFolderPath('Desktop')
      returns wherever it actually is.
    * WorkingDirectory is set to the program's own folder. Shortcuts
      otherwise inherit an arbitrary working directory, and reports are
      written relative to it - so a report would land somewhere the
      user never looks, on a machine that is not theirs.
    * The icon is taken from diag.exe itself when no .ico is present,
      because PyInstaller embeds it there.

.PARAMETER Remove
    Delete the shortcuts instead of creating them.
#>

[CmdletBinding()]
param([switch]$Remove)

$ErrorActionPreference = 'Stop'
$AppName = 'Diagnostic Companion'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Localised and OneDrive-aware; never assume the English path.
$DesktopDir   = [Environment]::GetFolderPath('Desktop')
$StartMenuDir = Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs'

$DesktopLink   = Join-Path $DesktopDir   "$AppName.lnk"
$StartMenuLink = Join-Path $StartMenuDir "$AppName.lnk"

if ($Remove) {
    foreach ($link in @($DesktopLink, $StartMenuLink)) {
        if (Test-Path $link) { Remove-Item $link -Force; Write-Host "Removed: $link" }
    }
    Write-Host 'Done.'
    exit 0
}

# Find the executable: beside this script (USB layout) or in dist\ after
# a local build.
# This script may sit beside diag.exe (USB layout) or two levels down
# inside the source tree (launchers\windows\), so look in both.
$Root = Resolve-Path (Join-Path $Here '..\..') -ErrorAction SilentlyContinue
$candidates = @(
    (Join-Path $Here 'diag.exe'),
    (Join-Path $Here 'dist\diag.exe')
)
if ($Root) {
    $candidates += @(
        (Join-Path $Root 'dist\diag.exe'),
        (Join-Path $Root 'dist\usb-kit\diag.exe'),
        (Join-Path $Root 'diag.exe')
    )
}
$Target = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $Target) {
    Write-Host ''
    Write-Host '  diag.exe was not found.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Build it first:'
    Write-Host '      python build.py --usb'
    Write-Host ''
    Write-Host '  then run this script again from the folder holding diag.exe.'
    Write-Host ''
    exit 1
}
$Target = (Resolve-Path $Target).Path
$TargetDir = Split-Path -Parent $Target
Write-Host "Program: $Target"

# Prefer a standalone .ico; otherwise use the one PyInstaller embedded
# in the executable (index 0).
$IconFile = Join-Path $Here 'diag-icon.ico'
if (-not (Test-Path $IconFile) -and $Root) {
    $IconFile = Join-Path $Root 'launchers\icons\diag-icon.ico'
}
if (Test-Path $IconFile) {
    $IconLocation = "$((Resolve-Path $IconFile).Path),0"
} else {
    $IconLocation = "$Target,0"
}
Write-Host "Icon:    $IconLocation"

function New-Shortcut {
    param([string]$Path, [string]$Description)

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($Path)
    $sc.TargetPath = $Target
    # No arguments: diag.exe opens the guided menu when run with none.
    $sc.Arguments = ''
    # Reports are written relative to this; without it they land wherever
    # Explorer happened to be.
    $sc.WorkingDirectory = $TargetDir
    $sc.IconLocation = $IconLocation
    $sc.Description = $Description
    $sc.Save()

    [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    Write-Host "Created: $Path"
}

$desc = 'Read-only health check of this computer - changes nothing'
New-Shortcut -Path $DesktopLink   -Description $desc
New-Shortcut -Path $StartMenuLink -Description $desc

Write-Host ''
Write-Host 'Done. The shortcut opens the guided menu.'
Write-Host ''
Write-Host 'For drive health (SMART), right-click the shortcut and choose'
Write-Host '"Run as administrator" - without it that one check is reported'
Write-Host 'as "could not check" rather than guessed at.'
Write-Host ''
