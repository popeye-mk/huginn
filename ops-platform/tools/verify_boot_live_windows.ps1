# Boot verification on Windows -- real Hyper-V guest, real backup.
#
#   .\tools\verify_boot_live_windows.ps1 C:\anora-test\cirros.vhdx
#
# The Windows twin of verify_boot_live.sh, and it exists for the same
# architectural reason rather than for convenience: this script owns
# restic and the disk image, because creating a backup is not the
# platform's job, and because `subprocess` belongs in engines/ (the
# architecture test enforces that and caught a first draft that put the
# restic calls in Python).
#
# MUST be run from an ELEVATED PowerShell. Every Hyper-V cmdlet needs it.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Image
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$platform = Split-Path -Parent $here

# --- preflight -----------------------------------------------------------
# Each of these is a reason the run cannot happen, not a verification
# failure. Reporting them as failures would blame the backup for a
# missing tool -- the exact confusion this platform exists to prevent.

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "  NOT ELEVATED. Open PowerShell with Win+X, A and try again."
    exit 2
}

if (-not (Test-Path -LiteralPath $Image -PathType Leaf)) {
    Write-Host "  no such disk image: $Image"
    exit 2
}

if (-not (Get-Command 'restic' -ErrorAction SilentlyContinue)) {
    Write-Host "  missing: restic"
    Write-Host ""
    Write-Host "    winget install -e --id restic.restic"
    Write-Host ""
    Write-Host "  A boot test that cannot run is UNVERIFIED, not verified-clean."
    exit 2
}

function Split-Invocation {
    <#
    Split "py -3" into an executable and its arguments.

    Written as a function because the obvious inline version is wrong in
    a way that reads as correct: `$parts[1..($parts.Length - 1)]` on a
    single-element array evaluates `1..0`, and PowerShell counts ranges
    BACKWARDS when the end is lower than the start -- so it returns
    element 0, the executable itself. "python" would have been run as
    `python python -c ...`.

    Select-Object -Skip has no such edge, and returns nothing when there
    is nothing to skip to.
    #>
    param([string]$Invocation)
    $parts = $Invocation.Split(' ') | Where-Object { $_ }
    return @($parts[0], @($parts | Select-Object -Skip 1))
}

function Find-Python {
    <#
    Get-Command is NOT a valid test for Python on Windows 11.

    The OS ships an App Execution Alias at
    %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe which Get-Command
    resolves happily -- and which, when run, prints "Python was not
    found; run without arguments to install from the Microsoft Store"
    and exits. A preflight that trusts it passes, and the run then dies
    later with a message that looks nothing like its cause. That is
    exactly what happened on the first real run of this harness.

    VERIFY.cmd already solved this: EXECUTE each candidate and require
    it to prove itself by printing a marker. Same fix here, because the
    platform's own rule applies to its tooling -- presence is not
    capability.
    #>
    foreach ($candidate in @('py -3', 'python', 'python3')) {
        $exe, $exeArgs = Split-Invocation $candidate
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $probe = & $exe @exeArgs -c `
                "import sys; sys.stdout.write('ANORAPYOK' if sys.version_info>=(3,8) else 'OLD')" 2>$null
        }
        catch { continue }
        if ($probe -eq 'ANORAPYOK') { return $candidate }
    }
    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Host "  No working Python was found on this machine."
    Write-Host ""
    Write-Host "  Windows 11 may show a 'python' command that only offers to"
    Write-Host "  open the Microsoft Store. That is not a Python install, and"
    Write-Host "  this check executes candidates rather than trusting PATH."
    Write-Host ""
    Write-Host "    winget install -e --id Python.Python.3.12"
    Write-Host ""
    Write-Host "  A boot test that cannot run is UNVERIFIED, not verified-clean."
    exit 2
}
Write-Host "  python: $python"

try { Get-VMHost | Out-Null } catch {
    Write-Host "  Hyper-V did not answer. Check:  Get-VMHost"
    exit 2
}

Write-Host ""
Write-Host "  R7 boot verification -- real Hyper-V guest, real backup"
Write-Host "  =================================================================="

# --- throwaway repository ------------------------------------------------
# Never point at the operator's real backups. The Linux harness unsets
# RESTIC_REPOSITORY and RESTIC_PASSWORD for exactly this reason; the
# same variables are honoured by restic on Windows.

$work = Join-Path $env:TEMP ("huginn-boot-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null

$passFile = Join-Path $work 'password'
'r7-boot-verification-throwaway' | Set-Content -LiteralPath $passFile -NoNewline -Encoding ascii
$repo = Join-Path $work 'repo'
$source = Join-Path $work 'source'
New-Item -ItemType Directory -Path $source -Force | Out-Null

Remove-Item Env:\RESTIC_REPOSITORY -ErrorAction SilentlyContinue
Remove-Item Env:\RESTIC_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:\RESTIC_PASSWORD_FILE -ErrorAction SilentlyContinue

$status = 1
try {
    $size = [math]::Round((Get-Item -LiteralPath $Image).Length / 1MB)
    Write-Host "  backing up $(Split-Path -Leaf $Image) ($size MB)"
    Copy-Item -LiteralPath $Image -Destination (Join-Path $source (Split-Path -Leaf $Image))

    & restic -r $repo --password-file $passFile init | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "restic init failed" }

    & restic -r $repo --password-file $passFile backup $source | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "restic backup failed" }

    Write-Host "  snapshot created -- now restoring and booting it"
    Write-Host ""

    # The interpreter proven to work in preflight, not whatever PATH
    # offers at this moment.
    $pyExe, $pyArgs = Split-Invocation $python
    & $pyExe @pyArgs (Join-Path $here 'verify_boot_live_windows.py') $repo $passFile
    $status = $LASTEXITCODE
}
catch {
    Write-Host "  harness failed before the platform was reached: $_"
    $status = 2
}
finally {
    # An orphaned VM holding a named pipe open is the leak this whole
    # design refuses to leave behind. The platform tears down its own
    # guest; this catches the case where it could not.
    Get-VM -Name 'boot-live-test' -ErrorAction SilentlyContinue |
        ForEach-Object {
            Stop-VM -VM $_ -TurnOff -Force -ErrorAction SilentlyContinue
            Remove-VM -VM $_ -Force -ErrorAction SilentlyContinue
        }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "  =================================================================="
if ($status -eq 0) {
    Write-Host "  R7 BOOT (Windows): a machine was restored from backup and came"
    Write-Host "  back up, and the named-pipe console reader was proven against a"
    Write-Host "  real VM for the first time."
}
else {
    Write-Host "  R7 BOOT (Windows): did not reach proof of recovery -- see above."
    Write-Host "  A real finding, whichever way it went. The console capture"
    Write-Host "  section is the useful part; send it as-is."
}
Write-Host ""
exit $status
