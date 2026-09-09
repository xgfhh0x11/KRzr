#Requires -Version 5.1
<#
.SYNOPSIS
    Loads KernelFuzzer.sys as a kernel service INSIDE the disposable guest
    ("WinKDbg"). Defaults to a dry run that only PRINTS what it would do.
    Nothing is armed/executed unless -Arm is passed explicitly.

.DESCRIPTION
    This script is meant to run inside the disposable Hyper-V kdnet guest,
    never on the host. It does not connect to, copy files to, or otherwise
    reach into any VM itself  -  that transfer and the decision to run it are
    entirely the operator's, done after taking a checkpoint (see README.md
    SAFETY section).

    Sequence (only when -Arm is given):
      1. Verify test-signing is enabled (bcdedit /enum {current} | testsigning).
      2. sc create KernelFuzzer type= kernel binPath= <SysPath> start= demand
      3. sc start KernelFuzzer
      4. sc query KernelFuzzer  (expect STATE: 4 RUNNING)

    A race-condition fuzzer is MORE likely than most drivers to bugcheck the
    box on load or on the first fuzzing iteration. TAKE A CHECKPOINT OF THE
    GUEST BEFORE RUNNING THIS WITH -Arm. See README.md.

.PARAMETER SysPath
    Path (inside the guest) to the built/signed KernelFuzzer.sys.

.PARAMETER Arm
    Required to actually create/start the service. Without it, this script
    only prints the commands it would run and exits 0.

.EXAMPLE
    .\load.ps1 -SysPath C:\KRzr\KernelFuzzer.sys
    # dry run  -  prints the plan, does nothing

.EXAMPLE
    .\load.ps1 -SysPath C:\KRzr\KernelFuzzer.sys -Arm
    # actually creates and starts the service (guest only, after a checkpoint)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SysPath,

    [string]$ServiceName = "KernelFuzzer",

    [switch]$Arm
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "load.ps1 must run from an elevated (Administrator) PowerShell inside the guest."
    }
}

Write-Host "=== KRzr load.ps1 (guest-only; service '$ServiceName') ===" -ForegroundColor Cyan

$resolvedSys = $SysPath
if (-not (Test-Path $SysPath)) {
    Write-Host "WARNING: $SysPath does not exist on this machine yet. In a dry run that's fine" -ForegroundColor Yellow
    Write-Host "         (this just previews the commands); with -Arm it will fail at sc create." -ForegroundColor Yellow
} else {
    $resolvedSys = (Resolve-Path $SysPath).Path
}

$planLines = @(
    "  sc create $ServiceName type= kernel binPath= `"$resolvedSys`" start= demand"
    "  sc start $ServiceName"
    "  sc query $ServiceName"
)

if (-not $Arm) {
    Write-Host ""
    Write-Host "DRY RUN (default)  -  nothing will be armed. Pass -Arm to actually load the driver." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Plan:"
    $planLines | ForEach-Object { Write-Host $_ }
    Write-Host ""
    Write-Host "Before using -Arm:" -ForegroundColor Yellow
    Write-Host "  1. Take a Hyper-V CHECKPOINT of this guest from the host (see README.md SAFETY)."
    Write-Host "  2. Confirm test-signing is on: bcdedit /enum {current} | findstr testsigning"
    Write-Host "  3. Confirm KernelFuzzer.sys is signed (SIGNING.md) or testsigning covers it."
    exit 0
}

Assert-Admin

if (-not (Test-Path $resolvedSys)) {
    Write-Host "ABORT: $resolvedSys not found. Build/copy the .sys into the guest first." -ForegroundColor Red
    exit 1
}

# --- Safety gate: test-signing must be on, or this load is pointless/unsafe ---
Write-Host ""
Write-Host "Checking test-signing state..." -ForegroundColor Cyan
$bcdOut = & bcdedit /enum "{current}" 2>&1 | Out-String
if ($bcdOut -notmatch "testsigning\s+Yes") {
    Write-Host "ABORT: testsigning is not enabled on this guest (bcdedit /enum '{current}')." -ForegroundColor Red
    Write-Host "Run:  bcdedit /set testsigning on   then reboot the guest, then retry." -ForegroundColor Red
    exit 1
}
Write-Host "testsigning: Yes" -ForegroundColor Green

Write-Host ""
Write-Host "REMINDER: this is a race-condition fuzzer. It is MORE likely than most drivers" -ForegroundColor Yellow
Write-Host "to bugcheck this box, possibly on the very first fuzzing iteration. Make sure" -ForegroundColor Yellow
Write-Host "you have already taken a checkpoint of THIS guest before continuing." -ForegroundColor Yellow
Write-Host ""

Write-Host "Arming: creating and starting service '$ServiceName'..." -ForegroundColor Cyan

# Clean up any stale registration from a prior run first (best-effort).
& sc.exe stop $ServiceName 2>&1 | Out-Null
& sc.exe delete $ServiceName 2>&1 | Out-Null

& sc.exe create $ServiceName type= kernel binPath= "$resolvedSys" start= demand
if ($LASTEXITCODE -ne 0) {
    Write-Host "sc create failed (exit $LASTEXITCODE)." -ForegroundColor Red
    exit $LASTEXITCODE
}

& sc.exe start $ServiceName
$startExit = $LASTEXITCODE

Write-Host ""
& sc.exe query $ServiceName

if ($startExit -ne 0) {
    Write-Host ""
    Write-Host "sc start returned $startExit  -  driver did not report RUNNING. Check the guest" -ForegroundColor Red
    Write-Host "for a bugcheck; if it crashed, REVERT THE CHECKPOINT rather than retrying load." -ForegroundColor Red
    exit $startExit
}

Write-Host ""
Write-Host "Loaded. Next: attach kd from the host (see README.md / kd-triage.txt) and run" -ForegroundColor Green
Write-Host "smoke-test.ps1 -Arm from a separate window, or drive src\client.py directly." -ForegroundColor Green
exit 0
