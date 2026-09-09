#Requires -Version 5.1
<#
.SYNOPSIS
    -Arm-gated wrapper around smoke_test.py: drives the loaded driver's
    real IOCTLs (allocate/free/coverage/fault-patterns) the way
    src/client.py does, and checks the responses are well-formed.

.DESCRIPTION
    Runs INSIDE the guest, against a KernelFuzzer service that is already
    loaded (load.ps1 -Arm). Without -Arm this only prints what it would
    run and exits 0  -  it never touches the driver on its own.

    Scope: IOCTL_ALLOCATE_MEMORY, IOCTL_FREE_MEMORY, IOCTL_GET_COVERAGE,
    IOCTL_GET_FAULT_PATTERNS  -  the four IOCTLs with real kernel logic
    behind them today (see ../README.md). Does not start the fuzzing loop
    or create kernel threads.

.PARAMETER Python
    Python interpreter to use. Defaults to "python" on PATH.

.EXAMPLE
    .\smoke-test.ps1
    # dry run  -  prints the plan, does nothing

.EXAMPLE
    .\smoke-test.ps1 -Arm
    # actually calls into the driver via src\client.py
#>
[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$Arm
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pyScript  = Join-Path $scriptDir "smoke_test.py"

Write-Host "=== KRzr smoke-test.ps1 ===" -ForegroundColor Cyan

if (-not $Arm) {
    Write-Host ""
    Write-Host "DRY RUN (default)  -  nothing will be sent to the driver. Pass -Arm to run it." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Would run:"
    Write-Host "  $Python `"$pyScript`""
    Write-Host ""
    Write-Host "Preconditions before using -Arm:"
    Write-Host "  - Guest checkpoint already taken (see README.md SAFETY)."
    Write-Host "  - KernelFuzzer service is loaded and RUNNING (load.ps1 -Arm; sc query KernelFuzzer)."
    exit 0
}

# Check the exit code, not sc.exe's message text: the descriptive
# "does not exist" sentence is localized (e.g. Turkish), while the
# STATE/TYPE keywords like RUNNING below are fixed, unlocalized tokens.
$ERROR_SERVICE_DOES_NOT_EXIST = 1060
$svc = & sc.exe query KernelFuzzer 2>&1
if ($LASTEXITCODE -eq $ERROR_SERVICE_DOES_NOT_EXIST) {
    Write-Host "ABORT: KernelFuzzer service is not registered. Run load.ps1 -Arm first." -ForegroundColor Red
    exit 1
}
if ($svc -notmatch "RUNNING") {
    Write-Host "WARNING: KernelFuzzer service does not report RUNNING:" -ForegroundColor Yellow
    $svc | ForEach-Object { Write-Host $_ }
    Write-Host "Proceeding anyway  -  the connect() check below will fail cleanly if it's not up." -ForegroundColor Yellow
}

$pythonCmd = Get-Command $Python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "ABORT: '$Python' not found on PATH." -ForegroundColor Red
    exit 1
}

Write-Host "Running: $Python `"$pyScript`""
Write-Host ""

& $Python $pyScript
$exitCode = $LASTEXITCODE

Write-Host ""
if ($exitCode -eq 0) {
    Write-Host "SMOKE TEST PASSED" -ForegroundColor Green
} else {
    Write-Host "SMOKE TEST FAILED (exit $exitCode)" -ForegroundColor Red
    Write-Host "If this followed unexpected driver behavior (hang, unresponsive IOCTLs)," -ForegroundColor Yellow
    Write-Host "check kd for a hang/bugcheck before retrying  -  see kd-triage.txt." -ForegroundColor Yellow
}

exit $exitCode
