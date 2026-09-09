#Requires -Version 5.1
<#
.SYNOPSIS
    Stops and deletes the KernelFuzzer service INSIDE the guest.

.DESCRIPTION
    Runs `sc stop` then `sc delete` against the KernelFuzzer service. This
    does NOT connect to any VM itself  -  run it from a PowerShell prompt
    already inside the guest.

    KNOWN LEAK (see ../README.md / code review): DriverUnload() /
    CleanupResources() do not free g_ThreadList or g_ResourceList (their
    DestroyFuzzingThread()/DestroyResource() counterparts are declared but
    never called), and DriverUnload() does not wait for FuzzingLoop or any
    ThreadWorker thread to exit before the device is deleted. Practically:

      - Every load/unload cycle leaks NonPagedPool tagged 'FZAR' and thread
        objects that are never fully torn down.
      - If any worker thread is still executing when unload runs, it can
        touch freed globals / unloaded driver code and bugcheck the guest.

    PREFER REVERTING THE HYPER-V CHECKPOINT over repeated unload/reload
    cycles in the same guest session. Use this script for a clean single
    stop at the end of a run, not as a reset button between test iterations.

.PARAMETER ServiceName
    Service name to stop/delete. Defaults to KernelFuzzer.

.PARAMETER WaitSeconds
    Seconds to sleep after `sc stop` before `sc delete`, to give
    FuzzingLoop/ThreadWorker threads a chance to notice g_FuzzingActive=
    FALSE and wind down before the device object is torn out from under
    them. This is a best-effort mitigation, NOT a guarantee  -  see the
    known-leak note above. Default 5.

.EXAMPLE
    .\unload.ps1
#>
[CmdletBinding()]
param(
    [string]$ServiceName = "KernelFuzzer",
    [int]$WaitSeconds = 5
)

$ErrorActionPreference = "Continue"

Write-Host "=== KRzr unload.ps1 (guest-only; service '$ServiceName') ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "KNOWN LEAK: g_ThreadList / g_ResourceList are never freed on unload, and no" -ForegroundColor Yellow
Write-Host "thread is waited on before the device is deleted (see README.md SAFETY). This" -ForegroundColor Yellow
Write-Host "unload can itself bugcheck the guest if a worker thread is still in flight." -ForegroundColor Yellow
Write-Host "Prefer reverting the checkpoint over relying on repeated unload/reload cycles." -ForegroundColor Yellow
Write-Host ""

# Use the exit code, not sc.exe's message text, since that text is
# localized (e.g. Turkish "yuklu bir hizmet olarak yok" instead of English
# "does not exist") and must not be relied on to decide control flow.
$ERROR_SERVICE_DOES_NOT_EXIST = 1060
& sc.exe query $ServiceName 2>&1 | Out-Null
if ($LASTEXITCODE -eq $ERROR_SERVICE_DOES_NOT_EXIST) {
    Write-Host "Service '$ServiceName' is not registered. Nothing to do." -ForegroundColor Green
    exit 0
}

Write-Host "Stopping '$ServiceName'..."
& sc.exe stop $ServiceName
Write-Host ""

Write-Host "Waiting $WaitSeconds s for in-flight worker threads to notice the stop flag" -ForegroundColor Cyan
Write-Host "(best-effort only  -  see KNOWN LEAK above; this does not guarantee they exit)."
Start-Sleep -Seconds $WaitSeconds

Write-Host "Deleting '$ServiceName'..."
& sc.exe delete $ServiceName
$deleteExit = $LASTEXITCODE

Write-Host ""
$post = & sc.exe query $ServiceName 2>&1
$postExit = $LASTEXITCODE
if ($postExit -eq $ERROR_SERVICE_DOES_NOT_EXIST) {
    Write-Host "Unloaded: service no longer registered." -ForegroundColor Green
} else {
    Write-Host "WARNING: service still queryable after delete  -  check for a pending stop" -ForegroundColor Red
    Write-Host "or a hung/crashed driver. Consider reverting the checkpoint instead of" -ForegroundColor Red
    Write-Host "retrying unload." -ForegroundColor Red
    $post | ForEach-Object { Write-Host $_ }
}

Write-Host ""
Write-Host "If this guest will be reused for another run, reverting the checkpoint is" -ForegroundColor Cyan
Write-Host "still the safer reset  -  this unload does not undo the pool/thread leak above."

exit $deleteExit
