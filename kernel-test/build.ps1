#Requires -Version 5.1
<#
.SYNOPSIS
    Builds KernelFuzzer.sys via MSBuild (Release|x64), host-side. Never
    touches a VM. Prints exact MSBuild errors and exits non-zero on any
    failure  -  it does not print a success message unless the .sys was
    actually produced.

.DESCRIPTION
    KRzr's only shipped build path is the legacy WDK 7.1-era
    "build -ceZ" (src/build.bat), which most current WDK/VS installs no
    longer carry (see ../BUILD_AND_VERIFY.md). This script instead drives
    kernel-test/msbuild/KernelFuzzer.vcxproj, a modern WDK 10 MSBuild
    driver project that compiles the SAME ../src/kernel_fuzzer.c the
    legacy path compiles. It requires the "Windows Driver Kit" Visual
    Studio extension (WindowsKernelModeDriver10.0 toolset) alongside
    MSBuild on this host.

.EXAMPLE
    .\build.ps1
#>
[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$projPath   = Join-Path $scriptDir "msbuild\KernelFuzzer.vcxproj"
$logPath    = Join-Path $scriptDir "build.log"

function Fail([string]$msg) {
    Write-Host ""
    Write-Host "BUILD FAILED: $msg" -ForegroundColor Red
    Write-Host "No .sys was produced. This is not a fake success  -  check the errors above." -ForegroundColor Red
    exit 1
}

Write-Host "=== KRzr host-side build ($Configuration|$Platform via MSBuild) ===" -ForegroundColor Cyan

if (-not (Test-Path $projPath)) {
    Fail "project file not found at $projPath"
}

# --- Locate MSBuild -----------------------------------------------------
$msbuild = $null

$cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
if ($cmd) { $msbuild = $cmd.Source }

if (-not $msbuild) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath 2>$null
        if ($vsPath) {
            $candidate = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
            if (Test-Path $candidate) { $msbuild = $candidate }
        }
    }
}

if (-not $msbuild) {
    Fail @"
msbuild.exe not found on PATH and vswhere could not locate a VS install with MSBuild.
Install "Build Tools for Visual Studio" (Desktop C++ workload) plus the
Windows Driver Kit (WDK) Visual Studio extension, or run this from a
"Developer PowerShell for VS" prompt, then retry.
"@
}

Write-Host "Using MSBuild: $msbuild"
Write-Host "Project:       $projPath"
Write-Host ""

# --- Build ----------------------------------------------------------------
$msbuildArgs = @(
    "`"$projPath`""
    "/p:Configuration=$Configuration"
    "/p:Platform=$Platform"
    "/nologo"
    "/verbosity:normal"
    "/fileLogger"
    "/fileLoggerParameters:LogFile=`"$logPath`";Verbosity=diagnostic"
)

& $msbuild @msbuildArgs
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    Write-Host ""
    Write-Host "--- MSBuild reported failure (exit $exitCode). Errors from $logPath : ---" -ForegroundColor Yellow
    if (Test-Path $logPath) {
        Select-String -Path $logPath -Pattern "error" -SimpleMatch:$false | Select-Object -Last 40 | ForEach-Object {
            Write-Host $_.Line -ForegroundColor Red
        }
    }
    Fail "MSBuild exited with code $exitCode. Common cause: the WindowsKernelModeDriver10.0 platform toolset (WDK VS extension) is not installed on this host  -  see ../BUILD_AND_VERIFY.md and https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk"
}

# --- Locate the produced .sys (never assume the path  -  verify it exists) --
$sys = Get-ChildItem -Path $scriptDir -Recurse -Filter "KernelFuzzer.sys" -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $sys) {
    Fail "MSBuild exited 0 but no KernelFuzzer.sys was found under $scriptDir. Treating this as a failed build  -  check $logPath."
}

Write-Host ""
Write-Host "BUILD OK" -ForegroundColor Green
Write-Host "  .sys : $($sys.FullName)"
Write-Host "  size : $($sys.Length) bytes"
Write-Host "  time : $($sys.LastWriteTime)"
Write-Host ""
Write-Host "Next: sign it (see ../SIGNING.md) before copying to the guest." -ForegroundColor Cyan
Write-Host "  signtool sign /fd SHA256 /a /s My /n KRzrTestCert /t http://timestamp.digicert.com `"$($sys.FullName)`""

exit 0
