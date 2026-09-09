@echo off
REM Kernel Race Condition Fuzzing Driver Uninstallation Script

REM Run from the script's own directory so service control works
REM regardless of the caller's current working directory.
cd /d "%~dp0"

echo Uninstalling Kernel Race Condition Fuzzing Driver...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as administrator - OK
) else (
    echo This script must be run as administrator!
    pause
    exit /b 1
)

REM Stop driver
echo Stopping driver...
sc stop KernelFuzzer

if %ERRORLEVEL% EQU 0 (
    echo Driver stopped successfully
) else (
    echo Driver was not running or failed to stop
)

REM Delete driver service
echo Removing driver service...
sc delete KernelFuzzer

if %ERRORLEVEL% EQU 0 (
    echo Driver service removed successfully
) else (
    echo Failed to remove driver service
)

echo.
echo Driver uninstalled successfully!
echo.

pause
