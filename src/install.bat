@echo off
REM Kernel Race Condition Fuzzing Driver Installation Script

REM Run from the script's own directory so the relative driver path
REM (and the %CD%-based binPath below) resolve regardless of caller CWD.
cd /d "%~dp0"

echo Installing Kernel Race Condition Fuzzing Driver...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as administrator - OK
) else (
    echo This script must be run as administrator!
    pause
    exit /b 1
)

REM Check if driver exists
if not exist "objfre_win7_amd64\amd64\KernelFuzzer.sys" (
    echo Driver not found! Please build the driver first.
    echo Run: build.bat
    pause
    exit /b 1
)

REM Stop driver if already running
echo Stopping existing driver...
sc stop KernelFuzzer >nul 2>&1

REM Delete existing driver
echo Removing existing driver...
sc delete KernelFuzzer >nul 2>&1

REM Create driver service
echo Creating driver service...
sc create KernelFuzzer type= kernel binPath= "%CD%\objfre_win7_amd64\amd64\KernelFuzzer.sys" start= demand

if %ERRORLEVEL% NEQ 0 (
    echo Failed to create driver service!
    pause
    exit /b 1
)

REM Start driver
echo Starting driver...
sc start KernelFuzzer

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Driver installed and started successfully!
    echo.
    echo Driver status:
    sc query KernelFuzzer
    echo.
    echo To test the driver:
    echo   python client.py
    echo.
    echo To uninstall the driver:
    echo   sc stop KernelFuzzer
    echo   sc delete KernelFuzzer
) else (
    echo Failed to start driver!
    echo Check the Windows Event Log for details.
    pause
    exit /b 1
)

pause
