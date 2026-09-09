@echo off
REM Kernel Race Condition Fuzzing Driver Build Script

echo Building Kernel Race Condition Fuzzing Driver...

REM Check if WDK is installed
if not exist "C:\Program Files (x86)\Windows Kits\10\bin\x64\setenv.cmd" (
    echo Windows Driver Kit (WDK) not found!
    echo Please install WDK from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    pause
    exit /b 1
)

REM Set up build environment
call "C:\Program Files (x86)\Windows Kits\10\bin\x64\setenv.cmd" /Release /x64

REM Build the driver
build -ceZ

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful!
    echo Driver: %CD%\objfre_win7_amd64\amd64\KernelFuzzer.sys
    echo.
    echo To install the driver:
    echo   sc create KernelFuzzer type= kernel binPath= "%CD%\objfre_win7_amd64\amd64\KernelFuzzer.sys"
    echo   sc start KernelFuzzer
    echo.
    echo To uninstall the driver:
    echo   sc stop KernelFuzzer
    echo   sc delete KernelFuzzer
    echo.
    echo To test the driver:
    echo   python src\client.py
) else (
    echo.
    echo Build failed! Check the output above for errors.
    exit /b 1
)

pause
