@echo off
call :main
set RC=%errorlevel%
echo.
if not "%RC%"=="0" (echo ===== FAILED with exit code %RC% - copy the text above and send it =====) else (echo ===== finished OK =====)
pause
exit /b %RC%

:main
setlocal
REM Builds App Proxy Manager (Release), verifies the bundled WinDivert files and runs the automated tests.
cd /d "%~dp0"

where dotnet >nul 2>nul || (echo [ERROR] .NET SDK 8 or newer not found. Install it from https://dotnet.microsoft.com/download & exit /b 1)

echo == Verifying bundled WinDivert 2.2.2 binaries ==
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\fetch-windivert.ps1" -VerifyOnly || exit /b 1

echo == Building ==
dotnet build AppProxyManager.sln -c Release -nologo || exit /b 1

echo == Running automated tests ==
dotnet run --project tests\AppProxyManager.Tests -c Release --no-build || exit /b 1

echo.
echo Build OK. Run: src\AppProxyManager.UI\bin\Release\net8.0-windows\AppProxyManager.exe
exit /b 0
