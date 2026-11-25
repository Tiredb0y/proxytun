@echo off
call :main
set RC=%errorlevel%
echo.
if not "%RC%"=="0" (echo ===== FAILED with exit code %RC% - copy the text above and send it =====) else (echo ===== finished OK =====)
pause
exit /b %RC%

:main
setlocal
REM Produces a standalone (self-contained, no .NET install needed) Windows x64 build in dist\ and a zip file.
cd /d "%~dp0"

where dotnet >nul 2>nul || (echo [ERROR] .NET SDK 8 or newer not found. & exit /b 1)
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\fetch-windivert.ps1" -VerifyOnly || exit /b 1

if exist dist rmdir /s /q dist
dotnet publish src\AppProxyManager.UI\AppProxyManager.UI.csproj -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=false -p:DebugType=None -o dist\AppProxyManager -nologo || exit /b 1

REM WinDivert.dll / WinDivert64.sys must sit next to the exe (not single-file); fail loudly if they are missing
if not exist dist\AppProxyManager\WinDivert.dll (echo [ERROR] WinDivert.dll missing from publish output & exit /b 1)
if not exist dist\AppProxyManager\WinDivert64.sys (echo [ERROR] WinDivert64.sys missing from publish output & exit /b 1)

mkdir dist\AppProxyManager\scripts
copy /y scripts\*.bat dist\AppProxyManager\scripts\ >nul
copy /y scripts\*.ps1 dist\AppProxyManager\scripts\ >nul
copy /y README.md dist\AppProxyManager\ >nul

powershell -NoProfile -Command "Compress-Archive -Path 'dist\AppProxyManager\*' -DestinationPath 'dist\AppProxyManager-win-x64.zip' -Force"
echo.
echo Published to dist\AppProxyManager and dist\AppProxyManager-win-x64.zip
exit /b 0
