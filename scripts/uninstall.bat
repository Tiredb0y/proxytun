@echo off
REM Complete removal of everything App Proxy Manager may have installed on this PC:
REM   1. WinDivert driver service   2. Windows Firewall rule   3. "launch at sign-in" scheduled task
REM   4. (optional) settings and logs.   Delete the program folder yourself afterwards.
net session >nul 2>&1 || (echo Please run this script as Administrator. & exit /b 1)

taskkill /im AppProxyManager.exe /f >nul 2>&1
call "%~dp0uninstall-driver.bat"
netsh advfirewall firewall delete rule name="App Proxy Manager (local redirector)" >nul 2>&1 && echo Firewall rule removed.
schtasks /Delete /TN "App Proxy Manager" /F >nul 2>&1 && echo Sign-in task removed.

set /p ANS=Also delete saved settings and logs (%APPDATA%\AppProxyManager, %LOCALAPPDATA%\AppProxyManager)? [y/N] 
if /i "%ANS%"=="y" (
  rmdir /s /q "%APPDATA%\AppProxyManager" 2>nul
  rmdir /s /q "%LOCALAPPDATA%\AppProxyManager" 2>nul
  echo Settings and logs deleted.
)
echo Done. Windows proxy settings were never modified by this program.
exit /b 0
