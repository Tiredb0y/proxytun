@echo off
REM Stops and removes the WinDivert kernel driver service. Safe to run at any time (routing must be stopped).
net session >nul 2>&1 || (echo Please run this script as Administrator. & exit /b 1)
echo Stopping WinDivert driver...
sc stop WinDivert >nul 2>&1
echo Removing WinDivert driver service...
sc delete WinDivert >nul 2>&1
sc query WinDivert >nul 2>&1 && (echo Driver service still present - it will be removed after a reboot.) || echo WinDivert driver removed.
exit /b 0
