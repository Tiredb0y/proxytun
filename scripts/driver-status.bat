@echo off
REM Shows whether the WinDivert kernel driver service currently exists / is running.
sc query WinDivert
if errorlevel 1 echo (The WinDivert driver service is not installed - this is the normal state while routing is stopped.)
