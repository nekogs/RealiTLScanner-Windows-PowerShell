@echo off
rem Double-click launcher for RealiTLScanner.ps1: runs it without changing
rem the execution policy and asks for an address when started without arguments.
setlocal
if "%~1"=="" set "RTS_LAUNCHER=1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0RealiTLScanner.ps1" %*
set "code=%errorlevel%"
rem keep the window open when PowerShell failed before the script could pause
if "%RTS_LAUNCHER%"=="1" if "%code%"=="1" pause
exit /b %code%
