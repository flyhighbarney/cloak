@echo off
REM cloakline uninstaller for Windows CMD.
REM From this repo's root, just type:  uninstall

setlocal
set "SCRIPT=%~dp0scripts\uninstall.ps1"
if not exist "%SCRIPT%" (
    echo cloakline: %SCRIPT% not found. Are you in the repo root?
    exit /b 1
)

REM uninstall.ps1 requires admin — self-elevate via PowerShell.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%SCRIPT%' -Wait"
endlocal
