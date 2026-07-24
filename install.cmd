@echo off
REM cloakline one-command installer for Windows CMD.
REM From this repo's root, just type:  install
REM
REM All flags passed through to bootstrap.ps1, e.g.:
REM   install -SkipBuild
REM   install -SkipTrust
REM
REM UAC elevation is handled inside bootstrap.ps1 — if you're not already
REM admin, Windows will show one prompt and open an elevated window that
REM runs the install; this window will wait for it to finish.

setlocal
set "SCRIPT=%~dp0scripts\bootstrap.ps1"
if not exist "%SCRIPT%" (
    echo cloakline: %SCRIPT% not found. Are you in the repo root?
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
endlocal
