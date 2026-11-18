@echo off
setlocal
set "script=%~dp0find_spotify_ip.py"
if not exist "%script%" (
    echo Place this launcher in the same folder as find_spotify_ip.py.
    set "result=2"
    goto finish
)

if "%~1"=="" (
    set "SPOTIFY_SEARCH_LAUNCHER=%~f0"
    powershell.exe -NoProfile -NonInteractive -Command "try { Start-Process -FilePath $env:SPOTIFY_SEARCH_LAUNCHER -ArgumentList '--apply' -Verb RunAs -ErrorAction Stop } catch { Write-Error $_; exit 2 }"
    if not errorlevel 1 exit /b 0
    set "result=2"
    goto finish
)

py -3 -u "%script%" %*
set "result=%errorlevel%"

:finish
echo.
pause
exit /b %result%
