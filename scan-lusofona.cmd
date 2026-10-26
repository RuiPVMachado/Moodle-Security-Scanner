@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scan-lusofona.ps1" %*
set "CODE=%ERRORLEVEL%"
echo.
if "%CODE%"=="0" (
    echo Scan finished.
) else (
    echo Scan exited with code %CODE%.
)
pause
exit /b %CODE%
