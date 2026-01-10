@echo off
echo ======================================================================
echo CYNC WEB CONTROLLER LAUNCHER
echo ======================================================================
echo.

cd /d "%~dp0\.."

echo 1. Installing dependencies (aiohttp, bleak)...
python -m pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ Failed to install dependencies!
    pause
    exit /b
)

echo.
echo 2. Starting Web Server...
echo    Open http://localhost:8080 in your browser
echo.

python src\cync_server.py

pause
