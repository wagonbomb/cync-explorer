@echo off
REM Complete Cync APK Decompilation
REM This script runs the PowerShell decompilation script

echo ================================================================================
echo CYNC APK COMPLETE DECOMPILATION
echo ================================================================================
echo.
echo This will fully decompile the Cync APK using APKTool
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0complete_decompile.ps1"

echo.
echo Press any key to exit...
pause >nul
