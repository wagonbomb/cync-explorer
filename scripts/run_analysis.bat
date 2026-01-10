@echo off
cd /d "%~dp0"
echo Running HCI Analysis in PowerShell...
powershell -ExecutionPolicy Bypass -File analyze_hci.ps1
pause
