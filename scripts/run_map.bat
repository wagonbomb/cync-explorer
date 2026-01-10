@echo off
cd /d "%~dp0\.."
echo Mapping UUIDs...
python src\map_uuid.py
pause
