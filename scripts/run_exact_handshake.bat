@echo off
cd /d "%~dp0\.."
python tests\test_exact_handshake.py
pause
