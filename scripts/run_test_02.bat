@echo off
echo ======================================================================
echo BASELINE TEST 2: CHARACTERISTIC DISCOVERY
echo Target: 34:13:43:46:CA:85
echo ======================================================================
echo.

cd /d "%~dp0\.."

echo Ensuring dependencies are installed...
python -m pip install -q -r requirements.txt

echo.
echo Running characteristic discovery test...
echo.
python tests\test_02_characteristics.py

echo.
pause
