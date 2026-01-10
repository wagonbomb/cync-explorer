@echo off
echo ======================================================================
echo BASELINE TEST 1: CONNECTIVITY
echo ======================================================================
echo.

cd /d "%~dp0\.."

echo Ensuring dependencies are installed...
python -m pip install -q -r requirements.txt

echo.
echo Running connectivity baseline test...
echo.
python tests\test_01_connectivity.py

echo.
pause
