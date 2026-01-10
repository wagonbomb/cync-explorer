@echo off
echo ======================================================================
echo BASELINE TEST 4: NOTIFICATION TESTING
echo Target: 34:13:43:46:CA:84
echo ======================================================================
echo.

cd /d "%~dp0\.."

echo Ensuring dependencies are installed...
python -m pip install -q -r requirements.txt

echo.
echo Running notification test...
echo.
python tests\test_04_notifications.py

echo.
pause
