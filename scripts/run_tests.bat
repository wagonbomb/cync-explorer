@echo off
echo ======================================================================
echo CYNC BLE SCANNER TEST SUITE
echo ======================================================================
echo.

cd /d "%~dp0\.."
python tests\test_ble_scanner.py

echo.
echo ======================================================================
echo Press any key to exit...
pause > nul
