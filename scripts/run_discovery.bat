@echo off
echo ======================================================================
echo DISCOVERY AND CONTROL ITERATION LOOP
echo Target: 34:13:43:46:CA:84
echo ======================================================================
echo.
echo This will systematically try multiple approaches:
echo   1. Pairing/Bonding
echo   2. Commands after pairing
echo   3. Brute force prefix discovery
echo   4. Initial notification analysis
echo   5. Read all characteristics
echo   6. Legacy Telink commands
echo.
echo Results will be saved to discovery_results.json
echo.
pause

cd /d "%~dp0\.."

python -m pip install -q -r requirements.txt

echo.
echo Starting discovery loop...
echo.
python src\discovery_loop.py

echo.
echo.
echo ======================================================================
echo Discovery complete! Check discovery_results.json for full results.
echo ======================================================================
pause
