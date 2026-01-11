@echo off
REM Cync DEX Analysis Pipeline - Entry Point
REM Runs JADX decompilation and generates structured markdown documentation

setlocal

set PYTHON=python
set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
set DEX_DIR=%PROJECT_ROOT%\artifacts\apk_extracted
set OUTPUT_DIR=%PROJECT_ROOT%\decomp
set ANALYZER=%PROJECT_ROOT%\scripts\dex_analysis\analyze_dex.py

echo ======================================================================
echo   Cync DEX Analysis Pipeline
echo ======================================================================
echo.
echo DEX Files:    %DEX_DIR%
echo Output:       %OUTPUT_DIR%
echo.

REM Check if Python is available
%PYTHON% --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found in PATH
    echo Please install Python 3.11+ or add it to PATH
    pause
    exit /b 1
)

REM Check if DEX files exist
if not exist "%DEX_DIR%\classes.dex" (
    echo ERROR: DEX files not found in %DEX_DIR%
    echo.
    echo Please ensure the Cync APK has been extracted.
    echo Expected files:
    echo   - classes.dex
    echo   - classes2.dex through classes8.dex
    echo.
    pause
    exit /b 1
)

REM Check if JADX exists
set JADX_PATH=%PROJECT_ROOT%\tools-local\jadx\bin\jadx.bat
if not exist "%JADX_PATH%" (
    echo ERROR: JADX not found at %JADX_PATH%
    echo.
    echo Please install JADX to tools-local\jadx\
    echo Download from: https://github.com/skylot/jadx/releases
    echo.
    pause
    exit /b 1
)

REM Create output directories if they don't exist
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%OUTPUT_DIR%\raw" mkdir "%OUTPUT_DIR%\raw"

REM Parse command line arguments
set MODE=full
set VERBOSE=

:parse_args
if "%~1"=="" goto end_parse
if /i "%~1"=="--test" set MODE=test
if /i "%~1"=="-v" set VERBOSE=-v
if /i "%~1"=="--verbose" set VERBOSE=-v
shift
goto parse_args
:end_parse

REM Run the analysis
echo.
echo Starting analysis...
echo.

if "%MODE%"=="test" (
    echo TEST MODE: Processing only classes7.dex for quick validation
    echo.
    %PYTHON% "%ANALYZER%" --test %VERBOSE%
) else (
    echo FULL MODE: Processing all 8 DEX files
    echo This will take approximately 25-30 minutes.
    echo.
    %PYTHON% "%ANALYZER%" %VERBOSE%
)

if %ERRORLEVEL% neq 0 (
    echo.
    echo ======================================================================
    echo ERROR: Analysis failed. See errors above.
    echo ======================================================================
    echo.
    pause
    exit /b %ERRORLEVEL%
)

REM Display results
echo.
echo ======================================================================
echo   Analysis Complete!
echo ======================================================================
echo.
echo Generated files:
if "%MODE%"=="test" (
    echo   %OUTPUT_DIR%\classes7.md
) else (
    echo   %OUTPUT_DIR%\INDEX.md
    echo   %OUTPUT_DIR%\BLE_REFERENCE.md
    echo   %OUTPUT_DIR%\SEARCH_GUIDE.md
    echo   %OUTPUT_DIR%\classes1.md through classes8.md
)
echo.
echo   Raw Java source: %OUTPUT_DIR%\raw\
echo.
echo Next steps:
echo   1. Open %OUTPUT_DIR%\INDEX.md to start exploring
echo   2. Check BLE_REFERENCE.md for protocol findings
echo   3. Use SEARCH_GUIDE.md for navigation tips
echo.

REM Open INDEX.md in default markdown viewer (optional)
if exist "%OUTPUT_DIR%\INDEX.md" (
    choice /C YN /M "Open INDEX.md now"
    if %ERRORLEVEL%==1 (
        start "" "%OUTPUT_DIR%\INDEX.md"
    )
)

echo ======================================================================
pause
