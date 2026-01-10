@echo off
REM Launch Ghidra MCP Server

echo ============================================================================
echo GHIDRA MCP SERVER FOR CYNC BLE ANALYSIS
echo ============================================================================
echo.

cd /d "%~dp0\.."

REM Check if venv exists
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Install MCP if needed
echo Checking MCP installation...
.venv\Scripts\pip show mcp >nul 2>&1
if errorlevel 1 (
    echo Installing MCP SDK...
    .venv\Scripts\pip install mcp
    if errorlevel 1 (
        echo Error: Failed to install MCP
        pause
        exit /b 1
    )
)

echo.
echo Starting Ghidra MCP Server...
echo.
echo Available tools:
echo   - list_libraries: Show all .so files
echo   - analyze_library: Import and analyze a library with Ghidra
echo   - find_functions: Search for functions by pattern
echo   - get_function_decompile: Decompile a specific function
echo   - search_strings: Search for strings in a library
echo.
echo Server is running on stdio (for MCP clients)...
echo.

.venv\Scripts\python src\ghidra_mcp_server.py

echo.
echo Server stopped.
pause
