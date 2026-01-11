@echo off
echo ============================================================
echo BlueStacks Cync Protocol Capture Setup
echo ============================================================
echo.

REM Check for ADB
where adb >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] ADB not found in PATH
    echo.
    echo Please install Android SDK Platform Tools:
    echo https://developer.android.com/studio/releases/platform-tools
    echo.
    echo Or add BlueStacks ADB to PATH:
    echo "C:\Program Files\BlueStacks_nxt\HD-Adb.exe"
    echo.
    pause
    exit /b 1
)

echo [1] Checking ADB connection to BlueStacks...
adb devices

echo.
echo [2] If BlueStacks is not listed, make sure:
echo     - BlueStacks is running
echo     - ADB is enabled in BlueStacks settings
echo     - Try: adb connect localhost:5555
echo.

set /p CONTINUE="Press Enter to continue with APK installation..."

echo.
echo [3] Installing Cync APK...
adb install "artifacts\com.ge.cbyge_6.20.0.54634-60b11b1f5-114634_minAPI26(arm64-v8a,armeabi-v7a)(nodpi).apk"

echo.
echo [4] Checking Frida tools...
pip show frida-tools >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing Frida tools...
    pip install frida-tools
)

echo.
echo ============================================================
echo Setup complete!
echo.
echo Next steps:
echo 1. Open Cync app in BlueStacks
echo 2. Run: frida -U -f com.ge.cbyge -l scripts\frida_ble_hook.js
echo 3. Pair a device in the app while Frida captures traffic
echo ============================================================
pause
