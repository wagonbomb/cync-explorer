@echo off
echo ========================================
echo Cync APK Reverse Engineering Setup
echo ========================================
echo.
set REPO_ROOT=%~dp0..
set TOOLS_DIR=%REPO_ROOT%\tools-local
set ARTIFACTS_DIR=%REPO_ROOT%\artifacts

REM Check Java installation
echo [1/4] Checking Java installation...
java -version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Java not found!
    echo Please install Java 17+ from: https://adoptium.net/temurin/releases/
    echo.
    pause
    exit /b 1
)
echo     OK Java found

REM Download jadx
echo.
echo [2/4] Downloading jadx decompiler...
cd /d "%TOOLS_DIR%"

if not exist "jadx" (
    echo     Downloading...
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip' -OutFile 'jadx.zip'"
    echo     Extracting...
    powershell -Command "Expand-Archive -Path jadx.zip -DestinationPath jadx -Force"
    del jadx.zip
    echo     OK jadx installed
) else (
    echo     OK jadx already installed
)

REM Check for APK
echo.
echo [3/4] Checking for Cync APK...
if exist "%ARTIFACTS_DIR%\com.ge.cbyge.apk" (
    echo     OK Found com.ge.cbyge.apk
) else (
    echo.
    echo     APK not found. Please download Cync APK:
    echo     1. Visit: https://www.apkmirror.com/apk/ge-lighting/
    echo     2. Search for "Cync"
    echo     3. Download latest APK
    echo     4. Save to: %ARTIFACTS_DIR%\com.ge.cbyge.apk
    echo.
    echo     Press any key once you've downloaded it...
    pause >nul
    
    if not exist "%ARTIFACTS_DIR%\com.ge.cbyge.apk" (
        echo     ERROR: com.ge.cbyge.apk still not found!
        pause
        exit /b 1
    )
)

REM Decompile APK
echo.
echo [4/4] Decompiling APK (this may take 2-5 minutes)...
if not exist "%ARTIFACTS_DIR%\cync_decompiled" (
    "%TOOLS_DIR%\jadx\bin\jadx.bat" -d "%ARTIFACTS_DIR%\cync_decompiled" "%ARTIFACTS_DIR%\com.ge.cbyge.apk"
    echo     OK Decompilation complete
) else (
    echo     OK Already decompiled
)

REM Run search
echo.
echo ========================================
echo Running APK search...
echo ========================================
cd /d "%REPO_ROOT%"
python src\apk_search.py "%ARTIFACTS_DIR%\cync_decompiled"

echo.
echo ========================================
echo Setup complete!
echo ========================================
echo.
echo Next steps:
echo 1. Review: artifacts\outputs\apk_search_results.txt
echo 2. Open jadx-gui for manual inspection:
echo    %TOOLS_DIR%\jadx\bin\jadx-gui.bat %ARTIFACTS_DIR%\com.ge.cbyge.apk
echo.
pause
