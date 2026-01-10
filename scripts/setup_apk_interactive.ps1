# Step-by-step APK setup with progress updates

$repoRoot = Join-Path $PSScriptRoot ".."
$toolsDir = Join-Path $repoRoot "tools-local"
$artifactsDir = Join-Path $repoRoot "artifacts"
$apkPath = Join-Path $artifactsDir "com.ge.cbyge.apk"
$jadxDir = Join-Path $toolsDir "jadx"
$decompiledDir = Join-Path $artifactsDir "cync_decompiled"

Write-Host "=" * 60
Write-Host "CYNC APK REVERSE ENGINEERING - STEP BY STEP"
Write-Host "=" * 60
Write-Host ""

# Step 1: Check Java
Write-Host "[Step 1/5] Checking Java..." -ForegroundColor Cyan
try {
    $javaVersion = java -version 2>&1 | Select-String "version"
    Write-Host "  OK Java is installed: $javaVersion" -ForegroundColor Green
} catch {
    Write-Host "  Java not found. Installing..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Opening download page: https://adoptium.net/temurin/releases/"
    Start-Process "https://adoptium.net/temurin/releases/"
    Write-Host ""
    Write-Host "  Please:"
    Write-Host "  1. Download 'Windows x64 JDK .msi' (Java 17 or later)"
    Write-Host "  2. Install it"
    Write-Host "  3. Press Enter to continue..."
    Read-Host
}

# Step 2: Download jadx
Write-Host ""
Write-Host "[Step 2/5] Setting up jadx decompiler..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
Set-Location $toolsDir

if (!(Test-Path $jadxDir)) {
    Write-Host "  Downloading jadx..."
    Invoke-WebRequest -Uri "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip" -OutFile "jadx.zip"
    Write-Host "  Extracting..."
    Expand-Archive -Path jadx.zip -DestinationPath $jadxDir -Force
    Remove-Item jadx.zip
    Write-Host "  OK jadx installed" -ForegroundColor Green
} else {
    Write-Host "  OK jadx already installed" -ForegroundColor Green
}

# Step 3: Download APK
Write-Host ""
Write-Host "[Step 3/5] Getting Cync APK..." -ForegroundColor Cyan

if (Test-Path $apkPath) {
    Write-Host "  OK com.ge.cbyge.apk found" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  Opening APKMirror download page..."
    Start-Process "https://www.apkmirror.com/apk/ge-lighting/"
    Write-Host ""
    Write-Host "  Please:"
    Write-Host "  1. Search for 'Cync'"
    Write-Host "  2. Download the latest version"
    Write-Host "  3. Save it as: $apkPath"
    Write-Host ""
    Write-Host "  Press Enter once downloaded..."
    Read-Host
    
    if (!(Test-Path $apkPath)) {
        Write-Host "  APK not found! Please try again." -ForegroundColor Red
        exit 1
    }
    Write-Host "  OK com.ge.cbyge.apk found" -ForegroundColor Green
}

# Step 4: Decompile
Write-Host ""
Write-Host "[Step 4/5] Decompiling APK (2-5 minutes)..." -ForegroundColor Cyan

if (!(Test-Path $decompiledDir)) {
    & (Join-Path $jadxDir "bin\\jadx.bat") -d $decompiledDir $apkPath
    Write-Host "  OK Decompilation complete" -ForegroundColor Green
} else {
    Write-Host "  OK Already decompiled" -ForegroundColor Green
}

# Step 5: Search
Write-Host ""
Write-Host "[Step 5/5] Searching for provisioning code..." -ForegroundColor Cyan
Set-Location $repoRoot
python src\apk_search.py $decompiledDir

Write-Host ""
Write-Host "=" * 60
Write-Host "SETUP COMPLETE!" -ForegroundColor Green
Write-Host "=" * 60
Write-Host ""
Write-Host "Results saved to: artifacts\\outputs\\apk_search_results.txt"
Write-Host ""
Write-Host "To browse manually:"
Write-Host "  $(Join-Path $jadxDir 'bin\\jadx-gui.bat') $apkPath"
Write-Host ""
