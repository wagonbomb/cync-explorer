# Complete APK Decompilation Script for Cync APK
# This ensures ALL DEX files are extracted and decompiled

param(
    [string]$ApkPath = "",
    [string]$OutputDir = "",
    [string]$ApktoolJar = ""
)

$RepoRoot = Join-Path $PSScriptRoot ".."
if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot "artifacts\\cync_smali_full"
}
if (-not $ApktoolJar) {
    $ApktoolJar = Join-Path $RepoRoot "tools-local\\apktool.jar"
}
if (-not $ApkPath) {
    $defaultApk = Join-Path $RepoRoot "artifacts\\com.ge.cbyge.apk"
    if (Test-Path $defaultApk) {
        $ApkPath = $defaultApk
    } else {
        $apkCandidates = Get-ChildItem -Path (Join-Path $RepoRoot "artifacts") -Filter "*.apk" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending
        if ($apkCandidates) {
            $ApkPath = $apkCandidates[0].FullName
        }
    }
}

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "COMPLETE CYNC APK DECOMPILATION" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan

# Check prerequisites
Write-Host "`n[1/5] Checking prerequisites..." -ForegroundColor Yellow

if (-not (Test-Path $ApkPath)) {
    Write-Host "❌ APK not found: $ApkPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please download the Cync APK first:" -ForegroundColor Yellow
    Write-Host "  1. Go to: https://apkcombo.com/cync/com.ge.cbyge/" -ForegroundColor White
    Write-Host "  2. Download the latest version" -ForegroundColor White
    Write-Host "  3. Save as: $ApkPath" -ForegroundColor White
    Write-Host ""
    exit 1
}

if (-not (Test-Path $ApktoolJar)) {
    Write-Host "❌ APKTool not found: $ApktoolJar" -ForegroundColor Red
    Write-Host ""
    Write-Host "Downloading APKTool..." -ForegroundColor Yellow
    $DownloadUrl = "https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ApktoolJar
    Write-Host "✅ APKTool downloaded" -ForegroundColor Green
}

# Check Java
Write-Host "Checking Java installation..." -ForegroundColor White
try {
    $javaVersion = java -version 2>&1 | Select-String "version"
    Write-Host "✅ Java found: $javaVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Java not found. Please install Java 17+" -ForegroundColor Red
    exit 1
}

# Get APK info
Write-Host "`n[2/5] Analyzing APK..." -ForegroundColor Yellow
$apkSize = (Get-Item $ApkPath).Length / 1MB
Write-Host "  APK Size: $([math]::Round($apkSize, 2)) MB" -ForegroundColor White
Write-Host "  Path: $ApkPath" -ForegroundColor White

# Remove old decompilation if exists
if (Test-Path $OutputDir) {
    Write-Host "`n[3/5] Removing old decompilation..." -ForegroundColor Yellow
    Remove-Item -Path $OutputDir -Recurse -Force
    Write-Host "✅ Old files removed" -ForegroundColor Green
} else {
    Write-Host "`n[3/5] No old files to remove" -ForegroundColor Yellow
}

# Run APKTool with full decompilation
Write-Host "`n[4/5] Running APKTool (this may take several minutes)..." -ForegroundColor Yellow
Write-Host "  This will decompile ALL DEX files (classes.dex, classes2.dex, etc.)" -ForegroundColor White
Write-Host ""

$startTime = Get-Date

# Run with verbose output to see progress
$apktoolArgs = @(
    "-jar", $ApktoolJar,
    "d",  # decode
    "-f",  # force overwrite
    "-o", $OutputDir,  # output directory
    $ApkPath
)

Write-Host "Command: java $($apktoolArgs -join ' ')" -ForegroundColor DarkGray
Write-Host ""

$process = Start-Process -FilePath "java" -ArgumentList $apktoolArgs -NoNewWindow -Wait -PassThru

$endTime = Get-Date
$duration = $endTime - $startTime

if ($process.ExitCode -eq 0) {
    Write-Host "✅ Decompilation completed in $($duration.TotalSeconds) seconds" -ForegroundColor Green
} else {
    Write-Host "❌ Decompilation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
    exit 1
}

# Analyze results
Write-Host "`n[5/5] Analyzing decompiled code..." -ForegroundColor Yellow

if (Test-Path $OutputDir) {
    # Count smali directories (indicates multi-DEX)
    $smaliDirs = Get-ChildItem -Path $OutputDir -Directory -Filter "smali*"
    Write-Host "  Smali directories: $($smaliDirs.Count)" -ForegroundColor White
    foreach ($dir in $smaliDirs) {
        $fileCount = (Get-ChildItem -Path $dir.FullName -Recurse -Filter "*.smali").Count
        Write-Host "    - $($dir.Name): $fileCount files" -ForegroundColor Cyan
    }
    
    # Total file count
    $totalSmaliFiles = (Get-ChildItem -Path $OutputDir -Recurse -Filter "*.smali").Count
    Write-Host "`n  Total .smali files: $totalSmaliFiles" -ForegroundColor Green
    
    # Check for key files
    Write-Host "`n  Key files:" -ForegroundColor White
    if (Test-Path "$OutputDir\AndroidManifest.xml") {
        Write-Host "    ✅ AndroidManifest.xml" -ForegroundColor Green
    }
    if (Test-Path "$OutputDir\res") {
        Write-Host "    ✅ Resources directory" -ForegroundColor Green
    }
    
    # Estimate original class count
    Write-Host "`n  Original APK had ~85,000 classes" -ForegroundColor White
    $percentage = [math]::Round(($totalSmaliFiles / 85000) * 100, 1)
    Write-Host "  Decompiled: $percentage% of classes" -ForegroundColor $(if ($percentage -gt 90) { "Green" } else { "Yellow" })
    
    if ($percentage -lt 50) {
        Write-Host "`n  ⚠️  Warning: Less than 50% of classes extracted!" -ForegroundColor Yellow
        Write-Host "  The APK may use resource compression or protection" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Output directory not created!" -ForegroundColor Red
    exit 1
}

Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "DECOMPILATION COMPLETE" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Output location: $OutputDir" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run: python explore_ble_code.py" -ForegroundColor White
Write-Host "  2. Search for UUID '2b11' (Mesh Provisioning In)" -ForegroundColor White
Write-Host "  3. Look for BluetoothGatt.writeCharacteristic calls" -ForegroundColor White
Write-Host ""
