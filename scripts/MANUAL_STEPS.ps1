# Manual APK Reverse Engineering Steps
# Copy and paste these commands one at a time

$repoRoot = Join-Path $PSScriptRoot ".."
$toolsDir = Join-Path $repoRoot "tools-local"
$artifactsDir = Join-Path $repoRoot "artifacts"
$apkPath = Join-Path $artifactsDir "com.ge.cbyge.apk"
$decompiledDir = Join-Path $artifactsDir "cync_decompiled"
$jadxDir = Join-Path $toolsDir "jadx"

# Step 1: Check if Java is installed
java -version

# If Java is NOT installed:
# 1. Open browser and go to: https://adoptium.net/temurin/releases/
# 2. Download "Windows x64 JDK .msi" (Java 17)
# 3. Install it
# 4. Close and reopen PowerShell
# 5. Run: java -version (to verify)

# Step 2: Download jadx
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
Set-Location $toolsDir
Invoke-WebRequest -Uri "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip" -OutFile "jadx.zip"
Expand-Archive -Path jadx.zip -DestinationPath $jadxDir -Force
Remove-Item jadx.zip

# Step 3: Get Cync APK
# Open this URL in your browser:
Start-Process "https://www.apkmirror.com/apk/ge-lighting/"
# Then:
# 1. Search for "Cync"
# 2. Click latest version
# 3. Download APK
# 4. Save to: $apkPath

# Step 4: Verify APK is downloaded
Test-Path $apkPath
# Should return: True

# Step 5: Decompile APK (takes 2-5 minutes)
& (Join-Path $jadxDir "bin\\jadx.bat") -d $decompiledDir $apkPath

# Step 6: Search for code
Set-Location $repoRoot
python src\apk_search.py $decompiledDir

# Step 7: View results
notepad (Join-Path $artifactsDir "outputs\\apk_search_results.txt")

# ALTERNATIVE: Browse with GUI
& (Join-Path $jadxDir "bin\\jadx-gui.bat") $apkPath
# Then press Ctrl+Shift+F and search for: telink_mesh1
