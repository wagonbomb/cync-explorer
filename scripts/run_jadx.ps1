$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-25.0.1.8-hotspot"
$env:PATH = "C:\Program Files\Eclipse Adoptium\jdk-25.0.1.8-hotspot\bin;" + $env:PATH

$repoRoot = Join-Path $PSScriptRoot ".."
$apkPath = Join-Path $repoRoot "artifacts\\com.ge.cbyge.apk"
$outputPath = Join-Path $repoRoot "artifacts\\cync_decompiled"
$jadxPath = Join-Path $repoRoot "tools-local\\jadx\\bin\\jadx.bat"

Write-Host "Starting jadx decompilation..."
Write-Host "APK: $apkPath"
Write-Host "Output: $outputPath"
Write-Host ""

& $jadxPath -d $outputPath $apkPath
