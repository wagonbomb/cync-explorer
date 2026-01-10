# Download Cync APK from APKCombo
# This script downloads the latest Cync APK for decompilation

param(
    [string]$OutputPath = ""
)

$RepoRoot = Join-Path $PSScriptRoot ".."
if (-not $OutputPath) {
    $OutputPath = Join-Path $RepoRoot "artifacts\\com.ge.cbyge.apk"
}

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "CYNC APK DOWNLOADER" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Check if already downloaded
if (Test-Path $OutputPath) {
    $size = (Get-Item $OutputPath).Length / 1MB
    Write-Host "✅ APK already exists: $OutputPath" -ForegroundColor Green
    Write-Host "   Size: $([math]::Round($size, 2)) MB" -ForegroundColor White
    Write-Host ""
    $overwrite = Read-Host "Download again? (y/N)"
    if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
        Write-Host "Keeping existing file" -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "Package: com.ge.cbyge (Cync - Smart Home)" -ForegroundColor White
Write-Host ""
Write-Host "Since direct APK download requires browser interaction," -ForegroundColor Yellow
Write-Host "please follow these manual steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Open your browser and go to:" -ForegroundColor Cyan
Write-Host "   https://apkcombo.com/cync/com.ge.cbyge/" -ForegroundColor White
Write-Host ""
Write-Host "2. Click the green 'Download APK' button" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Select 'Latest Version' (should be 6.20.0 or newer)" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Download the APK file" -ForegroundColor Cyan
Write-Host ""
Write-Host "5. Save it as:" -ForegroundColor Cyan
Write-Host "   $OutputPath" -ForegroundColor White
Write-Host ""
Write-Host "Alternative download sites:" -ForegroundColor Yellow
Write-Host "  - APKPure: https://apkpure.com/cync/com.ge.cbyge" -ForegroundColor White
Write-Host "  - APKMirror: https://www.apkmirror.com/apk/ge-lighting/" -ForegroundColor White
Write-Host ""
Write-Host "Once downloaded, run: .\run_complete_decompile.bat" -ForegroundColor Green
Write-Host ""

# Try to open the browser
Write-Host "Opening download page in browser..." -ForegroundColor Yellow
Start-Process "https://apkcombo.com/cync/com.ge.cbyge/"

Write-Host ""
Write-Host "Waiting for download..." -ForegroundColor Yellow
Write-Host "Press Enter when you've downloaded the APK to: $OutputPath" -ForegroundColor White
Read-Host

# Verify download
if (Test-Path $OutputPath) {
    $size = (Get-Item $OutputPath).Length / 1MB
    Write-Host ""
    Write-Host "✅ APK found!" -ForegroundColor Green
    Write-Host "   Size: $([math]::Round($size, 2)) MB" -ForegroundColor White
    
    if ($size -lt 50) {
        Write-Host ""
        Write-Host "⚠️  Warning: APK seems small (expected ~175 MB)" -ForegroundColor Yellow
        Write-Host "   Make sure you downloaded the full APK, not a stub" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Next step: Run complete decompilation" -ForegroundColor Green
    Write-Host "Command: .\run_complete_decompile.bat" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "❌ APK not found at: $OutputPath" -ForegroundColor Red
    Write-Host "   Please download and save it to the correct location" -ForegroundColor Yellow
}

Write-Host ""
