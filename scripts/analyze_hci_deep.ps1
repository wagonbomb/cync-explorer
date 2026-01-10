# Deep HCI Analysis - Look for keys and credentials
# Focus on finding encryption/network parameters

$root = Join-Path $PSScriptRoot ".."
$hciPath = Join-Path $root "artifacts\\outputs\\hci_analysis.json"
$hciData = Get-Content $hciPath | ConvertFrom-Json

Write-Host "="*60
Write-Host "DEEP HCI ANALYSIS - SEARCHING FOR KEYS"
Write-Host "="*60
Write-Host ""

# Look for notifications (device responses)
$notifications = $hciData | Where-Object { $_.type -like "*NOTIFY*" }
Write-Host "Found $($notifications.Count) notifications from device`n"

Write-Host "First 10 device responses:"
Write-Host "-"*60
$notifications | Select-Object -First 10 | ForEach-Object {
    Write-Host ("Frame {0,4}: Handle {1} -> {2}" -f $_.frame, $_.handle, $_.data)
}

Write-Host "`n"
Write-Host "="*60
Write-Host "LOOKING FOR SESSION ESTABLISHMENT PATTERN"
Write-Host "="*60
Write-Host ""

# Find write-notify pairs (command followed by response)
$writeCommands = $hciData | Where-Object { $_.type -like "*WRITE*" }
$pairings = @()

foreach ($write in $writeCommands | Select-Object -First 20) {
    # Look for notification within next 10 frames
    $nextNotif = $notifications | Where-Object { 
        $_.frame -gt $write.frame -and $_.frame -lt ($write.frame + 10)
    } | Select-Object -First 1
    
    if ($nextNotif) {
        Write-Host "Command-Response Pair:"
        Write-Host "  TX (Frame $($write.frame)): $($write.data)"
        Write-Host "  RX (Frame $($nextNotif.frame)): $($nextNotif.data)"
        Write-Host ""
    }
}

Write-Host "="*60
Write-Host "SEARCHING FOR ENCRYPTION INDICATORS"
Write-Host "="*60
Write-Host ""

# Look for long data payloads (likely encrypted)
$longWrites = $hciData | Where-Object { 
    $_.type -like "*WRITE*" -and $_.data.Length -gt 20 
}

Write-Host "Found $($longWrites.Count) long payloads (possibly encrypted)"
Write-Host "`nFirst 5 long payloads:"
Write-Host "-"*60
$longWrites | Select-Object -First 5 | ForEach-Object {
    $len = $_.data.Length / 2
    Write-Host ("Frame {0}: {1} bytes -> {2}..." -f $_.frame, $len, $_.data.Substring(0, [Math]::Min(40, $_.data.Length)))
}

Write-Host "`n"
Write-Host "="*60
Write-Host "RECOMMENDATION"
Write-Host "="*60
Write-Host ""
Write-Host "The device appears to require:"
Write-Host "  1. Mesh network membership (encryption keys)"
Write-Host "  2. Proper session establishment we haven't achieved"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  A) Factory reset the bulb and provision it fresh"
Write-Host "  B) Live BLE sniffing while using official app"
Write-Host "  C) Analyze notification responses for key exchange"
