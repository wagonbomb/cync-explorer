# HCI Log Analyzer - Extract exact commands from working session
# Run this in PowerShell

Write-Host "="*60
Write-Host "HCI LOG ANALYZER"
Write-Host "="*60
Write-Host ""

# Load HCI analysis
$root = Join-Path $PSScriptRoot ".."
$hciPath = Join-Path $root "artifacts\\outputs\\hci_analysis.json"
$hciData = Get-Content $hciPath | ConvertFrom-Json

# Filter for writes to mesh characteristics
# Handle 0x0025 = Mesh Provisioning In (33 decimal)
# Handle 0x0027 = Mesh Proxy In (39 decimal)
$meshWrites = $hciData | Where-Object { 
    $_.type -like "*WRITE*" -and 
    ($_.handle -eq "0x0025" -or $_.handle -eq "0x0027")
}

Write-Host "Found $($meshWrites.Count) writes to Mesh characteristics`n"

Write-Host "First 30 commands:"
Write-Host "-"*60

$meshWrites | Select-Object -First 30 | ForEach-Object {
    $handleName = if ($_.handle -eq "0x0025") { "PROV_IN" } else { "PROXY_IN" }
    Write-Host ("Frame {0,4}: {1,-9} -> {2}" -f $_.frame, $handleName, $_.data)
}

Write-Host ""
Write-Host "="*60
Write-Host "EXTRACTING COMMAND SEQUENCE"
Write-Host "="*60
Write-Host ""

# Group commands by proximity (within 50 frames = likely same session)
$commandSequences = @()
$currentSequence = @()
$lastFrame = 0

foreach ($cmd in $meshWrites) {
    if ($currentSequence.Count -eq 0 -or ($cmd.frame - $lastFrame) -lt 50) {
        $currentSequence += $cmd
    } else {
        if ($currentSequence.Count -gt 0) {
            $commandSequences += ,@($currentSequence)
        }
        $currentSequence = @($cmd)
    }
    $lastFrame = $cmd.frame
}

# Add last sequence
if ($currentSequence.Count -gt 0) {
    $commandSequences += ,@($currentSequence)
}

Write-Host "Found $($commandSequences.Count) command sequences`n"

# Show first sequence (most likely the handshake)
if ($commandSequences.Count -gt 0) {
    Write-Host "SEQUENCE 1 (Frames $($commandSequences[0][0].frame) - $($commandSequences[0][-1].frame)):"
    Write-Host "-"*60
    
    $commandSequences[0] | ForEach-Object {
        $handleName = if ($_.handle -eq "0x0025") { "PROV_IN" } else { "PROXY_IN" }
        Write-Host ("  {0,-9} -> {1}" -f $handleName, $_.data)
    }
}

Write-Host ""
Write-Host "Analysis saved. Review the command sequences above."
