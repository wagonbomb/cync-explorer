# Test Single Command - PowerShell Native
# Usage: .\test_command.ps1

Write-Host "Running Python test in PowerShell..."
$root = Join-Path $PSScriptRoot ".."
python (Join-Path $root "src\\single_command_test.py")
