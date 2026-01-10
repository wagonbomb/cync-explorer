# Run exact handshake test
$root = Join-Path $PSScriptRoot ".."
python (Join-Path $root "tests\\test_exact_handshake.py")
