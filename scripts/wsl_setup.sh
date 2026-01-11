#!/bin/bash
# WSL BLE Setup Script
# Run this in your WSL Ubuntu terminal

set -e

echo "=========================================="
echo "WSL BLE Setup for Cync Protocol Capture"
echo "=========================================="
echo

# Install required packages
echo "[1/4] Installing system packages..."
sudo apt-get update
sudo apt-get install -y bluez python3-pip python3-venv usbutils

# Check Bluetooth
echo
echo "[2/4] Checking Bluetooth adapter..."
if lsusb | grep -i bluetooth; then
    echo "  ✓ Bluetooth adapter found"
else
    echo "  ✗ Bluetooth adapter not found"
    echo "  Run this in Windows PowerShell (as admin):"
    echo '  usbipd attach --wsl --busid 2-5'
    exit 1
fi

# Start Bluetooth service
echo
echo "[3/4] Starting Bluetooth service..."
sudo systemctl start bluetooth || sudo service bluetooth start
sudo hciconfig hci0 up 2>/dev/null || echo "  Note: hci0 may need a moment to initialize"

# Set up Python environment
echo
echo "[4/4] Setting up Python environment..."
cd /mnt/c/Users/Meow/Documents/Projects/cync-explorer
python3 -m venv .venv-wsl 2>/dev/null || true
source .venv-wsl/bin/activate
pip install bleak pycryptodome cryptography

echo
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo
echo "Now run:"
echo "  cd /mnt/c/Users/Meow/Documents/Projects/cync-explorer"
echo "  source .venv-wsl/bin/activate"
echo "  python src/blind_handshake.py"
echo
