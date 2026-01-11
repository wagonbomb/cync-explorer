#!/bin/bash
# Capture HCI traffic while running BLE test

echo "=========================================="
echo "HCI Capture for Cync BLE Protocol"
echo "=========================================="
echo

# Create output directory
mkdir -p /tmp/cync_capture

# Start btmon in background
echo "[1] Starting HCI monitor..."
sudo btmon -w /tmp/cync_capture/trace.btsnoop > /tmp/cync_capture/btmon.log 2>&1 &
BTMON_PID=$!
sleep 2

echo "    btmon PID: $BTMON_PID"
echo

# Run the BLE test
echo "[2] Running BLE test..."
cd /mnt/c/Users/Meow/Documents/Projects/cync-explorer
source .venv-wsl/bin/activate
timeout 60 python src/linux_ble_direct.py

# Stop btmon
echo
echo "[3] Stopping HCI monitor..."
sudo kill $BTMON_PID 2>/dev/null
sleep 1

# Decode and show interesting parts
echo
echo "[4] Decoding captured traffic..."
if [ -f /tmp/cync_capture/trace.btsnoop ]; then
    sudo btmon -r /tmp/cync_capture/trace.btsnoop 2>&1 | grep -A5 -E "(ATT:|Handle Value|Write Request|Write Command)" | head -100
    echo
    echo "Full trace saved to /tmp/cync_capture/trace.btsnoop"
    echo "View with: sudo btmon -r /tmp/cync_capture/trace.btsnoop"
else
    echo "No trace file captured"
fi
