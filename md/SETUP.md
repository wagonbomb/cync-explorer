# Environment Setup Guide

## Overview

GE Cync BLE requires **Linux with BlueZ** for proper Bluetooth Mesh support. Windows BLE stack has limitations with notification subscriptions on Telink characteristics.

---

## Option 1: WSL2 with USB Bluetooth Passthrough (Recommended)

### Prerequisites
- Windows 10/11 with WSL2
- USB Bluetooth adapter
- usbipd-win installed

### Step 1: Install usbipd-win

```powershell
# PowerShell (Admin)
winget install usbipd
```

### Step 2: Install WSL2 USB Support

```bash
# In WSL2
sudo apt update
sudo apt install linux-tools-generic hwdata
sudo update-alternatives --install /usr/local/bin/usbip usbip /usr/lib/linux-tools/*-generic/usbip 20
```

### Step 3: Install BlueZ

```bash
sudo apt install bluez bluez-tools
sudo service dbus start
sudo bluetoothd &
```

### Step 4: Attach USB Bluetooth to WSL

```powershell
# PowerShell (Admin) - list USB devices
usbipd list

# Bind and attach (replace BUSID with your adapter)
usbipd bind --busid 1-4
usbipd attach --wsl --busid 1-4
```

### Step 5: Verify in WSL

```bash
# Check adapter
hciconfig

# Should show:
# hci0:   Type: Primary  Bus: USB
#         UP RUNNING

# Scan for devices
bluetoothctl scan on
```

---

## Option 2: Native Linux

### Install Dependencies

```bash
# Debian/Ubuntu
sudo apt install bluez bluez-tools python3-pip python3-venv

# Start Bluetooth service
sudo systemctl start bluetooth
sudo systemctl enable bluetooth
```

### Verify Bluetooth

```bash
hciconfig
bluetoothctl show
```

---

## Python Environment

### Create Virtual Environment

```bash
cd cync-explorer
python3 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies

```bash
pip install bleak cryptography pycryptodome aiohttp
```

---

## Testing the Setup

### 1. Scan for Device

```bash
python src/linux_ble_provision.py
```

Expected output:
```
Found: C by GE (or telink_mesh1)
Connected! MTU: 23
```

### 2. Test Provisioning

```bash
python src/linux_ble_provision_final.py
```

Expected output:
```
[STEP 1] Invite
  OK - 4 elements
[STEP 2] Start
  OK
[STEP 3] Public Key Exchange
  OK - Got device key
...
```

---

## Troubleshooting

### "Notify acquired" Error

BlueZ locks notification on some characteristics. Use Mesh Proxy characteristics (2adc/2ade) instead of Telink 1911.

### Device Not Found

1. Ensure device is powered on and in range
2. Check if device is paired to phone app (unpair first)
3. Try resetting Bluetooth: `sudo hciconfig hci0 reset`

### Connection Timeout

1. Device may need time between connections
2. Try: `bluetoothctl disconnect <MAC>` before reconnecting
3. Power cycle the light

### Permission Denied

```bash
sudo usermod -a -G bluetooth $USER
# Then logout/login
```

---

## Device Information

### Target Device
- **MAC:** 34:13:43:46:CA:84
- **Name:** "C by GE" or "telink_mesh1"
- **Type:** Bluetooth Mesh (requires provisioning)

### GATT Services
```
00001827 - Mesh Provisioning
00001828 - Mesh Proxy
00010203-...-1910 - Telink Vendor
```
