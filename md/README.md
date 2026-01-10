# GE Cync Lighting BLE Explorer

A set of Python tools to discover and interact with GE Cync smart lights via Bluetooth Low Energy (BLE).

## Prerequisites

- Windows 10/11 with Bluetooth hardware
- Python 3.8+
- `bleak` library for BLE communication

## Installation

```bash
pip install bleak
```

## Tools

### 1. BLE Scanner (`src/ble_scanner.py`)

Scans for nearby BLE devices to discover your Cync lights.

```bash
# Scan all nearby BLE devices
python src/ble_scanner.py

# Search for a specific MAC address
python src/ble_scanner.py 34134346ca85
```

### 2. GATT Explorer (`src/gatt_explorer.py`)

Connects to a Cync light and enumerates all its GATT services and characteristics.

```bash
python src/gatt_explorer.py 34134346ca85
```

This will show:
- All available services
- All characteristics and their properties (read/write/notify)
- Current values of readable characteristics
- Identifies potential control characteristics

### 3. Light Controller (`src/cync_controller.py`)

Interactive tool to test control commands on the light.

```bash
python src/cync_controller.py 34134346ca85
```

Features:
- Write arbitrary hex data to characteristics
- Test common ON/OFF patterns
- Interactive discovery mode

## Usage Flow

1. **Find your light**: Run `ble_scanner.py` to confirm your light is discoverable
2. **Explore services**: Run `gatt_explorer.py` to see what the light exposes
3. **Test control**: Use `cync_controller.py` to try sending commands

## Notes

- GE Cync lights use proprietary BLE protocols that aren't publicly documented
- Some lights may require pairing/bonding before they respond to commands
- The control protocol may involve specific byte sequences discovered through reverse engineering
- Lights that are WiFi-connected may primarily communicate through the cloud rather than BLE
