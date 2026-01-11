# Cync BLE Control Project - Master Architecture

**Last Updated**: January 7, 2026  
**Project Goal**: Achieve direct Bluetooth Low Energy (BLE) control of GE Cync smart bulbs without cloud dependency

---

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Current Status](#current-status)
3. [Technical Architecture](#technical-architecture)
4. [Work Completed](#work-completed)
5. [Test Results](#test-results)
6. [Next Steps](#next-steps)
7. [Key Findings](#key-findings)

---

## 🎯 Project Overview

### Objective
Build a custom Bluetooth LE control system for GE Cync smart bulbs to enable:
- Local control without internet/cloud
- Integration with custom automation systems
- Home Assistant BLE integration (non-cloud)
- Direct Python API for bulb control

### Target Device
- **Model**: GE Cync Smart Bulb (C by GE)
- **MAC Address**: 34:13:43:46:CA:84
- **Protocol**: Bluetooth Mesh (Telink-based)
- **Current State**: Factory reset, device name "telink_mesh1"

### Technology Stack
- **Language**: Python 3.11
- **BLE Library**: Bleak 0.21.0+
- **Platform**: Windows 11 with native Bluetooth adapter
- **Tools**: Wireshark (HCI logs), jadx (APK decompiler)

---

## 🚦 Current Status

### Phase: APK Reverse Engineering (In Progress)

**Current Task**: Decompiling Cync Android app to extract provisioning protocol

**Blockers**:
- ⚠️ Cync APK not yet downloaded

**Immediate Next Steps**:
1. ✅ ~~Install Java 17+ from Adoptium~~ (COMPLETE)
2. Download jadx decompiler (tools-local)
3. Download Cync APK from APKMirror (save to artifacts/com.ge.cbyge.apk)
4. Decompile with .\scripts\run_jadx.ps1
5. Search for provisioning code
6. Implement Python BLE pairing

**Why This Matters**:  
Device is in "telink_mesh1" mode (factory reset) but requires Cync's proprietary provisioning protocol to accept commands. Standard Telink/Bluetooth Mesh provisioning does not work.

---

## 🏗️ Technical Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                    Control Layer                        │
│  ┌────────────────────────────────────────────────┐    │
│  │ Python Application (Future)                    │    │
│  │ - Home Assistant Integration                   │    │
│  │ - REST API Server                              │    │
│  │ - CLI Control Tool                             │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              BLE Communication Layer                    │
│  ┌────────────────────────────────────────────────┐    │
│  │ Bleak BLE Library                              │    │
│  │ - Connection Management                        │    │
│  │ - Characteristic R/W                           │    │
│  │ - Notification Handling                        │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Protocol Implementation                    │
│  ┌────────────────────────────────────────────────┐    │
│  │ [TO BE IMPLEMENTED]                            │    │
│  │ - Telink Provisioning                          │    │
│  │ - Mesh Network Pairing                         │    │
│  │ - Command Encryption                           │    │
│  │ - Session Management                           │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  Physical Device                        │
│              GE Cync Bulb (34:13:43:46:CA:84)          │
└─────────────────────────────────────────────────────────┘
```

### BLE Characteristics Map

| UUID | Name | Handle | Properties | Purpose |
|------|------|--------|------------|---------|
| `00002adb-...-9b34fb` | Mesh Provisioning In | 33 | WRITE-NO-RESP | Send provisioning commands |
| `00002adc-...-9b34fb` | Mesh Provisioning Out | 35 | NOTIFY | Receive provisioning responses |
| `00002add-...-9b34fb` | Mesh Proxy In | 39 | WRITE-NO-RESP | Send mesh control commands |
| `00002ade-...-9b34fb` | Mesh Proxy Out | 41 | NOTIFY | Receive mesh responses |
| `00010203-...-0d1912` | Telink Command | 20 | READ, WRITE, WRITE-NO-RESP | Send Telink commands |
| `00010203-...-0d1911` | Telink Status | 17 | READ, WRITE, NOTIFY | Receive Telink responses (Windows blocks) |

### Communication Protocols

**Bluetooth Mesh (Standard)**: ❌ Not working  
**Telink Mesh (Proprietary)**: ⚠️ Partially understood  
**Cync Proprietary**: 🔍 Under investigation

---

## ✅ Work Completed

### Phase 1: Environment Setup ✅
- [x] Python 3.11 installed (Windows Store)
- [x] Bleak library installed
- [x] Git repository initialized
- [x] WSL/PowerShell terminal setup
- [x] BLE adapter verified working

### Phase 2: Discovery & Baseline Testing ✅

#### Test 01: Connectivity ✅
**File**: `tests/test_01_connectivity.py`  
**Status**: PASS  
**Results**:
- ✅ 31 Cync devices found in scan
- ✅ Target device connects successfully
- ✅ MTU: 247 bytes
- ✅ 100% connection stability (3/3 cycles)

#### Test 02: Characteristic Discovery ✅
**File**: `tests/test_02_characteristics.py`  
**Status**: PASS  
**Results**:
- ✅ 6 services discovered
- ✅ All 5 expected characteristics found
- ✅ Handles mapped correctly
- ✅ All properties readable

#### Test 04: Notification Testing ✅
**File**: `tests/test_04_notifications.py`  
**Status**: PARTIAL  
**Results**:
- ✅ Mesh Proxy Out: Subscription works
- ❌ Telink Status: Windows blocks CCCD write (Protocol Error 0x03)
- ✅ Initial notification received: `010100efbb755d239432fc0000000032bd9bc1d371a887`

#### Test 05: Command Testing ⚠️
**File**: `tests/test_05_simple.py`, `src/single_command_test.py`  
**Status**: COMMANDS SEND, NO RESPONSES  
**Results**:
- ✅ All writes succeed without errors
- ❌ No responses to any commands
- ❌ Device disconnects after 3-4 commands
- ❌ No physical light changes observed

### Phase 3: Advanced Attack Methods ✅

#### Comprehensive Attack Suite ❌
**File**: `src/comprehensive_attack.py`  
**Status**: ALL FAILED  
**Attacks Tested**:
1. **Telink Direct** (7E packets): 0 responses
2. **Simple Mesh** (b0c0 variations): 0 responses
3. **Full Handshake** (HCI sequence): 1 response (initial notification only)
4. **Brute Force** (all characteristics): No physical change

**Conclusion**: Device locked to existing mesh network, ignores unauthorized commands

#### HCI Log Analysis ✅
**Files**: `scripts/analyze_hci.ps1`, `scripts/analyze_hci_deep.ps1`  
**Status**: SUCCESSFUL EXTRACTION  
**Results**:
- ✅ 380 mesh write commands extracted
- ✅ 458 device responses found
- ✅ Complete handshake sequence identified
- ✅ Command-response pairs mapped
- ⚠️ Commands contain device-specific encrypted data

**Key Sequence Found** (from HCI logs):
```
TX: 000501000000000000000000 → RX: 00060100000000000000000001
TX: 00000100000000000000040000 → RX: 00010100000000000000040000310001
TX: 3100 → RX: 3100d2b77b0a
TX: 3101 → RX: 3101000344
TX: 3102 → RX: 3102010202
TX: 3103 → RX: 3103300fac06df7eb4ce
TX: 3104 → RX: 31041e99e41b1991b80c380bd445585609da
TX: 00000100000000000000160000 → RX: 00010100000000000000160000320000
TX: 320119000000 → RX: 320200
```

### Phase 4: Device Reset & Fresh Provisioning ✅

#### Factory Reset ✅
**Method**: Power cycle 5x (ON 2s, OFF 2s)  
**Results**:
- ✅ Device name changed: "C by GE" → "telink_mesh1"
- ✅ Device in unprovisioned state confirmed
- ❌ Standard provisioning still fails

#### Fresh Provisioning Attempts ❌
**Files**: `tests/test_exact_handshake.py`, `src/provision_fresh.py`, `src/telink_pair_password.py`  
**Status**: ALL FAILED  
**Methods Tested**:
- Standard Bluetooth Mesh Invite (0x00)
- Telink Pair Command (0x0C)
- Telink Login with default passwords ("123", "telink_mesh1", 0x00, 0xFF)
- Mesh provisioning PDUs
- Simple ON/OFF commands

**Results**:
- ❌ No responses to any provisioning attempts
- ❌ No physical light changes
- ❌ Device waiting for Cync-specific protocol

### Phase 5: APK Reverse Engineering 🔄
**Current Phase**  
**Files Created**:
- `md/APK_REVERSE_ENGINEERING.md` - Full guide
- `src/apk_search.py` - Automated code searcher
- `scripts/setup_apk_reverse.bat` - Automated setup
- `scripts/setup_apk_interactive.ps1` - Interactive setup
- `scripts/MANUAL_STEPS.ps1` - Manual commands

**Prerequisites**:
- [x] Java 17+ installed
- [ ] jadx decompiler downloaded
- [ ] Cync APK downloaded from APKMirror
- [ ] APK decompiled
- [ ] Provisioning code located

---

## 🧪 Test Results

### Summary Table

| Test | File | Status | Key Finding |
|------|------|--------|-------------|
| BLE Scan | tests/test_01_connectivity.py | ✅ PASS | 31 devices found, stable connections |
| GATT Discovery | tests/test_02_characteristics.py | ✅ PASS | All characteristics accessible |
| Notifications | tests/test_04_notifications.py | ⚠️ PARTIAL | Mesh works, Telink blocked by Windows |
| Commands | tests/test_05_simple.py | ❌ FAIL | Sends but no responses |
| Telink Direct | src/comprehensive_attack.py | ❌ FAIL | 7E packets ignored |
| Mesh Commands | src/comprehensive_attack.py | ❌ FAIL | b0c0 packets ignored |
| HCI Replay | tests/test_exact_handshake.py | ❌ FAIL | Device won't respond to replayed commands |
| Factory Reset | Manual (power cycle) | ✅ PASS | Device now "telink_mesh1" |
| Std Provisioning | src/provision_fresh.py | ❌ FAIL | Device ignores standard BT Mesh |
| Telink Pairing | src/telink_pair_password.py | ❌ FAIL | All default passwords rejected |
| BLE Reset | tests/test_ble_reset.py | ❌ FAIL | No reset commands found |

### Critical Discoveries

#### ✅ What Works
1. **BLE Stack**: Full access to all characteristics
2. **Connections**: Stable, repeatable
3. **Writes**: All commands accepted without error
4. **Reads**: Device name, manufacturer data accessible
5. **Notifications**: Mesh Proxy Out works perfectly
6. **Factory Reset**: Power cycling 5x resets device

#### ❌ What Doesn't Work
1. **Physical Control**: Zero light changes in 50+ tests
2. **Command Responses**: Device silent to all unauthorized commands
3. **Standard Provisioning**: BT Mesh, Telink standard protocols fail
4. **HCI Replay**: Commands from working session don't work on reset device
5. **Windows Telink Status**: CCCD write blocked by OS

#### 🔍 Key Insights

**Device States**:
- **Paired**: Name = "C by GE", connected to Cync mesh, ignores unauthorized commands
- **Reset**: Name = "telink_mesh1", waiting for Cync provisioning, ignores standard protocols

**Initial Notification Decoded**:
```
010100efbb755d239432fc0000000032bd9bc1d371a887
│││├─────────────────┤├─────────┤├─────────────────┤
││││    Device ID     │ Session  │     Token       │
││││  efbb755d239432fc│ 00000000 │ 32bd9bc1d371a887│
│││└─ Type: 0x01      └─ No session yet
││└── Subtype: 0x01
│└─── Length: 0x01
└──── Header: 0x01
```

**HCI Analysis**:
- Handshake works when device is already paired
- Commands contain device-specific data: `058813a01302962d...`
- Padding matters: `000501000000000000000000` vs `000501`
- Session-based encryption after handshake

**Conclusion**: Cync uses proprietary provisioning that must be reverse-engineered from their app

---

## 🎯 Next Steps

### Immediate Actions (In Order)

#### 1. Complete APK Reverse Engineering Setup
**Status**: In Progress  
**Actions**:
- [x] Install Java 17+ from https://adoptium.net/temurin/releases/
- [ ] Download jadx decompiler to `tools-local\jadx`
- [ ] Download Cync APK from https://www.apkmirror.com/apk/ge-lighting/ (save to `artifacts\com.ge.cbyge.apk`)
- [ ] Run: `.\scripts\run_jadx.ps1`
- [ ] Run: `python src\apk_search.py ".\artifacts\cync_decompiled"`

#### 2. Locate Provisioning Code
**Search Targets**:
- `telink_mesh1` string references
- `00010203-0405-0607-0809-0a0b0c0d1912` UUID references
- `provision`, `pair`, `0x0c` command bytes
- `BluetoothGatt`, `writeCharacteristic` calls
- `encrypt`, `AES`, `password` functions

**Expected Files**:
- `*BleManager*.java`
- `*TelinkDevice*.java`
- `*MeshDevice*.java`
- `*ProvisionManager*.java`

#### 3. Extract Protocol Details
**Required Information**:
- Default mesh password
- Pairing command structure
- Encryption key derivation
- Session establishment sequence
- Command format after pairing

#### 4. Implement Python Provisioning
**New File**: `cync_provision.py`  
**Functions**:
- `pair_with_password(device, password)` - Initial pairing
- `establish_session(device)` - Session setup
- `encrypt_command(cmd, session_key)` - Command encryption
- `control_light(device, action)` - ON/OFF/brightness

#### 5. Test & Validate
- Provision factory-reset bulb
- Verify physical light control
- Document working protocol
- Create library for reuse

---

## 📚 Key Findings

### Why Standard Methods Failed

1. **Not Standard Bluetooth Mesh**: Cync uses Telink's proprietary mesh protocol
2. **Not Standard Telink**: Cync has custom provisioning on top of Telink
3. **Encryption Required**: All commands encrypted with session keys
4. **Device-Specific Keys**: Keys appear derived from device ID or MAC
5. **Pairing State Matters**: Commands only work after proper provisioning

### Home Assistant Integration Status

**Current HA Integration**: Cloud-based only
- Uses `pycync` library (cloud API)
- Requires Cync account login
- No BLE support
- Source: https://github.com/home-assistant/core/tree/dev/homeassistant/components/cync

**Our Goal**: Local BLE control without cloud

### Alternative Paths (Not Chosen)

1. ~~Use Cloud API~~ - Defeats purpose of local control
2. ~~Live BLE Sniffing~~ - Requires nRF52840 dongle ($10) we don't have
3. ~~Memory Dumping~~ - Requires rooted Android device
4. ✅ **APK Reverse Engineering** - Chosen path, no hardware needed

---

## 📁 File Organization

### Core Test Files (tests/)
```
tests/test_01_connectivity.py      - BLE scan & connection baseline
tests/test_02_characteristics.py   - GATT service discovery
tests/test_04_notifications.py     - Notification subscription tests
tests/test_05_simple.py            - Basic command testing
tests/test_05_commands.py          - Command variations and validation
tests/test_ble_scanner.py          - Scanner sanity checks
```

### Advanced Testing (tests/)
```
tests/test_exact_handshake.py      - HCI sequence replay
tests/test_exact_hci.py            - Exact HCI with padding
tests/test_unpaired_control.py     - Unpaired command test
tests/test_ble_reset.py            - BLE reset attempts
tests/test_dual_subscribe.py       - Dual notification test
tests/test_mesh_provision.py       - Mesh provisioning attempts
```

### Attack and Provisioning Tools (src/)
```
src/comprehensive_attack.py        - All attack methods combined
src/single_command_test.py         - One command per connection
src/provision_fresh.py             - Fresh device provisioning
src/telink_pair_password.py        - Telink password attempts
src/cync_provision_test.py         - Provisioning experiments
```

### Analysis Tools (src/ + scripts/)
```
src/analyze_hci.py                 - Parse HCI logs
scripts/analyze_hci.ps1            - Parse HCI JSON logs
scripts/analyze_hci_deep.ps1       - Deep HCI analysis
src/decode_notification.py         - Decode initial notification
src/check_device_state.py          - Device state checker
src/analyze_native_libs.py         - Quick native library analysis
```

### APK Reverse Engineering
```
md/APK_REVERSE_ENGINEERING.md      - Full guide
src/apk_search.py                  - Automated code searcher
src/quick_ble_search.py            - Fast BLE code search
src/explore_ble_code.py            - Interactive code explorer
scripts/setup_apk_reverse.bat      - Automated setup
scripts/setup_apk_interactive.ps1  - Interactive setup
scripts/MANUAL_STEPS.ps1           - Step-by-step commands
scripts/complete_decompile.ps1     - Full smali decompilation
scripts/run_jadx.ps1               - Jadx decompile helper
```

### Documentation (md/)
```
md/README.md                       - Project overview
md/BASELINE_RESULTS.md             - Test results summary
md/NEXT_STEPS.md                   - Recommendations
md/cync_context_dump.md            - Original context
md/implementation_plan.md          - Original plan
md/task.md                         - Task list
```

### Batch Launchers (scripts/)
```
scripts/run_test_01.bat, scripts/run_test_02.bat, scripts/run_test_04.bat
scripts/run_exact_handshake.bat, scripts/run_forensics.bat
scripts/run_gui.bat, scripts/run_network_scan.bat
```

---

## 🔄 Version History

- **2026-01-07 18:15** - Java 17 (Temurin) installed
- **2026-01-07 18:00** - APK reverse engineering phase started
- **2026-01-07 17:00** - Factory reset successful, provisioning attempts failed
- **2026-01-07 16:00** - Comprehensive attack all methods failed
- **2026-01-07 15:00** - HCI analysis completed, 380 commands extracted
- **2026-01-07 14:00** - Baseline tests completed, all BLE functions working

---

**Status**: 🔄 Active Development  
**Phase**: APK Reverse Engineering  
**Confidence**: High (all infrastructure working, just need provisioning protocol)
