# POC Test Plan - BLE Mesh Pairing

**Date**: 2026-01-10
**Status**: Ready to Execute
**File**: `tests/test_mesh_pairing_poc.py`

---

## Test Objective

Validate the Telink BLE mesh pairing protocol with a factory-reset GE Cync bulb using credentials and protocol extracted from APK decompilation.

**Success Criteria:**
- ✓ Device accepts pairing messages without disconnecting
- ✓ Device responds to pairing opcodes (0x04-0x07)
- ✓ Session key is established
- ✓ Device name changes from "telink_mesh1" to "out_of_mesh"
- ✓ Control commands work after pairing

---

## Prerequisites

### 1. Factory Reset Your Bulb

**Procedure:**
1. Turn bulb **ON** for 2 seconds
2. Turn bulb **OFF** for 2 seconds
3. Repeat steps 1-2 **four more times** (5 cycles total)
4. Bulb should **flash** to confirm reset
5. Device name should change to **"telink_mesh1"**

**Verification:**
```bash
# Scan for device
python -c "from bleak import BleakScanner; import asyncio; asyncio.run(BleakScanner.discover())"

# Look for device with MAC 34:13:43:46:CA:84
# Name should be "telink_mesh1"
```

### 2. Ensure Server is Not Running

```bash
# Kill any running server instances
taskkill /F /IM python.exe
```

---

## Running the Test

### Step 1: Execute POC Test

```bash
cd C:\Users\Meow\Documents\Projects\cync-explorer
python tests\test_mesh_pairing_poc.py
```

### Step 2: Follow Interactive Prompts

The test will:
1. Ask you to confirm prerequisites
2. Connect to the device
3. Subscribe to notifications
4. Send pairing sequence
5. Display detailed results

### Step 3: Observe Output

**Expected Output Phases:**

**Phase 1 - Connection:**
```
[PHASE 1] Connecting to device...
✓ Connected to 34:13:43:46:CA:84
  Device Name: telink_mesh1

  Subscribing to notifications...
    ✓ Subscribed to 00002adc-0000-1000-8000-00805f9b34fb
    ✓ Subscribed to 00002ade-0000-1000-8000-00805f9b34fb

  Waiting for initial notification...
[NOTIFY] 00002ade-0000-1000-8000-00805f9b34fb: 010100efbb755d...
```

**Phase 2 - Pairing:**
```
[PHASE 2] Executing pairing protocol...
[PHASE 2A] Attempting to derive session key...
  Initial notification: 010100efbb755d239432fc0000000032bd9bc1d371a887
  Using default session key: 00000000000000000000000000000000

[PHASE 2B] Building pairing messages...
  Mesh Name: 'out_of_mesh' -> 6f75745f6f665f6d65736800000000000000
  Mesh Pass: '123456' -> 3132333435360000000000000000000000
  LTK: d00710a0a601370854e32e177afd1159

  Encrypting with session key: 00000000000000000000000000000000
  Encrypted Name: <hex>
  Encrypted Pass: <hex>
  Encrypted LTK:  <hex>

[PHASE 2C] Sending pairing sequence...
  Sending Network Name to 00002add...
  ✓ Sent 17 bytes
  ✓ Received response  OR  ⚠ No response (timeout)

  Sending Password to 00002add...
  ✓ Sent 17 bytes
  ...
```

**Phase 3 - Validation:**
```
[PHASE 3] Validating pairing result...
  ✓ Pairing messages sent successfully

  Waiting 3 seconds for device to process...

  Received 4 pairing-related notifications
  ✓ Device responded to pairing messages!
```

**Phase 4 - Summary:**
```
[PHASE 4] Test Summary
================================================================================
Connection: ✓ Success
Notifications: 8 received
Pairing Messages Sent: 4/4
Session Key: 00000000000000000000000000000000

NEXT STEPS:
1. Scan for device again - name should have changed
2. Try sending control commands with this session key
3. If successful, promote to src/protocol/mesh_pairing.py
================================================================================
```

---

## Expected Outcomes

### Scenario 1: Complete Success ✅

**Indicators:**
- Device responds to all 4 pairing messages
- Notifications show pairing opcodes (0x04, 0x05, 0x06, 0x07)
- No disconnection during pairing
- Device name changes to "out_of_mesh" (verify with new scan)

**Next Action:**
- Promote POC code to `src/protocol/mesh_pairing.py`
- Integrate into web server
- Add control command test with session key

### Scenario 2: Partial Success ⚠

**Indicators:**
- Device accepts some messages but not all
- Device responds but with error codes
- Connection stays alive but no confirmation

**Next Action:**
- Analyze notification responses for error codes
- Adjust session key derivation method
- Try alternative credential formats

### Scenario 3: Failure ❌

**Indicators:**
- Device disconnects immediately after first message
- No responses to any pairing messages
- Connection lost during pairing sequence

**Possible Causes:**
1. **Session key incorrect** - Try alternative derivation methods
2. **Wrong UUID** - Device expects pairing on different characteristic
3. **Encryption format wrong** - Byte order or padding issue
4. **Device not in pairing mode** - Factory reset may not have worked

**Debug Steps:**
1. Add hex dumps of all notification data
2. Compare with HCI logs from official app
3. Try sending unencrypted credentials (if device accepts plaintext)
4. Verify AES encryption matches Telink implementation

---

## Troubleshooting

### Device Not Found
```bash
# Verify Bluetooth is enabled
# Ensure device is powered on
# Check MAC address is correct
```

### "Device may already be paired"
```bash
# Factory reset bulb again
# Verify name changes to "telink_mesh1"
```

### No Initial Notification
```bash
# This is OK - continue with test
# Session key will use default (all zeros)
```

### Connection Drops During Pairing
```bash
# This indicates session key or message format issue
# Check logs for exact point of disconnection
# Compare message format with APK decompilation
```

---

## Post-Test Validation

### 1. Scan for Device Again
```bash
python -c "from bleak import BleakScanner; import asyncio; asyncio.run(BleakScanner.discover())"

# Device name should have changed:
# Before: "telink_mesh1"
# After:  "out_of_mesh" (or custom mesh name if you changed it)
```

### 2. Test Control Command
```bash
# If pairing succeeded, test a simple control command
# Use the session key from the test output
# Send encrypted ON/OFF command
```

---

## Code Promotion Path (If Successful)

### Phase 1: Extract Reusable Code
- Move helper functions to `src/protocol/crypto_utils.py`
- Move pairing logic to `src/protocol/mesh_pairing.py`

### Phase 2: Integration
- Add `/api/pair` endpoint to `src/cync_server.py`
- Update web UI with "Pair Device" button
- Store session keys in `active_sessions`

### Phase 3: Testing
- Update `test_light_control.py` to include pairing step
- Test with multiple devices
- Verify re-pairing works

### Phase 4: Documentation
- Add pairing instructions to README
- Document session key management
- Create user guide for Home Assistant integration

---

## Key Differences from Handshake

| Aspect | Old Handshake (Failed) | New Pairing (POC) |
| --- | --- | --- |
| **Protocol** | Generic mesh handshake | Telink-specific pairing |
| **Opcodes** | 0x00, 0x31, 0x32 | 0x04, 0x05, 0x06, 0x07 |
| **Credentials** | None | Mesh name, password, LTK |
| **Encryption** | None | AES/ECB with byte reversal |
| **Target Device** | Paired device | Fresh/unprovisioned device |
| **Expected Response** | Session ID (0x04 0x00 0x00) | Pairing confirmations |

---

## Critical Implementation Details

### 1. Byte Reversal (IMPORTANT!)
Telink uses **reversed byte order** for AES encryption:
```python
# Before encryption: reverse bytes
# After encryption: reverse bytes again
```

This is unique to Telink and NOT standard AES!

### 2. Padding
All credentials must be **exactly 16 bytes**:
- Shorter: pad with 0x00
- Longer: truncate

### 3. Session Key
For unprovisioned devices:
- Try: All zeros (0x00 * 16)
- Try: Last 16 bytes of initial notification
- Try: MAC address derived key

### 4. Message Order
Send in EXACT order:
1. Network Name (0x04)
2. Password (0x05)
3. LTK (0x06)
4. Confirm (0x07)

---

## References

**Decompiled Source Files:**
- `TelinkDeviceBleManager$pairMesh$2.java` - Pairing implementation
- `Telink.java` - Encryption helpers (m600b, m602d)
- `MeshCredentials.java` - Credential structure
- `ppbbbdb.java` - Default credentials
- `BLEJniLib.java` - Native library wrapper

**Protocol Specification:**
- `md/PROTOCOL_SPECIFICATION.md` - Complete protocol details
- `md/WIFI_PROVISIONING_ANALYSIS.md` - Pairing vs WiFi clarification

---

## Ready to Execute

**Current Status:** ✅ POC code is ready
**Dependencies:** ✅ All installed
**Documentation:** ✅ Complete

**WAITING FOR:** User to factory reset bulb and confirm ready to proceed

---

**Once you've factory reset the bulb and it shows as "telink_mesh1", simply run:**
```bash
python tests\test_mesh_pairing_poc.py
```
