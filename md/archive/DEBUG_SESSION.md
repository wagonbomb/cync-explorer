# Handshake Debugging Session - 2026-01-10

## Problem Summary

**Goal**: Turn OFF the light at MAC `34:13:43:46:CA:84`

**Issue**: BLE connection disconnects during handshake, preventing control commands from being sent.

---

## Root Cause Analysis

### Timeline of Disconnection

```
16:32:04 - Connected to device (timestamp: 2634300.515)
16:32:12 - Handshake starts
16:32:12 - Step 1: Send handshake start (000501...)
16:32:12 - Step 2: Send key exchange (000001...040000)
16:32:12 - Step 3: TIMEOUT waiting for session ID
16:32:12 - Step 4: Send sync sequence
16:32:12 -   Sync 0: 3100 ✓
16:32:12 -   Sync 1: 3101 ✓
16:32:12 -   **DEVICE DISCONNECTED** (timestamp: 2634308.625)
16:32:12 -   Sync 2, 3, 4: Failed (not connected)
```

**Disconnection occurs**: 8.11 seconds after connection, during Sync 1 packet

### Notifications Received

**ONLY ONE notification received** (right after connection, before handshake):
```
[NOTIFY] 00002ade (Mesh Proxy Data Out): 010100efbb755d239432fc0000000032bd9bc1d371a887
```

**After sending handshake packets**: ZERO responses

---

## Critical Discovery: HCI Logs vs Protocol Spec Mismatch

### Protocol Spec Says:
```
TX: 000501...
TX: 000001...040000
RX: 04 00 00 [SESSION_ID]  ← Expected response
```

### HCI Logs Show (from paired device):
```
TX: 000501000000000000000000
RX: 00060100000000000000000001  ← Actual response (echoes request + data)

TX: 00000100000000000000040000
RX: 00010100000000000000040000310001  ← Actual response

TX: 3100 → RX: 3100d2b77b0a
TX: 3101 → RX: 3101000344
TX: 3102 → RX: 3102010202
TX: 3103 → RX: 3103300fac06df7eb4ce
TX: 3104 → RX: 31041e99e41b1991b80c380bd445585609da
TX: 320119000000 → RX: 320200
```

**Key Finding**: Device echoes every request with additional data appended, NOT the simple `04 00 00 [id]` format!

---

## Hypothesis: Device is Paired/Provisioned

### Evidence:
1. Device does NOT respond to our handshake packets
2. HCI logs show responses ONLY when device is paired with official app
3. Protocol spec may be for unpaired/fresh devices
4. Our notification handler waits for pattern `\x04\x00\x00` which never appears

### Device State Possibilities:
- **Paired to GE Cync app**: Device ignores unauthorized handshakes
- **Encrypted session required**: Device expects authentication we're not providing
- **Different firmware**: Device behavior doesn't match protocol spec

---

## Fixes Attempted

### Fix 1: Connection Keep-Alive ❌
**Approach**: Send test command immediately after handshake
**Result**: Failed - connection already lost before keep-alive runs

### Fix 2: Disconnection Monitoring ✓
**Approach**: Added `disconnected_callback` to BleakClient
**Result**: Successfully identified exact disconnection timing (after Sync 1)

### Fix 3: Correct UUID Routing ✓
**Approach**: Send Sync + Auth Finalize ONLY to MESH_PROXY_IN (per protocol spec)
**Result**: Partial improvement - disconnection moved from Sync 2 to Sync 1

---

## Next Steps

### Option 1: Factory Reset Device
**Procedure** (from PROJECT_ARCHITECTURE.md):
1. Power cycle device 5x (ON 2s, OFF 2s)
2. Device name should change to "telink_mesh1"
3. Device enters unpaired state
4. Retry handshake with fresh device

**Expected Behavior**:
- Unpaired device should respond to handshake packets
- Should match protocol spec behavior
- Session ID response should appear

### Option 2: Fix Notification Handler
**Approach**: Update notification handler to recognize actual response pattern

**Current Code**:
```python
if b"\x04\x00\x00" in data:
    client.handshake_data = data
    client.handshake_event.set()
```

**Updated Code**:
```python
# Recognize echo responses (device echoes request + data)
if len(data) > 0:
    # Log ALL notifications to understand device responses
    logger.info(f"   [NOTIFY DETAIL] Hex: {data.hex()}, Len: {len(data)}")

    # Check for handshake response (starts with 00 06 or 00 01)
    if data.startswith(b"\x00\x06") or data.startswith(b"\x00\x01"):
        client.handshake_data = data
        client.handshake_event.set()
```

### Option 3: Decrypt Existing Session
**Approach**: Use official GE Cync app to pair, then sniff session key

**Steps**:
1. Use HCI logs to capture app pairing
2. Extract session key from pairing data
3. Use session key to encrypt our commands
4. Send encrypted commands to paired device

**Complexity**: HIGH - requires reverse engineering session key derivation

---

## Recommended Action

### Immediate: Test with Factory Reset Device

**Why**: This will determine if the issue is pairing-related vs protocol implementation

**Steps**:
1. Factory reset light (power cycle 5x: ON 2s, OFF 2s)
2. Verify device name changes to "telink_mesh1"
3. Scan for device with updated name
4. Retry handshake sequence
5. Monitor for responses

**Expected Outcome**:
- ✓ Device responds to handshake packets
- ✓ Notification handler receives session ID
- ✓ Control commands work

**If still fails**:
- Device firmware may be incompatible with our protocol implementation
- Need to analyze official app's exact byte sequences
- Consider using Frida to hook app's native library calls

---

## Code Changes Made

### File: `src/cync_server.py`

**Change 1**: Added disconnection callback
```python
def disconnection_callback(client_obj):
    logger.warning(f"[{mac}] !!! DEVICE DISCONNECTED !!!")
    logger.warning(f"   Connection lost at: {asyncio.get_event_loop().time()}")

client = BleakClient(mac, timeout=20.0, disconnected_callback=disconnection_callback)
```

**Change 2**: Connection keep-alive (unsuccessful)
```python
# Send test command after handshake
test_cmd = CommandBuilder.build_power_command(True, prefix=prefix_byte)
await client.write_gatt_char(MESH_PROXY_IN, test_cmd, response=False)
```

**Change 3**: Corrected UUID routing
```python
# Sync and Auth Finalize ONLY to MESH_PROXY_IN
await client.write_gatt_char(MESH_PROXY_IN, sync_pkt, response=False)
```

---

## Test Automation Created

### File: `test_light_control.py`

**Purpose**: Automated testing of all control methods

**Test Sequence**:
1. Server status check
2. Device connection
3. Handshake execution
4. Control endpoints (/api/control, /api/power_protocol, /api/brightness)

**Results**: All control endpoints fail with "Not connected" error

---

## Summary

**Problem**: Device does not respond to handshake packets and disconnects during Sync sequence

**Root Cause**: Likely device is paired/provisioned and ignoring unauthorized handshakes OR protocol spec doesn't match actual device behavior

**Status**: Need to test with factory reset device to confirm hypothesis

**Next Action**: User should factory reset the light OR provide access to an unpaired device for testing
