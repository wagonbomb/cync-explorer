# POC Pairing Test Results

**Date**: 2026-01-10
**Device**: 34:13:43:46:CA:84
**Initial State**: Factory reset, expected name "telink_mesh1"

---

## Iteration 1: Encrypted Pairing Protocol

**Test File**: `tests/test_mesh_pairing_poc.py`
**Approach**: Send encrypted pairing messages per Telink protocol

### Results:
- ✅ Connection successful
- ✅ Subscribed to notifications (PROV_OUT, PROXY_OUT)
- ✅ Sent all 4 pairing messages without errors:
  - 0x04: Network Name (encrypted)
  - 0x05: Password (encrypted)
  - 0x06: LTK (encrypted)
  - 0x07: Confirm
- ❌ **ZERO responses** from device
- ❌ **NO initial notification** (unusual - normally get device beacon)
- ⚠️ Device name changed to "None" after test

### Session Key Used:
```
00000000000000000000000000000000  (all zeros - default for unprovisioned)
```

### Messages Sent:
```
PAIR_NETWORK_NAME: 04d601448c9551c70b10a59f097fc8f1a7
PAIR_PASSWORD:     05d7cac37c0732aff2335801e549347ef0
PAIR_LTK:          064990d237dfda1f652f550ea337af3c01
PAIR_CONFIRM:      07
```

---

## Iteration 2: Alternative Approaches

**Test File**: `tests/test_pairing_iteration2.py`
**Approaches**: 4 different strategies to elicit response

### Approach 1: Provisioning UUID
- Sent BLE Mesh provisioning invite (0x00) to MESH_PROV_IN
- **Result**: No response

### Approach 2: Unencrypted Credentials
- Sent plaintext mesh name and password
- **Result**: No response

### Approach 3: Simple Test Commands
- Sent null command, query status, ping
- **Result**: No response to any

### Approach 4: Reconnect Check
- Disconnected and reconnected to check state
- **Result**: Still no notifications

### Summary:
- ❌ Device did not respond to ANY approach
- ❌ ZERO notifications across all 4 approaches
- ✅ Connection remained stable (no disconnection)
- ✅ Writes accepted without errors

---

## Critical Observations

### 1. Missing Initial Notification

**Expected Behavior** (from previous tests with paired device):
```
[NOTIFY] 00002ade: 010100efbb755d239432fc0000000032bd9bc1d371a887
```

**Actual Behavior** (factory reset device):
```
(No notifications at all)
```

This initial notification is the "device beacon" that typically contains:
- Device type/version
- Session information
- Device ID

**Its absence suggests the device is in an abnormal state.**

### 2. Device Name Changed

**Before pairing attempt**:
- Device name: "telink_mesh1" (expected after factory reset)

**After pairing attempt**:
- Device name: "None" (empty/null)

**This indicates the device processed something, but not successfully.**

### 3. Device Still Advertising

The device:
- ✅ Still visible in BLE scan
- ✅ MAC address: 34:13:43:46:CA:84
- ✅ Accepts connections
- ✅ GATT characteristics accessible
- ❌ But completely silent (no notifications)

---

## Hypothesis: Device State Issue

### Possible Explanations:

#### Theory 1: Partial Pairing State
The device may have:
- Received pairing messages
- Processed them partially
- Entered a "waiting" state
- But didn't complete pairing due to incorrect session key

**Evidence**:
- Device name changed (indicates processing occurred)
- No error responses (device accepted commands)
- Silent state (waiting for correct sequence?)

#### Theory 2: Wrong Provisioning Flow
We may be using the wrong provisioning sequence:
- Telink devices have standard AND custom provisioning
- GE Cync may use a hybrid approach
- Factory reset may put device in standard BLE Mesh mode
- But we're sending Telink custom pairing

**Evidence**:
- Device accepts but doesn't respond
- No initial beacon (standard BLE Mesh behavior?)

#### Theory 3: Device Needs Reset
The first pairing attempt may have:
- Put device in error state
- Requires power cycle to reset
- Will return to normal advertising after reboot

**Evidence**:
- Device name is "None" (abnormal)
- No notifications at all (abnormal)
- Was working before (had "telink_mesh1" name)

---

## Next Steps

### Immediate: Power Cycle Test

1. **Power OFF the bulb**
2. **Wait 5 seconds**
3. **Power ON the bulb**
4. **Run diagnostic scan**:
   ```bash
   python -c "import asyncio; from bleak import BleakScanner; devices = asyncio.run(BleakScanner.discover(timeout=5.0)); target = [d for d in devices if '34:13:43:46:CA:84' in d.address]; print('Name:', target[0].name if target else 'NOT FOUND')"
   ```

5. **Connect and check for initial notification**

**Expected After Power Cycle**:
- Device name returns to "telink_mesh1"
- Initial notification appears on connection
- Device responds normally

**If Still Silent**:
- May need full factory reset again
- Device may be in persistent error state

### Alternative: Check HCI Logs

Compare our pairing sequence with official GE Cync app:
1. Enable HCI logging on Android
2. Pair bulb with official app
3. Extract actual pairing sequence
4. Compare with our implementation

**This will show**:
- Exact byte sequence app sends
- Responses from device
- Any missing steps we're not doing

### Alternative: Try Official Telink SDK

GE Cync is based on Telink mesh. Try:
1. Download Telink BLE Mesh SDK
2. Use their provisioning tool
3. See if standard Telink provisioning works
4. If yes, extract their sequence

---

## Code Quality Assessment

### POC Architecture: ✅ Excellent

**Strengths**:
- Clean, standalone implementation
- Comprehensive logging
- Multiple approaches tested
- No bloat in main codebase
- Easy to iterate

**Test Coverage**:
- ✅ Connection handling
- ✅ Notification subscription
- ✅ Multiple UUID paths
- ✅ Encrypted and unencrypted
- ✅ Error handling

### Pairing Protocol Implementation: ⚠️ Needs Validation

**What We Have**:
- ✅ Correct UUIDs (per spec)
- ✅ Correct encryption (AES/ECB with reversal)
- ✅ Correct padding (16 bytes)
- ✅ Correct opcodes (0x04-0x07)
- ✅ Correct default credentials

**What's Uncertain**:
- ❓ Session key derivation (used all-zeros)
- ❓ Message format (device doesn't respond)
- ❓ Provisioning prerequisites (may need handshake first)
- ❓ Response handling (no responses to validate)

---

## Comparison: Handshake vs Pairing

| Aspect | Old Handshake (Failed) | Pairing POC (Current) |
| --- | --- | --- |
| **Connection** | Disconnects after 8s | Stays connected ✅ |
| **Writes** | Accepted initially | Accepted always ✅ |
| **Responses** | Zero (timeout) | Zero |
| **Error** | Disconnection | Silent/no response |
| **Progress** | Device rejects | Device accepts but silent |

**Pairing is closer to working** - device doesn't reject, just doesn't confirm.

---

## Recommendations

### Recommendation 1: Power Cycle + Retry (Quick)
- **Time**: 5 minutes
- **Likelihood of success**: Medium
- **Action**: Reboot device, run POC again with fresh state

### Recommendation 2: HCI Log Comparison (Thorough)
- **Time**: 1-2 hours
- **Likelihood of success**: High
- **Action**: Capture official app pairing, compare byte-for-byte

### Recommendation 3: Try Telink SDK (Alternative)
- **Time**: 2-3 hours
- **Likelihood of success**: Medium
- **Action**: Use official Telink tools to validate device works

### Recommendation 4: Session Key Iteration (Experimental)
- **Time**: 30 minutes
- **Likelihood of success**: Low-Medium
- **Action**: Try different session key derivations:
  - MAC address based
  - Fixed Telink keys
  - Extracted from device advertising data

---

## Conclusion

**POC Status**: ⚠️ Inconclusive - Device accepts but doesn't respond

**Root Cause**: Unknown - could be:
- Session key incorrect
- Missing provisioning step
- Device in error state
- Wrong message format

**Next Action**: Power cycle device and retest

**Code Promotion**: **NOT YET** - need device response validation first

---

**USER ACTION REQUIRED**: Power cycle bulb, then run:
```bash
cd tests && python test_mesh_pairing_poc.py
```
