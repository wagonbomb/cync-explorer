# WiFi Provisioning Analysis - GE Cync Bulbs vs Hubs

**Date**: 2026-01-10
**Question**: Do we need to mimic WiFi pairing for GE Cync smart bulbs?

---

## TL;DR Answer

**For BULBS: NO WiFi required** - Bulbs are BLE-only mesh devices
**For HUBS: YES WiFi required** - Hubs need WiFi for cloud connectivity

Your device (34:13:43:46:CA:84) is a **smart bulb**, so you can **skip WiFi provisioning** entirely.

---

## Device Type Analysis

### GE Cync Smart Bulbs
- **Connectivity**: Bluetooth Mesh (Telink) ONLY
- **No WiFi radio** - physically cannot connect to WiFi
- **Control**: 100% via BLE mesh protocol
- **Pairing**: BLE mesh pairing only (no WiFi step)

### GE Cync Hubs/Bridges
- **Connectivity**: BLE + WiFi
- **WiFi Required**: YES (for cloud services)
- **Control**: BLE mesh to devices, WiFi to cloud
- **Pairing**: WiFi setup THEN mesh pairing

---

## Evidence from Decompilation

### 1. WiFi Provisioning Code is Hub-Specific

**From `HubManager$setWifiCredentials$2.java`**:
```java
// Line 77-80: "Scanning for device with product type"
// Line 84: Product IDs for Hub devices:
//   - Hub V1: "160fa2b07d45ba00160fa2b07d45ba01"
//   - Hub V2: "160fa6b2279f03e9160fa6b2279f4801"
```

**Key Finding**: WiFi setup uses `HubManager` class, NOT `BulbManager` or `LightManager`

### 2. Commissioning Flow Differences

**From `BaseRouter.java` commissioning steps**:

**For Hubs**:
1. ScanDevices
2. EnableBluetooth
3. SelectWifi ← WiFi step
4. WifiPassword ← WiFi step
5. ConnectingWifi ← WiFi step
6. CommissionDevice (mesh pairing)

**For Bulbs** (inferred from BLE-only nature):
1. ScanDevices
2. EnableBluetooth
3. CommissionDevice (mesh pairing)

### 3. BLE Protocol is Complete Without WiFi

**From `PROTOCOL_SPECIFICATION.md`**:
- All UUIDs are BLE Mesh standard (2adb, 2add, 2ade)
- Protocol is Telink BLE Mesh
- No WiFi-related UUIDs or commands
- Complete control via BLE frames

---

## What Factory Reset Does

**From `PROJECT_ARCHITECTURE.md` (lines 212-217)**:

**Factory Reset Procedure**:
- Power cycle 5x (ON 2s, OFF 2s)
- Device name changes: "C by GE" → "telink_mesh1"
- Device enters **unprovisioned BLE mesh state**
- Device is NOT waiting for WiFi - waiting for **BLE mesh provisioning**

**Key Quote (line 60)**:
> "Device is in 'telink_mesh1' mode (factory reset) but requires Cync's proprietary provisioning protocol to accept commands."

This is referring to **BLE mesh provisioning**, not WiFi setup.

---

## Why the Confusion?

The GE Cync app supports BOTH bulbs and hubs:
- **Hubs**: Require WiFi setup flow (what the agent found)
- **Bulbs**: BLE-only, no WiFi step

The commissioning router handles BOTH types, which is why WiFi steps appear in the code.

---

## What You Actually Need to Implement

### For Your Bulb (34:13:43:46:CA:84)

**After Factory Reset**:
1. **BLE Mesh Provisioning** (NOT WiFi)
   - Device is in "telink_mesh1" unprovisioned state
   - Needs Cync's proprietary BLE mesh pairing
   - Establishes mesh network credentials
   - Creates session key for encryption

2. **BLE Mesh Pairing Commands**
   - Frame Type 1: `PAIR_REQ/RESP` (from PROTOCOL_SPECIFICATION.md)
   - Sends via `getNormalRequestData(1, pairData, len, packages)`
   - Response contains session key material
   - Session key used for encrypting future commands

3. **Session Key Derivation**
   - Native function: `madeSessionKey(pairingData, len, sessionKey)`
   - Creates 16-byte AES-128 key
   - Used to encrypt all control commands

---

## Next Steps for Your Implementation

### Option A: Implement BLE Mesh Pairing (Proper)

1. **Find pairing packet format**
   - Search decomp for `PAIR_REQ` implementation
   - Look for Frame Type 1 construction
   - Find default mesh network credentials

2. **Implement pairing function**
   ```python
   async def pair_device(client, mesh_name="telink_mesh1", password="123"):
       # Build pairing request (Frame Type 1)
       pair_req = build_pairing_request(mesh_name, password)

       # Send via getNormalRequestData
       await client.write_gatt_char(MESH_PROXY_IN, pair_req)

       # Wait for PAIR_RESP
       pair_resp = await wait_for_response()

       # Extract session key
       session_key = extract_session_key(pair_resp)

       return session_key
   ```

3. **Test with factory reset bulb**
   - Reset bulb (power cycle 5x)
   - Verify name = "telink_mesh1"
   - Run pairing function
   - Device should accept pairing

### Option B: Use Already-Paired Device (Easier)

**If your bulb is ALREADY paired to the GE Cync app**:
- Device is in paired state (name = "C by GE")
- You can skip pairing entirely
- Just need to capture/derive the session key
- Device is ignoring our handshake because we don't have valid session key

**Evidence from HCI logs** (PROJECT_ARCHITECTURE.md lines 197-208):
```
TX: 000501... → RX: 000601...  (device responds when paired)
```

Our device (unpaired) doesn't respond because:
- No session key established
- Device waiting for pairing, not handshake

---

## Recommendation

### Path 1: Factory Reset + Implement BLE Pairing ✅
**Pros**:
- Clean start
- Fully reverse-engineered solution
- No dependency on GE app

**Cons**:
- Need to find pairing packet format
- Need to derive session key
- More implementation work

**Steps**:
1. Factory reset bulb
2. Search decomp for `PAIR_REQ` / Frame Type 1
3. Implement pairing function
4. Test

### Path 2: Use HCI Sniffing to Capture Session Key ⚡
**Pros**:
- Works with already-paired device
- No pairing implementation needed
- Can extract working session key

**Cons**:
- Requires HCI logging setup
- Session key might be device-specific
- Need to re-capture if bulb re-pairs

**Steps**:
1. Enable HCI logging on Windows
2. Pair bulb with GE Cync app
3. Capture pairing session
4. Extract session key from logs
5. Use session key in our code

---

## Conclusion

**YOU DO NOT NEED TO IMPLEMENT WIFI PROVISIONING** for your GE Cync bulb.

The bulb is BLE-only and has no WiFi capability. The WiFi provisioning code in the app is for Hub devices, not bulbs.

What you DO need:
- **BLE mesh pairing** (if starting from factory reset)
- **Session key** (from pairing or HCI sniffing)
- **Encrypted commands** (using session key)

The handshake disconnection you're experiencing is likely because:
1. Device is unpaired (telink_mesh1 state)
2. Device expects pairing request (Frame Type 1)
3. We're sending handshake instead of pairing
4. Device rejects and disconnects

**Next immediate step**: Search decomp for pairing implementation to find Frame Type 1 packet format.
