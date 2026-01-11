# Reverse Engineering Process

This document describes how we reverse engineered the GE Cync Bluetooth Mesh protocol.

---

## Phase 1: APK Analysis

### 1.1 Obtaining the APK

Downloaded GE Cync Android app (v6.20.0) from APKMirror.

### 1.2 DEX Decompilation

Used jadx to decompile the APK:

```bash
jadx -d decomp/raw cync_v6.20.0.apk
```

### 1.3 Key Findings from Java Code

**BLE UUIDs** (from `bppbqbb.java`):
- `00002adb` - Mesh Provisioning In
- `00002adc` - Mesh Provisioning Out
- `00002add` - Mesh Proxy In
- `00002ade` - Mesh Proxy Out

**JNI Interface** (from `BLEJniLib.java`):
```java
public class BLEJniLib {
    native byte[] getNormalRequestData(...);
    native byte[] getCommandRequestData(...);
    native void madeSessionKey(...);
    native void parseDataRecived(...);
}
```

---

## Phase 2: Native Library Analysis

### 2.1 Library Extraction

Extracted `libBleLib.so` (16KB ARM64) from APK:
```
apk_extracted/lib/arm64-v8a/libBleLib.so
```

### 2.2 Ghidra Decompilation

Imported into Ghidra and decompiled all functions:

```bash
# Export script: scripts/ghidra/ExportAllFunctions.py
# Output: artifacts/ghidra-output/libBleLib.so.c
```

### 2.3 Key Functions Discovered

**Packet Framing** (`trsmitr_send_pkg_encode`):
- 7-bit variable-length encoding
- Frame: [var_offset][var_total_len][type_seq][data]
- type_seq: upper nibble = type, lower nibble = sequence

**KLV Encoding** (`make_klv_list`, `data_2_klvlist`):
- Key: 2 bytes (little-endian)
- Length: 1 byte
- Value: N bytes

**Session Key** (`made_session_key`):
- External function (not in libBleLib.so)
- Likely in another native library

---

## Phase 3: HCI Traffic Analysis

### 3.1 Capturing BLE Traffic

Used Android HCI snoop log:
```bash
adb bugreport > bugreport.zip
# Extract: FS/data/misc/bluetooth/logs/btsnoop_hci.log
```

### 3.2 Initial Protocol Discovery

Captured handshake sequence from working app:
```
→ 000501000000000000000000   (Handshake Start)
→ 00000100000000000000040000 (Key Exchange)
← 04 00 00 [session_id]      (Session Response)
→ 3100, 3101, 3102, 3103, 3104 (Sync)
→ 320119000000               (Auth Finalize)
```

### 3.3 Session ID Transformation

Discovered prefix calculation:
```python
prefix = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
```

---

## Phase 4: Provisioning Discovery

### 4.1 The Breakthrough

Device wasn't responding to commands. Testing revealed:
- Device advertises **Mesh Provisioning** service (0x1827)
- Standard BT Mesh requires provisioning before control

### 4.2 PB-GATT Testing

Sent Provisioning Invite → Device responded with Capabilities!

```python
# Send: [03 00 00] (Proxy header + Invite + attention=0)
# Recv: [03 01 04 00 01 00 01 00 00 00 00 00 00]
#       Capabilities: 4 elements, P-256 ECDH, StaticOOB available
```

### 4.3 Full Provisioning Exchange

Successfully completed:
1. ✅ Invite → Capabilities
2. ✅ Start (No OOB)
3. ✅ Public Key exchange
4. ✅ ECDH shared secret
5. ✅ Confirmation exchange
6. ✅ Random exchange
7. ✅ Confirmation verified!
8. ⚠️ Provisioning Data (AES-CCM issue)

---

## Phase 5: Current Status

### Working
- Complete provisioning handshake up to data encryption
- Key derivation verified (confirmation matches)
- ECDH key exchange
- AES-CMAC calculations

### Remaining Issue
AES-CCM encryption of provisioning data returns DECRYPTION_FAILED.

Possible causes:
- CCM nonce format
- CCM parameter mismatch (M, L values)
- Byte order in encrypted payload

---

## Tools Used

| Tool | Purpose |
|------|---------|
| jadx | DEX decompilation |
| Ghidra | Native library decompilation |
| Wireshark | HCI log analysis |
| bleak | Python BLE library |
| BlueZ | Linux Bluetooth stack |

---

## Files Generated

| File | Description |
|------|-------------|
| `artifacts/ghidra-output/libBleLib.so.c` | Decompiled C code |
| `src/protocol/telink_framing.py` | Framing implementation |
| `src/linux_ble_provision*.py` | Provisioning scripts |
