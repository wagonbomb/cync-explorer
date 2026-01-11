# HCI Log Analysis Findings

## Summary

Successfully captured and parsed HCI log from GE Cync app pairing and controlling bulb.

**File:** `artifacts/hci_logs/btsnoop_hci_fresh.log` (1.4 MB)
**Total packets:** 18,272
**ACL Data packets:** 287
**ATT Write operations:** 44 (all sent from phone to bulb)

---

## Discovered Characteristics

### Known Characteristics (from DEX analysis)
- **0x0011:** Telink Command (00010203-...-1912)
- **0x0014:** Mesh Prov In (2adb) - Write
- **0x0016:** Mesh Prov Out (2adc) - Notify
- **0x0019:** Mesh Proxy In (2add) - Write
- **0x001b:** Mesh Proxy Out (2ade) - Notify

### NEW Characteristics (discovered from HCI log)
- **0x0012:** Unknown - Receives 1-byte enable notification command (`01`)
- **0x0015:** Unknown - Receives **37 encrypted writes** (likely handshake, sync, and control commands)

**Important:** Handle 0x0015 is where most protocol traffic happens, NOT the mesh characteristics!

---

## Write Operations Breakdown

### Writes to 0x001b (Mesh Proxy Out - 2ade) - 6 total

**Early Writes (before pairing):**
```
Packet 1166: 0ca0a1a2a3a4a5a6a78db674711b855a79  (17 bytes)
Packet 1182: 0ca0a1a2a3a4a5a6a7c0c0d4abef0d15c3  (17 bytes)
```

**Pairing Sequence:**
```
Packet 8417: 045b7eab67f223368e4a7bc65139b4d9f5  (Pairing Network Name)
Packet 8431: 0574cc2e38baf1ef4484139556e9c4746e  (Pairing Password)
Packet 8460: 061061bdc9e752c21621b2a1eb0cb1968f  (Pairing LTK)
```

**Post-Pairing:**
```
Packet 8469: 0ca0a1a2a3a4a5a6a7c0c0d4abef0d15c3  (same as 1182)
```

### Writes to 0x0015 (Unknown) - 37 total

All encrypted/obfuscated data:
```
Packet 1370:  6d0500aec79538dc700342           (11 bytes)
Packet 1621:  9d5a00eeb97f77ecc276f3491f       (13 bytes)
Packet 1779:  3ef200a55e5053558f75d4b303       (13 bytes)
Packet 1852:  1ad400f8a10ec8dd35e2539a88       (13 bytes)
Packet 2448:  11ba009a89eb91040420ba           (11 bytes)
Packet 3057:  c8f900c6bf9444774d3dd3           (11 bytes)
Packet 4051:  ab2400674aafa7cce079487f         (12 bytes)
Packet 4054:  b21701d4c79a79566d6269c9fa1bec9cd85a4940  (20 bytes)
Packet 4058:  dd6902081e49926715666395513fbabffe149edc  (20 bytes)
Packet 4084:  d5ce03cba85bd13e617334a05b60023510ef93cf  (20 bytes)
Packet 4101:  0daa0414148faf55f0f2e7f82955       (14 bytes)
Packet 5981:  ee0600e07990909462e88c35         (12 bytes)
Packet 6006:  3c520126bce6041ad6467d374e3acde3d084e691  (20 bytes)
Packet 6009:  b3fa02251336b60bf5d0704ae57b0a92f431852f  (20 bytes)
Packet 6022:  20e70303286b85652170d68c28ed7a352b02d8e4  (20 bytes)
Packet 6032:  49bf049890cf130655a39beca128       (14 bytes)
Packet 7193:  e17400e02dc6c896cce39450         (12 bytes)
Packet 7199:  3487002f2c286b3b7294d1           (11 bytes)
Packet 7239:  8c9e0025c160dbfb084f2e           (11 bytes)
Packet 7572:  65c90046f147fbe2ad86095e         (12 bytes)
Packet 7614:  0f6700b64b02ea83c07fd3           (11 bytes)
Packet 7628:  45f2009f672f9f9d6f569e           (11 bytes)
Packet 7967:  d692005370750317cd9317cb         (12 bytes)
Packet 8513:  71f4005d0d6a71e29e3e134f         (12 bytes)
Packet 8529:  ed4600fd4e997a2b0f9fa3a3e5       (13 bytes)
Packet 8554:  7e6100a835e322681373d6be9cf6fc4737478683  (20 bytes)
Packet 8728:  020000fb62c82c7dbefbf76d4d       (13 bytes)
Packet 8917:  fc5500445c0441d68b2ee45a         (12 bytes)
Packet 8953:  8e8a0076587cd75d5fc613a4         (12 bytes)
Packet 9833:  4d6a00f4fd2dae3c58aae72f         (12 bytes)
Packet 9850:  dfad00e3b5d71fd46d3dd4fe         (12 bytes)
Packet 9874:  1f8b0053ac634c49e6c70115         (12 bytes)
Packet 9875:  201c00c79c5ee37262aae5f4070ff27a0a8f1c94  (20 bytes)
Packet 9972:  be50002fa9ee72df694dd682         (12 bytes)
Packet 10909: fd4b003567d1109fb7a2aec6         (12 bytes)
Packet 11153: 5f2b00ef343485eaef9ac8e4         (12 bytes)
Packet 11481: f5cd001a2fcb0ba6b1de6707         (12 bytes)
```

### Writes to 0x0012 (Unknown) - 1 total

```
Packet 1354: 01  (Enable notifications)
```

---

## Key Insights

### 1. Characteristic 0x0015 is Critical
- Receives 37 out of 44 writes (84%)
- Likely handles all handshake, sync, auth, and control commands
- Not documented in any DEX files
- All data appears encrypted or obfuscated

### 2. Mesh Proxy Out (0x001b) Used for Pairing
- Despite being a "notify" characteristic, app writes to it
- Pairing credentials sent here (opcodes 0x04, 0x05, 0x06)
- Some pre/post-pairing control commands

### 3. No Clear Handshake Packets
- Did NOT find `000501...`, `000001...`, or `3100-3104` patterns
- These sequences either:
  - Don't exist (protocol is different than POC tests)
  - Are encrypted before transmission
  - Are sent to a different characteristic

### 4. Data Encryption
- Most writes are encrypted/obfuscated
- Cannot identify handshake, sync, or control commands by inspection
- Need to decrypt or find encryption key

---

## Next Steps

1. **Identify Handle 0x0015**
   - Use `bleak` to scan bulb and enumerate all characteristics
   - Match handle 0x0015 to its UUID
   - Understand its role in protocol

2. **Decrypt Protocol Traffic**
   - Reverse engineer encryption used for handle 0x0015 writes
   - Look for encryption in libBleLib.so
   - Try known keys (network key, LTK from pairing)

3. **Correlate with User Actions**
   - Map packet timestamps to known actions (ON/OFF/brightness)
   - Identify which packets correspond to which commands
   - Find patterns in encrypted data

4. **Test with Known Commands**
   - Replay captured packets to bulb
   - See which ones actually control the light
   - Reverse engineer command structure from working packets

---

## Pairing Credentials (Encrypted)

**From packets 8417, 8431, 8460 - sent to 0x001b:**

```python
encrypted_network_name = bytes.fromhex("5b7eab67f223368e4a7bc65139b4d9f5")
encrypted_password = bytes.fromhex("74cc2e38baf1ef4484139556e9c4746e")
encrypted_ltk = bytes.fromhex("1061bdc9e752c21621b2a1eb0cb1968f")
```

These should decrypt to:
- Network name: "out_of_mesh" (padded to 16 bytes)
- Password: "123456" (padded to 16 bytes)
- LTK: `D00710A0A601370854E32E177AFD1159` (network key)

**Can reverse engineer encryption by comparing encrypted vs plaintext!**

---

## Files Generated

- `artifacts/hci_logs/btsnoop_hci_fresh.log` - Raw HCI capture (1.4 MB)
- `artifacts/hci_logs/writes_analysis.txt` - Complete write operation analysis
- `artifacts/hci_logs/complete_analysis.txt` - Full ATT operation breakdown
- `md/HCI_FINDINGS.md` - This document
