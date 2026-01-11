# GE Cync Bluetooth Mesh Protocol Specification

**Last Updated:** 2026-01-11
**Status:** Provisioning 90% complete, control commands pending

---

## Overview

GE Cync smart lights use **Bluetooth Mesh** with a Telink BLE SoC. Devices must be **provisioned** before accepting control commands. This document covers the complete protocol from provisioning through device control.

---

## 1. BLE Characteristics

| UUID | Name | Direction | Purpose |
|------|------|-----------|---------|
| `00002adb-...` | Mesh Prov In | Write | Provisioning PDU input |
| `00002adc-...` | Mesh Prov Out | Notify | Provisioning PDU output |
| `00002add-...` | Mesh Proxy In | Write | Mesh commands input |
| `00002ade-...` | Mesh Proxy Out | Notify | Mesh commands output |
| `00010203-...-1912` | Telink Command | Write | Legacy Telink commands |

---

## 2. Provisioning Protocol

### 2.1 PB-GATT PDU Format

All provisioning uses Proxy PDU wrapping:

```
┌─────────────┬──────────────────────────────────────┐
│   Header    │              Payload                 │
│   1 byte    │             N bytes                  │
└─────────────┴──────────────────────────────────────┘

Header byte:
  Bits 6-7: SAR (Segmentation)
    00 = Complete message
    01 = First segment
    10 = Continuation
    11 = Last segment
  Bits 0-5: Message Type
    0x03 = Provisioning PDU
```

### 2.2 Provisioning PDU Types

| Type | Name | Direction | Size |
|------|------|-----------|------|
| 0x00 | Invite | → Device | 2 bytes |
| 0x01 | Capabilities | ← Device | 12 bytes |
| 0x02 | Start | → Device | 6 bytes |
| 0x03 | Public Key | ↔ Both | 65 bytes |
| 0x05 | Confirmation | ↔ Both | 17 bytes |
| 0x06 | Random | ↔ Both | 17 bytes |
| 0x07 | Data | → Device | 34 bytes |
| 0x08 | Complete | ← Device | 1 byte |
| 0x09 | Failed | ← Device | 2 bytes |

### 2.3 Complete Provisioning Sequence

```
CLIENT                                          DEVICE
   │                                               │
   │─────── [03 00 00] Invite ────────────────────>│
   │        (attention=0)                          │
   │                                               │
   │<────── [03 01 ...] Capabilities ──────────────│
   │        (elements=4, algo=P256, staticOOB=1)   │
   │                                               │
   │─────── [03 02 00 00 00 00 00] Start ─────────>│
   │        (algo=0, pubkey=0, auth=NoOOB)         │
   │                                               │
   │─────── [03 03 ...] Public Key (64 bytes) ────>│
   │        (segmented: SAR=01, 10, 11)            │
   │                                               │
   │<────── [03 03 ...] Public Key (64 bytes) ─────│
   │                                               │
   │        ══ ECDH: SharedSecret computed ══      │
   │                                               │
   │─────── [03 05 ...] Confirmation (16 bytes) ──>│
   │                                               │
   │<────── [03 05 ...] Confirmation (16 bytes) ───│
   │                                               │
   │─────── [03 06 ...] Random (16 bytes) ────────>│
   │                                               │
   │<────── [03 06 ...] Random (16 bytes) ─────────│
   │                                               │
   │        ══ Confirmation VERIFIED ══            │
   │                                               │
   │─────── [03 07 ...] Encrypted Data (33 bytes) >│
   │        (NetworkKey + KeyIndex + Flags +       │
   │         IVIndex + UnicastAddr, AES-CCM)       │
   │                                               │
   │<────── [03 08] Complete ──────────────────────│
   │                                               │
```

### 2.4 Device Capabilities (Observed)

```
Elements:        4
Algorithms:      0x0001 (FIPS P-256 ECDH)
Public Key Type: 0 (No OOB Public Key)
Static OOB:      1 (Available, not required)
Output OOB:      0 (None)
Input OOB:       0 (None)
```

---

## 3. Cryptographic Functions

### 3.1 Salt Function (s1)

```python
def s1(m: bytes) -> bytes:
    """s1 salt generation"""
    return aes_cmac(bytes(16), m)
```

### 3.2 Key Derivation (k1)

```python
def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    """k1 key derivation"""
    t = aes_cmac(salt, n)
    return aes_cmac(t, p)
```

### 3.3 Key Derivation During Provisioning

```python
# After ECDH key exchange
confirmation_inputs = (
    invite_value +      # 1 byte: attention duration
    capabilities +      # 11 bytes
    start_value +       # 5 bytes
    provisioner_pubkey + # 64 bytes
    device_pubkey        # 64 bytes
)

# Confirmation phase
confirmation_salt = s1(confirmation_inputs)
confirmation_key = k1(ecdh_secret, confirmation_salt, b"prck")

# Provisioning data phase
provisioning_salt = s1(confirmation_salt + random_prov + random_device)
session_key = k1(ecdh_secret, provisioning_salt, b"prsk")
session_nonce = k1(ecdh_secret, provisioning_salt, b"prsn")[:13]
device_key = k1(ecdh_secret, provisioning_salt, b"prdk")
```

### 3.4 Confirmation Calculation

```python
# AuthValue for No OOB = 16 zero bytes
auth_value = bytes(16)

# Confirmation = AES-CMAC(ConfirmationKey, Random || AuthValue)
confirmation = aes_cmac(confirmation_key, random_value + auth_value)
```

### 3.5 Provisioning Data Encryption

```python
# Provisioning Data (25 bytes)
prov_data = (
    network_key +           # 16 bytes
    key_index.to_bytes(2) + # 2 bytes, big-endian
    flags +                 # 1 byte
    iv_index.to_bytes(4) +  # 4 bytes, big-endian
    unicast_addr.to_bytes(2) # 2 bytes, big-endian
)

# Encrypt with AES-CCM (8-byte MIC)
encrypted = aes_ccm_encrypt(session_key, session_nonce, prov_data)
# Result: 33 bytes (25 + 8 MIC)
```

---

## 4. Telink Frame Format

From Ghidra decompilation of `libBleLib.so`:

### 4.1 Variable-Length Encoding

```
┌──────────────┬────────────────┬───────────┬───────────┐
│  var_offset  │  var_total_len │  type_seq │   data    │
│   1-4 bytes  │   1-4 bytes    │   1 byte  │  N bytes  │
└──────────────┴────────────────┴───────────┴───────────┘
```

**7-bit encoding with continuation bit:**
- Value < 0x80: `[value & 0x7f]`
- Value < 0x4000: `[(value & 0x7f) | 0x80, (value >> 7) & 0x7f]`
- Continuation bit (0x80) indicates more bytes follow

**type_seq byte:**
- Bits 4-7: Frame type (0-15)
- Bits 0-3: Sequence number (0-15, wraps)

### 4.2 Example Encoding

| Raw Command | Framed |
|-------------|--------|
| `000501000000000000000000` | `000c00` + data |
| `3100` | `000202` + `3100` |
| `3101` | `000203` + `3101` |

---

## 5. Control Commands (Post-Provisioning)

### 5.1 Data Point Format

```
┌──────┬──────┬────────┬─────────────┐
│ DPID │ Type │ Length │    Value    │
│ 1B   │ 1B   │  1B    │   N bytes   │
└──────┴──────┴────────┴─────────────┘
```

**Data Types:**
- 0: Raw
- 1: Boolean
- 2: Value (integer)
- 3: String
- 4: Enum
- 5: Bitmap

### 5.2 Common Data Points

| DPID | Name | Type | Values |
|------|------|------|--------|
| 1 | Power | Bool | 0=Off, 1=On |
| 2 | Brightness | Value | 0-255 |
| 3 | Color Temp | Value | 2700-6500K |

### 5.3 Command Examples

```python
# Power ON
dp_command = bytes([0x01, 0x01, 0x01, 0x01])
#                   DPID  Type  Len   Value

# Set Brightness 50%
dp_command = bytes([0x02, 0x02, 0x01, 0x7F])
```

---

## 6. Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Provisioning Invite | ✅ | Working |
| Capabilities Parse | ✅ | Working |
| ECDH Key Exchange | ✅ | Working |
| Confirmation | ✅ | Verified |
| Random Exchange | ✅ | Verified |
| AES-CCM Encryption | ⚠️ | Decryption failed - format issue |
| Control Commands | ⏳ | Pending provisioning |

---

## 7. Error Codes

### 7.1 Provisioning Failed Reasons

| Code | Name | Description |
|------|------|-------------|
| 0x00 | Prohibited | Reserved |
| 0x01 | Invalid PDU | Unrecognized PDU |
| 0x02 | Invalid Format | Wrong format |
| 0x03 | Unexpected PDU | Wrong sequence |
| 0x04 | Confirmation Failed | Auth mismatch |
| 0x05 | Out of Resources | Device busy |
| 0x06 | Decryption Failed | CCM decrypt error |
| 0x07 | Unexpected Error | Generic error |
| 0x08 | Cannot Assign Addr | Address conflict |

---

## 8. References

- Bluetooth Mesh Profile Specification v1.0.1
- Bluetooth Mesh Model Specification v1.0.1
- `libBleLib.so` decompilation (Ghidra)
- GE Cync Android APK v6.20.0 analysis
