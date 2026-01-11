# Development Log

## 2026-01-11: Major Provisioning Breakthrough

### Achievements
- Ghidra decompilation of libBleLib.so complete
- Implemented Telink 7-bit variable-length framing
- Discovered device requires Bluetooth Mesh provisioning
- Successfully completed ECDH key exchange
- Confirmation/Random exchange verified!
- Pushed to GitHub: https://github.com/wagonbomb/cync-explorer

### Current Issue
AES-CCM encryption of provisioning data fails with DECRYPTION_FAILED (0x06).

The encryption parameters are:
- Key: SessionKey (16 bytes)
- Nonce: SessionNonce (13 bytes)
- Plaintext: 25 bytes (NetKey + KeyIndex + Flags + IVIndex + UnicastAddr)
- Output: 33 bytes (25 + 8 byte MIC)

Debugging needed for CCM format.

---

## Previous Work

### Windows BLE Limitation
Windows BLE stack cannot subscribe to Telink 1911 characteristic notifications (missing CCCD descriptor). Switched to WSL2 with USB Bluetooth passthrough.

### BlueZ "Notify acquired"
BlueZ locks notification on Telink 1911. Workaround: Use Mesh Proxy characteristics (2adc/2ade) instead.

### Initial Protocol Discovery
From HCI capture, identified handshake sequence:
- START: 000501...
- KEY_EXCHANGE: 000001...040000
- SYNC: 3100-3104
- AUTH: 320119...

This sequence is for already-provisioned devices. Unprovisioned devices need full Mesh provisioning first.

---

## Next Steps

1. **Fix AES-CCM encryption**
   - Check CCM nonce format (flags + nonce + counter)
   - Verify L parameter (length field size)
   - Compare with Bluetooth Mesh spec examples

2. **Complete provisioning**
   - Send encrypted provisioning data
   - Receive Provisioning Complete

3. **Control commands**
   - Implement brightness control
   - Implement color temperature
   - Test ON/OFF

4. **Multi-device support**
   - Mesh network management
   - Device discovery
   - Group control

---

## Test Device

| Property | Value |
|----------|-------|
| MAC | 34:13:43:46:CA:84 |
| Name | "C by GE" / "telink_mesh1" |
| Elements | 4 |
| Algorithms | P-256 ECDH |
| Static OOB | Available |
