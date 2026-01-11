# Windows BLE Limitation - GE Cync Devices

## Summary

The GE Cync smart bulb uses a Telink mesh protocol that **cannot be fully implemented on Windows** due to a fundamental BLE stack limitation.

## The Problem

1. **Notification Subscription Blocked**
   - The Telink Status characteristic (UUID 1911) does NOT have a CCCD (Client Characteristic Configuration Descriptor)
   - Windows BLE stack refuses to enable notifications without a CCCD
   - Error: `Protocol Error 0x03: Write Not Permitted`

2. **Interactive Protocol Requirement**
   - The Cync handshake is bidirectional - each command expects a response
   - The sync sequence (3100-3104) returns device-specific random data
   - This data is likely used for session key derivation
   - Without receiving responses, the session cannot be established

3. **Read Causes Disconnect**
   - Attempting to read from characteristic 1911 causes immediate disconnection
   - This prevents any workaround via polling

## What Works on Windows

- BLE scanning and device discovery
- Connecting to the device
- Writing to characteristics (1912, PROV_IN, PROXY_IN)
- Subscribing to MESH_PROV_OUT (2adc) and MESH_PROXY_OUT (2ade)

## What Doesn't Work on Windows

- Subscribing to Telink Status (1911) notifications
- Receiving responses from the handshake protocol
- Completing the interactive session establishment
- Controlling the light (requires valid session)

## Protocol Flow (from HCI Log)

```
1. Enable notifications on 1911 (BLOCKED ON WINDOWS)
2. Send handshake start: 000501000000000000000000
3. Receive: 00060100000000000000000001
4. Send key exchange: 00000100000000000000040000
5. Receive: 00010100000000000000040000310001

6. Interactive sync:
   Send: 3100 -> Receive: 3100 + random bytes
   Send: 3101 -> Receive: 3101 + device data
   Send: 3102 -> Receive: 3102 + capabilities
   Send: 3103 -> Receive: 3103 + more data
   Send: 3104 -> Receive: 3104 + session info

7. Finalize: 320119000000
8. Receive: 320200 (success)
9. Session established - can now send b0c0XXXX commands
```

## Solutions

### Option 1: Android Emulation (Recommended)

Use Android to capture the exact protocol and verify our implementation.

**Setup:**
1. Install BlueStacks 5 or Android-x86
2. Configure BLE passthrough (requires USB Bluetooth adapter)
3. Install Cync APK
4. Use Frida hooks (`scripts/frida_ble_hook.js`) to capture traffic

**See:** `md/ANDROID_EMULATION_SETUP.md`

### Option 2: Physical Android Phone

1. Use any Android phone with BLE
2. Install Frida server
3. Run Frida hooks to capture exact byte sequences
4. Transfer captured protocol to our Python implementation

### Option 3: Linux

Linux BLE stack (BlueZ) handles notification subscriptions differently and may work where Windows fails.

```bash
# On Linux:
python src/cync_server.py
```

### Option 4: Proxy Through Android

1. Create an Android app that acts as BLE proxy
2. Android handles the Telink protocol
3. Exposes HTTP API for Windows to control
4. Essentially an Android-based HomeAssistant integration

## Files Created

| File | Purpose |
|------|---------|
| `src/precise_handshake.py` | Matches HCI log sequence exactly |
| `src/ble_pairing_test.py` | Tests pairing and notification subscription |
| `src/direct_cccd_write.py` | Attempts low-level CCCD access |
| `src/telink_wakeup.py` | Tests various wake-up sequences |
| `src/raw_gatt_test.py` | Low-level GATT experiments |
| `src/simple_connect.py` | Minimal connection test |
| `src/poll_handshake.py` | Polling approach (fails) |
| `src/blind_handshake.py` | Sends commands without reads |
| `scripts/frida_ble_hook.js` | Frida script for Android capture |

## Technical Details

### Telink Characteristic Structure

```
Service: 00010203-0405-0607-0809-0a0b0c0d1910 (Telink)
├── 1911 (Handle 0x0011): notify, write, read
│   └── Descriptor: 2901 (User Description) - NO CCCD!
├── 1912 (Handle 0x0014): write
│   └── Descriptor: 2901
├── 1913 (Handle 0x0017): write, read
│   └── Descriptor: 2901
└── 1914 (Handle 0x001a): write
    └── Descriptor: 2901
```

The absence of CCCD (0x2902) on characteristic 1911 violates Bluetooth spec but works on Android because Android's BLE stack is more permissive.

### Why Android Works

Android's BLE implementation allows notification subscriptions even without a formal CCCD by:
1. Using implicit notification registration
2. Not requiring a specific CCCD handle
3. More tolerant of non-standard implementations

## Next Steps

1. **Set up Android environment** (BlueStacks or physical device)
2. **Run Frida hooks** to capture exact protocol
3. **Verify protocol understanding** with captured data
4. **Consider alternative approaches:**
   - Create Android proxy app
   - Wait for HomeAssistant Cync integration
   - Use Linux for the BLE component
