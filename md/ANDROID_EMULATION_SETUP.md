# Android Emulation Setup for BLE Protocol Capture

## Problem

The GE Cync device requires enabling notifications on the Telink Status characteristic (UUID 1911), but Windows BLE stack blocks this with "Write Not Permitted" error. The Android Cync app works fine because Android's BLE stack doesn't have this limitation.

## Solution: Android Emulation with BLE Passthrough

### Option 1: BlueStacks with BLE Support (Recommended)

**Requirements:**
- BlueStacks 5 or later
- USB Bluetooth adapter (built-in Bluetooth usually won't work for passthrough)

**Setup:**
1. Download and install BlueStacks 5: https://www.bluestacks.com/
2. In BlueStacks settings, enable "Android Debug Bridge (ADB)"
3. Install the Cync APK (can sideload or get from Google Play)
4. For BLE passthrough, you may need:
   - A rooted BlueStacks instance
   - OR use WSA (Windows Subsystem for Android) with BLE support

### Option 2: Windows Subsystem for Android (WSA)

**Requirements:**
- Windows 11 with WSA installed
- ADB tools
- Frida tools

**Setup:**
1. Install WSA from Microsoft Store (Amazon Appstore)
2. Enable Developer Mode in WSA settings
3. Connect ADB: `adb connect 127.0.0.1:58526`
4. Install Cync APK: `adb install com.ge.cbyge.apk`

### Option 3: Android-x86 on VirtualBox/VMware

**Requirements:**
- VirtualBox or VMware
- Android-x86 ISO
- USB passthrough for Bluetooth adapter

**Setup:**
1. Download Android-x86: https://www.android-x86.org/
2. Create VM with USB passthrough for Bluetooth adapter
3. Install Android and set up Play Store
4. Install Cync app

### Option 4: Physical Android Phone (Easiest)

If you have an Android phone:
1. Enable Developer Mode (Settings > About > Tap Build Number 7 times)
2. Enable USB Debugging
3. Connect phone via USB
4. Install Frida server on phone

## Capturing the Protocol

### Method 1: Frida Hooks (Recommended)

Frida allows hooking into the app's BLE API calls in real-time.

**Setup Frida:**
```bash
# Install Frida tools on your PC
pip install frida-tools

# Download Frida server for Android
# Get the version matching your frida-tools:
# https://github.com/frida/frida/releases

# Push to Android device
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"
```

**Run the hook:**
```bash
# Start Cync app with Frida
frida -U -f com.ge.cbyge -l scripts/frida_ble_hook.js --no-pause

# Or attach to running app
frida -U com.ge.cbyge -l scripts/frida_ble_hook.js
```

**What the hook captures:**
- All GATT characteristic writes (with UUIDs and data)
- All notification subscriptions
- All received notifications
- Native library calls (session key generation, command encoding)

### Method 2: Android HCI Snoop Log

Android can capture all Bluetooth traffic.

**Enable HCI Snoop:**
1. Go to Developer Options
2. Enable "Bluetooth HCI snoop log"
3. Pair with the device using Cync app
4. Pull the log: `adb pull /sdcard/btsnoop_hci.log`

**Analyze with Wireshark:**
```bash
wireshark btsnoop_hci.log
```

### Method 3: ADB Logcat

```bash
# Filter for BLE logs
adb logcat | grep -i "gatt\|ble\|bluetooth"
```

## Expected Output

When you run the Frida hook and pair a device in the Cync app, you should see:

```
[NOTIFY] UUID: 00010203-0405-0607-0809-0a0b0c0d1911
         Enable: true

[WRITE] UUID: 00010203-0405-0607-0809-0a0b0c0d1912
        Data: 000501000000000000000000

[NOTIFY_RX] UUID: 00010203-0405-0607-0809-0a0b0c0d1911
            Data: 00060100000000000000000001

[JNI] madeSessionKey
      Name: telink_mesh1
      Password: 123
      Result: <session_key_bytes>
```

This will reveal:
1. The exact characteristic used for writes
2. The exact data format for handshake
3. How the session key is derived
4. The complete protocol sequence

## Next Steps After Capture

1. Document all captured write sequences
2. Note which UUIDs are used for writes vs notifications
3. Extract session key algorithm from `madeSessionKey` calls
4. Compare with our current implementation
5. Implement correct protocol in Python

## Files to Use

- `scripts/frida_ble_hook.js` - Frida hook script for BLE capture
- `artifacts/com.ge.cbyge_*.apk` - Cync APK for installation
- `src/cync_server.py` - Web server to update with correct protocol
