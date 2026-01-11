# Cync BLE Control - Current Status & Next Steps

## What We've Discovered

### ✅ Working
1. **BLE Connectivity**: Can scan, connect, read/write to all characteristics
2. **Device Reset**: Factory reset via power cycling (5x ON/OFF) works
3. **Device States**:
   - Paired: Name = "C by GE", accepts mesh commands but ignores unauthorized ones
   - Factory Reset: Name = "telink_mesh1", waiting for provisioning
4. **Characteristics Mapped**: All 5 UUID characteristics identified and functional
5. **HCI Analysis**: Successfully extracted 380 commands from Android session

### ❌ Blocked
1. **Proprietary Provisioning Protocol**: Cync uses custom pairing (not standard BT Mesh)
2. **No Responses**: Device doesn't respond to standard Telink or mesh provisioning
3. **Encryption Required**: Commands from HCI logs only work when device is already paired
4. **Physical Control**: Zero light changes during all 50+ test attempts

## Home Assistant Integration Status

**Home Assistant Cync integration does NOT support BLE.**

- Uses cloud API only (pycync library)
- Requires Cync account login
- All control goes through GE servers
- "IoT Class: Cloud Push"
- [Source Code](https://github.com/home-assistant/core/tree/dev/homeassistant/components/cync)
- [Library: pycync](https://github.com/nikshriv/pycync) (cloud-only)

## What You Need for Custom BLE Control

Since no existing library supports Cync BLE, you have **3 options**:

### Option 1: Reverse Engineer the Cync App (Most Reliable)

**Tools Needed:**
- **Android APK Decompiler**: jadx, APKTool
- **Network Analysis**: Frida, objection (for runtime inspection)
- **BLE Sniffer**: nRF52840 dongle + Wireshark

**Steps:**
1. Download Cync APK from APKMirror
2. Decompile with `.\scripts\run_jadx.ps1` (jadx GUI or CLI)
3. Search for:
   - Telink provisioning code
   - Encryption key generation
   - Pairing sequence
   - Command structure after pairing
4. Find the default mesh password or key derivation algorithm
5. Implement in Python

**Likely Files to Check:**
- `com/ge/lighting/` (main package)
- `*/bluetooth/*` or `*/ble/*`
- `*/telink/*` or `*/mesh/*`
- Look for strings: "telink_mesh1", "pair", "provision"

### Option 2: Live BLE Sniffing (Requires Hardware)

**Hardware:**
- nRF52840 Dongle ($10) or Ubertooth One ($120)
- Or use built-in sniffer: `btmon` (Linux) / HCI log (Android)

**Process:**
1. Factory reset bulb
2. Start BLE sniffer
3. Pair bulb with Cync app
4. Control light (ON/OFF) multiple times
5. Capture ALL BLE packets including:
   - Pairing exchange
   - Encryption negotiation
   - Control commands
6. Analyze with Wireshark to find:
   - Pairing request/response
   - Encryption keys
   - Command structure

**Linux Command:**
```bash
# Built-in Bluetooth sniffer
sudo btmon -w cync_pairing.log

# Then use Wireshark to open cync_pairing.log
```

### Option 3: Use Cloud API + BLE Hybrid

**Approach:**
- Use pycync for initial provisioning via cloud
- Once provisioned, capture session keys from app memory
- Use those keys for local BLE control

**This requires:**
1. Root access on Android (or jailbreak iOS)
2. Memory dumping (GameGuardian, Frida)
3. Finding encryption keys in RAM during active session

## Recommended Approach

**I recommend Option 1 (Reverse Engineering)** because:

1. ✅ No additional hardware needed
2. ✅ One-time effort - once you find the protocol, it works forever
3. ✅ Can be automated completely
4. ✅ You already have Windows + Python environment

**Start here:**
```powershell
# Download jadx (Java Decompiler)
cd C:\Users\Meow\Documents\Projects\cync-explorer\tools-local
Invoke-WebRequest -Uri "https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip" -OutFile "jadx.zip"
Expand-Archive jadx.zip -DestinationPath jadx

# Download Cync APK
# Visit: https://www.apkmirror.com/apk/ge-lighting/
# Search for "Cync" and download latest APK
# Save to: C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\com.ge.cbyge.apk

# Decompile
cd C:\Users\Meow\Documents\Projects\cync-explorer
.\scripts\run_jadx.ps1

# Optional: run the search helper
python src\apk_search.py .\artifacts\cync_decompiled
```

Then search for:
- `telink` (case-insensitive)
- `mesh.*password`
- `provision`
- `0x0c` (the Telink pair command byte)
- `00010203-0405-0607` (Telink UUID)

## Alternative: Use Official App

If BLE control is not critical:

**Just use the cloud API with Home Assistant:**
1. Install Home Assistant Cync integration
2. Use cloud control (works perfectly)
3. Accept 100-200ms latency vs local BLE

**Benefits:**
- ✅ Works immediately
- ✅ No reverse engineering needed
- ✅ Officially supported
- ✅ Handles encryption automatically

## Summary

Your bulb is **working correctly** - it's just locked to Cync's proprietary provisioning protocol. The HCI logs you have only work AFTER the bulb is provisioned through the official app with the correct encryption keys.

**Next Action**: Choose your path forward:
- **Quick solution**: Use Home Assistant cloud integration
- **Full control**: Reverse engineer Cync APK for BLE protocol
- **Hardware path**: Buy nRF52840 dongle for live sniffing

Let me know which direction you want to go, and I can provide detailed steps!
