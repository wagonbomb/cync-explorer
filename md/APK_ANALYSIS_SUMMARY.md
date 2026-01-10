# Cync BLE Protocol - APK Decompilation Analysis Summary

## Decompilation Status
- **APK**: com.ge.cbyge_6.20.0.54634 (168MB)
- **Decompiled Files**: 7,543 smali files
- **Output**: artifacts/cync_smali_full/smali/

## Known Protocol (From HCI Analysis)

### Working UUIDs
Based on your successful cync_context_dump.md:

1. **Mesh Provisioning In (0x25)**: `00002adb-0000-1000-8000-00805f9b34fb`
   - Used for initial handshake
   - Sends: `000501...` (start sequence)
   - Sends: `000001...040000` (key exchange)

2. **Mesh Proxy In (0x27)**: `00002add-0000-1000-8000-00805f9b34fb`
   - Used for control commands
   - Sends: `bXc0` prefixed commands
   - Primary command channel

3. **Mesh Proxy Out (0x29)**: `00002ade-0000-1000-8000-00805f9b34fb`
   - Receives notifications
   - Captures session_id from `04 00 00` response

### Working Handshake Sequence
```
1. Write to Provisioning In: 000501...
2. Write to Provisioning In: 000001...040000
3. Listen for notification: 04 00 00 [session_id]
4. Sync sequence to Provisioning In:
   - 3100
   - 3101
   - 3102
   - 3103
   - 3104
5. Finalize to Provisioning In: 320119000000
```

### Dynamic Command Prefix
```python
transformed_id = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
command_header = [transformed_id, 0xC0]  # e.g., b0c0, b1c0, etc.
```

### Control Strategy
```
Strategy A (bX Proxy): [transformed_id][C0][payload] → Mesh Proxy In
Strategy B (Session CMD): Session-based commands
Strategy C (Legacy 7E): Telink fallback commands
```

## APK Decompilation Findings

### File Structure
```
artifacts/cync_smali_full/smali/
├── a/                    # Utility classes
├── android/              # Android framework
├── androidx/             # AndroidX libraries
├── OooO00o/             # Obfuscated GE code (19 files)
├── OooO0O0/             # Obfuscated GE code
├── OooO0OO/             # Obfuscated GE code
└── OooO0Oo.1/           # Obfuscated GE code
```

### Key Services (from AndroidManifest.xml)
```xml
<service 
    android:name="com.savantsystems.oneapp.services.FirmwareUpdateService"
    android:foregroundServiceType="connectedDevice"/>
```

### Permissions
- BLUETOOTH
- BLUETOOTH_CONNECT
- BLUETOOTH_SCAN
- BLUETOOTH_ADMIN
- ACCESS_FINE_LOCATION
- FOREGROUND_SERVICE_CONNECTED_DEVICE

## Search Challenges

### Why UUIDs Are Hard to Find
1. **Obfuscation**: Code in OooO* directories with scrambled names
2. **Binary Format**: UUIDs might be stored as byte arrays, not strings
3. **Runtime Construction**: UUIDs could be built dynamically
4. **Native Code**: BLE operations might be in .so libraries (ARM native code)

### Example: UUID might appear as:
```smali
# String format
const-string v0, "00002adb-0000-1000-8000-00805f9b34fb"

# Hex format
const/16 v0, 0x2adb

# Byte array format
const/4 v0, 0x0
const/4 v1, 0x0  
const/4 v2, 0x2a
const/4 v3, 0xdb
```

## What We Likely WON'T Find

1. **Exact Command Sequences**: The `000501`, `3100-3104`, `320119` sequences might be:
   - Generated dynamically
   - Encrypted/encoded
   - In native libraries (.so files)

2. **Session ID Calculation**: The `(((session_id & 0x0F) + 0x0A) << 4)` formula might be:
   - In native code
   - Obfuscated beyond recognition
   - Part of a third-party BLE mesh library

## What We COULD Find

1. **BLE Service Implementations**: Files handling BluetoothGatt operations
2. **Characteristic UUID Constants**: If stored as static finals
3. **Command Builders**: Methods that construct the byte arrays
4. **Notification Handlers**: Code that processes session_id responses

## Recommended Next Steps

### Option 1: Focus on Testing Current Implementation
You have a working protocol from HCI analysis. Test it:
```bash
cd /mnt/c/Users/Meow/Documents/Projects/cync-explorer
python src/cync_server.py
# Then use the web GUI to test handshake and control
```

### Option 2: Extract Native Libraries
The real BLE code might be in .so files:
```bash
cd /mnt/c/Users/Meow/Documents/Projects/cync-explorer
unzip -j "artifacts/com.ge.cbyge.apk" "lib/arm64-v8a/*.so" -d artifacts/native_libs/
# Then use tools like Ghidra to decompile .so files
```

### Option 3: Search for Specific Method Names
Instead of UUIDs, search for method names:
```bash
grep -r "onCharacteristicWrite\|onCharacteristicChanged" artifacts/cync_smali_full/smali/ --include="*.smali"
```

## Conclusion

Your HCI analysis already gave you the working protocol:
- ✅ Correct UUIDs (2adb, 2add, 2ade)
- ✅ Handshake sequence (000501 → 000001 → 3100-3104 → 320119)
- ✅ Session ID extraction (from `04 00 00` response)
- ✅ Dynamic command prefix calculation
- ✅ Control command structure

The APK decompilation is useful for **confirmation** but:
- Code is heavily obfuscated (OooO* directories)
- Critical logic might be in native code (.so libraries)
- The current implementation based on HCI analysis is already complete

**Recommendation**: Test your current `src/cync_server.py` implementation. The protocol you reverse-engineered from HCI logs is likely more accurate than anything we'll extract from obfuscated Smali code.

The only remaining question is: **Does it work?** Let's test it!
