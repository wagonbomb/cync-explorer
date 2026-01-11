# Cync APK Reverse Engineering Guide

## Step 1: Install Java (Required for jadx)

```powershell
# Check if Java is installed
java -version

# If not installed, download from:
# https://adoptium.net/temurin/releases/
# Install JDK 17 or later
```

## Step 2: Download jadx (APK Decompiler)

```powershell
# Download jadx
cd C:\Users\Meow\Documents\Projects\cync-explorer\tools-local
Invoke-WebRequest -Uri "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip" -OutFile "jadx.zip"
Expand-Archive -Path jadx.zip -DestinationPath jadx -Force

# Verify installation
.\jadx\bin\jadx.bat --help
```

## Step 3: Download Cync APK

**Option A: From Device (if you have Android phone)**
```powershell
# Use ADB to pull APK from phone
adb shell pm list packages | findstr cync
adb shell pm path com.gelighting.cync
adb pull /data/app/.../base.apk cync.apk
```

**Option B: From APKMirror (recommended)**
1. Visit: https://www.apkmirror.com/apk/ge-lighting/
2. Search for "Cync" or "C by GE"
3. Download latest version
4. Save to: `C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\com.ge.cbyge.apk`

**Option C: From APKPure**
1. Visit: https://apkpure.com/cync/com.gelighting.cync
2. Download APK
3. Save to Downloads folder

## Step 4: Decompile APK

```powershell
cd C:\Users\Meow\Documents\Projects\cync-explorer

# GUI mode (recommended - easier to browse)
.\tools-local\jadx\bin\jadx-gui.bat .\artifacts\com.ge.cbyge.apk

# OR command-line mode (faster)
.\tools-local\jadx\bin\jadx.bat -d .\artifacts\cync_decompiled .\artifacts\com.ge.cbyge.apk
```

## Step 5: Search for Key Information

### What to Look For

**1. Telink Provisioning Code**
Search for these strings in jadx:
- `telink_mesh1` (default device name)
- `00010203-0405-0607-0809-0a0b0c0d1912` (Telink UUID)
- `0x0c` or `0x0C` (pair command)
- `provision`
- `pair`

**2. Mesh Password/Keys**
- `password`
- `mesh.*pass`
- `auth`
- `123` (common default)
- `0x313233` (hex for "123")

**3. BLE Connection Code**
- `BluetoothGatt`
- `writeCharacteristic`
- `onCharacteristicWrite`
- `00002adb` (Mesh Provisioning In UUID)

**4. Encryption**
- `encrypt`
- `decrypt`
- `AES`
- `key`
- `crypto`

### Using jadx-gui

1. Open APK in jadx-gui
2. Press `Ctrl+Shift+F` to open text search
3. Search for each term above
4. Look at the code context around matches

### Using grep (command-line)

```powershell
cd C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\cync_decompiled

# Search for Telink references
Get-ChildItem -Recurse -Filter *.java | Select-String -Pattern "telink" -CaseSensitive:$false

# Search for mesh password
Get-ChildItem -Recurse -Filter *.java | Select-String -Pattern "mesh.*pass" -CaseSensitive:$false

# Search for provisioning
Get-ChildItem -Recurse -Filter *.java | Select-String -Pattern "provision" -CaseSensitive:$false

# Search for the Telink UUID
Get-ChildItem -Recurse -Filter *.java | Select-String -Pattern "00010203-0405-0607-0809"

# Search for characteristic writes
Get-ChildItem -Recurse -Filter *.java | Select-String -Pattern "writeCharacteristic"
```

## Step 6: Key Files to Check

Look for these package names in the decompiled source:

- `com.gelighting.cync.*`
- `com.ge.lighting.*`
- `*.bluetooth.*`
- `*.ble.*`
- `*.telink.*`
- `*.mesh.*`

Likely important files:
- `*BleManager*.java`
- `*BluetoothService*.java`
- `*TelinkDevice*.java`
- `*MeshDevice*.java`
- `*ProvisionManager*.java`
- `*PairingActivity*.java`

## Step 7: What We're Looking For

### Example 1: Mesh Password
```java
// Might look like:
private static final String MESH_PASSWORD = "123";
// OR
byte[] password = "telink_mesh1".getBytes();
// OR  
return new byte[]{0x31, 0x32, 0x33}; // "123" in hex
```

### Example 2: Pairing Command
```java
// Might look like:
byte[] pairCommand = new byte[]{0x0c, ...};
characteristic.write(pairCommand);
// OR
public static final byte CMD_PAIR = 0x0c;
```

### Example 3: Provisioning Sequence
```java
// Might look like:
void provisionDevice() {
    sendCommand(0x0c); // pair
    sendMeshName("telink_mesh1");
    sendPassword("123");
    // ... encryption setup
}
```

## Step 8: Create Test Script

Once you find the provisioning code, we'll create a Python script to replicate it.

**Expected findings:**
1. Default mesh password (likely "123", "telink", or derived from MAC)
2. Pairing packet structure (what bytes to send on 0x0C command)
3. Encryption key derivation (how to generate session keys)
4. Command format after pairing

## Quick Start Commands

```powershell
# Full automated search
cd C:\Users\Meow\Documents\Projects\cync-explorer
.\tools-local\jadx\bin\jadx.bat -d .\artifacts\cync_decompiled .\artifacts\com.ge.cbyge.apk

# Then run our search script
cd C:\Users\Meow\Documents\Projects\cync-explorer
python src\apk_search.py .\artifacts\cync_decompiled
```

---

**Next**: After downloading and decompiling, share any findings and we'll build the Python implementation!
