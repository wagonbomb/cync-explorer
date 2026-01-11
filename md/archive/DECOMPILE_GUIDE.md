# Complete APK Decompilation Guide

## 🎯 Goal
Fully decompile the Cync Android APK to extract BLE provisioning protocol

## 📋 Prerequisites
- ✅ Java 17+ installed (you have Java 25)
- ✅ Python 3.11 installed
- ⚠️ Cync APK file (~175 MB)

## 🚀 Quick Start (3 Steps)

### Step 1: Download the APK
```powershell
.\scripts\download_apk.ps1
```

This will:
- Open APKCombo in your browser
- Guide you to download `com.ge.cbyge.apk`
- Save it to `C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\com.ge.cbyge.apk`

**Manual alternative:** Download from https://apkcombo.com/cync/com.ge.cbyge/

---

### Step 2: Run Complete Decompilation
```powershell
.\scripts\run_complete_decompile.bat
```

This will:
- Download APKTool if needed (23 MB)
- Decompile ALL DEX files (classes.dex, classes2.dex, etc.)
- Extract to `artifacts\cync_smali_full\` directory
- Verify all 85,000+ classes were extracted

**Expected output:**
```
Total .smali files: 80,000+
Smali directories: 10+ (smali, smali_classes2, smali_classes3, etc.)
Decompiled: 95%+ of classes
```

**Time:** 5-10 minutes depending on your CPU

---

### Step 3: Search for BLE Code
```bash
python src/quick_ble_search.py
```

This will:
- Search all decompiled code for BLE UUIDs (2b11, 2b12, 1912, etc.)
- Find BluetoothGatt.writeCharacteristic calls
- Show you the files containing provisioning logic

---

## 🔍 What We're Looking For

### Critical BLE UUIDs
Our tests found these UUIDs in use:
- **2b11** - Mesh Provisioning In (device receives data)
- **2b12** - Mesh Provisioning Out (device sends data)  
- **1912** - Telink Command characteristic
- **1914** - Telink Status characteristic
- **00010203-0405-0607-0809** - Telink service UUID

### Key Code Patterns
Looking for Smali code that:
1. Writes to characteristic 2b11 (provisioning handshake)
2. Reads from characteristic 2b12 (device responses)
3. Contains byte arrays like `0x00, 0x05, 0x01` (HCI log patterns)
4. Implements authentication/password logic

---

## 📂 Output Structure

After decompilation, you'll have:

```
artifacts/cync_smali_full/
├── AndroidManifest.xml          # App manifest (package info, permissions)
├── res/                          # Resources (strings, layouts, images)
├── smali/                        # Main DEX (10,000+ classes)
├── smali_classes2/               # Additional DEX files
├── smali_classes3/               # (multidex for large apps)
├── smali_classes4/
├── ...
└── smali_classes10+/
```

**Why so many smali directories?**
Android has a 64K method limit per DEX file. Large apps like Cync (286,557 methods) split code across multiple DEX files. APKTool creates one smali directory per DEX.

---

## 🛠️ Troubleshooting

### "APK not found"
- Download from: https://apkcombo.com/cync/com.ge.cbyge/
- Save as: `C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\com.ge.cbyge.apk`
- Verify size is ~175 MB

### "Java not found"  
You have Java 25 installed, but it might not be in PATH:
```powershell
# Check current Java
java -version

# If not found, restart PowerShell or run:
$env:PATH += ";C:\Program Files\Eclipse Adoptium\jdk-25.0.1.11-hotspot\bin"
```

### "APKTool failed"
The APK might be using resource compression. Try:
```powershell
java -jar tools-local\apktool.jar d -f -r -o artifacts\cync_smali_full artifacts\com.ge.cbyge.apk
```
The `-r` flag skips resource decompilation (faster, Smali only)

### "Only 10,000 classes extracted (not 85,000)"
This is what happened before. The issue is:
- Old decompilation (`artifacts\cync_smali\`) only has smali/ directory
- Complete decompilation needs smali_classes2, smali_classes3, etc.
- Run `scripts\complete_decompile.ps1` to get ALL DEX files

---

## 🎓 Understanding Smali

Smali is Android's assembly language (like x86 assembly but for Android).

**Example - Finding a UUID:**
```smali
const-string v0, "00010203-0405-0607-0809"
invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;
```
This creates a UUID object - if you see "2b11" nearby, that's our target!

**Example - Writing to BLE:**
```smali
invoke-virtual {p0, v1, v2, v3}, Landroid/bluetooth/BluetoothGatt;->writeCharacteristic(
    Landroid/bluetooth/BluetoothGattCharacteristic;[BI)I
```
This is the actual BLE write operation we need to find!

---

## 📊 Progress Tracking

- [x] APKTool downloaded (23 MB)
- [ ] Cync APK downloaded (175 MB) ← **YOU ARE HERE**
- [ ] Complete decompilation run
- [ ] BLE code located (UUID 2b11 search)
- [ ] Provisioning sequence identified
- [ ] Python implementation created
- [ ] Light control achieved!

---

## 🔗 Related Files

- `scripts\complete_decompile.ps1` - Main decompilation script
- `scripts\run_complete_decompile.bat` - Easy-to-run batch file
- `scripts\download_apk.ps1` - APK download helper
- `src\quick_ble_search.py` - Fast BLE code searcher
- `src\explore_ble_code.py` - Interactive code explorer
- `md\PROJECT_ARCHITECTURE.md` - Full project documentation

---

## 💡 Tips

1. **Use src/quick_ble_search.py first** - It's fast and finds the important files
2. **Focus on UUID 2b11** - This is where provisioning data goes
3. **Look for byte arrays** - Commands like `0x00, 0x05, 0x01` from HCI logs
4. **Check smali_classes2+** - The BLE code might not be in the main smali/

---

## 🆘 Need Help?

If you get stuck:
1. Check that Java is working: `java -version`
2. Verify APK exists and is ~175 MB
3. Look at APKTool output for error messages
4. Try the `-r` flag to skip resources if it's taking too long

The goal is to get 80,000+ .smali files extracted, then we can find the provisioning code!
