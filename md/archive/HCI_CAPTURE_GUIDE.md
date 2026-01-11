# HCI Log Capture Guide - Windows

**Goal**: Capture Bluetooth traffic while using GE Cync app to control the bulb
**Time**: 15 minutes
**Output**: HCI log file with session keys and control commands

---

## Prerequisites

1. ✅ Bulb is factory reset (currently is)
2. ✅ GE Cync app installed on phone/tablet
3. ✅ Windows PC with Bluetooth adapter
4. ✅ USB cable to connect phone to PC (for Android)

---

## Method 1: Android Phone (Recommended - Easiest)

### Step 1: Enable Developer Options on Android

1. Open **Settings** on your Android phone
2. Go to **About Phone**
3. Tap **Build Number** 7 times
4. You'll see "You are now a developer!"

### Step 2: Enable Bluetooth HCI Snoop Log

1. Go to **Settings** → **System** → **Developer Options**
2. Scroll down to **Bluetooth HCI snoop log**
3. **Turn it ON**
4. You should see: "Bluetooth HCI snoop log: ON"

### Step 3: Pair Bulb with GE Cync App

1. Open **GE Cync** app
2. Follow app prompts to pair the bulb (MAC: 34:13:43:46:CA:84)
3. Complete pairing process
4. **Don't close the app yet!**

### Step 4: Control the Bulb

Perform these actions IN ORDER (I need to see each command):

1. **Turn OFF** the bulb (tap OFF button)
2. Wait 2 seconds
3. **Turn ON** the bulb (tap ON button)
4. Wait 2 seconds
5. **Turn OFF** again
6. Wait 2 seconds
7. **Set brightness to 50%** (if app has slider)
8. Wait 2 seconds
9. **Turn ON** one more time

### Step 5: Extract HCI Log File

1. Connect phone to PC via USB
2. Enable **File Transfer** mode on phone
3. Navigate to phone storage on PC
4. Find the HCI log file at one of these locations:
   ```
   /sdcard/Android/data/btsnoop_hci.log
   /data/misc/bluetooth/logs/btsnoop_hci.log
   /sdcard/btsnoop_hci.log
   ```
5. **Copy the file to:**
   ```
   C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\hci_logs\
   ```
6. Rename it to: `cync_pairing_capture.log`

### Step 6: Turn OFF HCI Logging

1. Go back to **Developer Options**
2. Turn OFF **Bluetooth HCI snoop log**
3. (This prevents filling up storage)

---

## Method 2: Windows PC (Alternative)

If you don't have Android or prefer using Windows:

### Step 1: Install Bluetooth Packet Logger

1. Download **Bluetooth Packet Logger** from:
   - Option A: Microsoft Store → Search "Bluetooth Packet Logger"
   - Option B: Use built-in Windows ETW logging

### Step 2: Start Capture

**Using Windows Event Tracing (Built-in):**

1. Open **PowerShell as Administrator**
2. Run:
   ```powershell
   # Start Bluetooth logging
   logman create trace "Bluetooth" -ow -o C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\hci_logs\bluetooth_trace.etl -p {8a1f9517-3a8c-4a9e-a018-4f17a200f277} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

   logman start "Bluetooth"
   ```

### Step 3: Use GE Cync App on Windows

1. If GE Cync has Windows app, use it
2. OR use Android emulator (BlueStacks, etc.) with GE Cync app
3. Pair and control the bulb as described above

### Step 4: Stop Capture

```powershell
logman stop "Bluetooth" -ets
```

### Step 5: Convert ETL to PCAP

```powershell
# We'll do this together after you send the file
```

---

## What Happens Next (My Part)

Once you provide the HCI log file, I will:

1. **Parse the log file** (5 minutes)
   - Extract all Bluetooth packets
   - Filter for MAC: 34:13:43:46:CA:84
   - Identify write operations

2. **Extract session key** (10 minutes)
   - Find pairing sequence
   - Locate session key exchange
   - Extract 16-byte AES key

3. **Map control commands** (15 minutes)
   - Find ON command bytes
   - Find OFF command bytes
   - Find brightness command format
   - Decrypt and analyze structure

4. **Implement control** (30 minutes)
   - Create `src/protocol/captured_session.py`
   - Use extracted session key
   - Implement ON/OFF/brightness
   - Test with your bulb

5. **Verify it works** (10 minutes)
   - Run test script
   - Your bulb should turn ON/OFF
   - Success! Working prototype ✅

---

## Troubleshooting

### Can't Find HCI Log on Android
- Try looking in: `/sdcard/Download/btsnoop_hci.log`
- Or use app "Bluetooth HCI Log" from Play Store
- Or use ADB: `adb pull /sdcard/Android/data/btsnoop_hci.log`

### GE Cync App Won't Pair
- Make sure bulb is in pairing mode (should be after factory reset)
- App should detect "telink_mesh1"
- Follow app's WiFi setup (it's required even for BLE control)

### Windows Logging Not Working
- Use Android method instead (much simpler)
- Or I can guide you through Wireshark setup

---

## Quick Start (TL;DR)

**For Android Users:**
1. Settings → Developer Options → Enable HCI Snoop Log
2. Open GE Cync app → Pair bulb → Control it (OFF/ON/OFF/Brightness/ON)
3. Copy `/sdcard/Android/data/btsnoop_hci.log` to PC
4. Send file location to me
5. Done!

**Estimated Time:** 10 minutes

---

## File Delivery

Once you have the HCI log file, just let me know:
```
"HCI log ready at: C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\hci_logs\cync_pairing_capture.log"
```

And I'll immediately start extracting the session key and commands!
