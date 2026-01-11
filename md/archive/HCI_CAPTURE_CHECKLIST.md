# HCI Capture Checklist - Step by Step

**Current Status**: Phone connected via ADB ✅

---

## Complete Setup Steps

### Step 1: Enable HCI Logging on Phone

**On your Android phone:**
1. Settings → About Phone → Tap "Build Number" 7 times
2. Settings → System → Developer Options
3. Scroll down to **"Bluetooth HCI snoop log"**
4. **Turn it ON** (must show "ON" or "Enabled")
5. **IMPORTANT**: Some phones require a Bluetooth restart:
   - Toggle Bluetooth OFF
   - Toggle Bluetooth ON

### Step 2: Use Bluetooth (Pair with GE Cync App)

**AFTER enabling HCI log:**
1. Open GE Cync app
2. Add new device / Pair bulb
3. Complete pairing (provide WiFi when asked - it's fine)
4. Control the bulb:
   - Turn OFF
   - Turn ON
   - Turn OFF
   - Brightness 50%
   - Turn ON

**This creates the HCI log file with the traffic we need**

### Step 3: Extract Log via ADB

**We're doing this now with bug report method**

---

## Current Approach: Bug Report Method

**What's happening:**
```bash
adb bugreport artifacts/hci_logs/bugreport.zip
```

**This will:**
- Generate complete diagnostic dump (2-3 minutes)
- Includes HCI snoop log if it exists
- Saves to: artifacts/hci_logs/bugreport.zip

**After it completes:**
- I'll extract btsnoop_hci.log from the zip
- Parse it for session keys and commands

---

## Alternative: Manual File Pull (If Bug Report Fails)

If bug report doesn't work, we can try:

1. **Enable HCI log on phone**
2. **Use Bluetooth (pair/control bulb)**
3. **Pull log manually:**
   ```bash
   # Try different locations
   adb pull /sdcard/Android/data/btsnoop_hci.log artifacts/hci_logs/
   adb pull /data/misc/bluetooth/logs/btsnoop_hci.log artifacts/hci_logs/
   adb pull /sdcard/btsnoop_hci.log artifacts/hci_logs/
   ```

4. **Or use file browser:**
   - Settings → Developer Options → "Take bug report" → "Interactive report"
   - Wait for it to complete
   - Share the bug report zip file
   - Copy to PC

---

## What To Do Right Now

**Option A: If you ALREADY paired bulb with HCI logging ON**
- Just wait for bug report to complete (2-3 min)
- I'll extract and parse the log

**Option B: If you HAVEN'T paired yet OR HCI log wasn't ON**
1. On phone: Settings → Developer Options → Enable "Bluetooth HCI snoop log"
2. Toggle Bluetooth OFF then ON
3. Open GE Cync app and pair the bulb
4. Control it (OFF/ON/OFF/Brightness/ON)
5. Tell me: "Pairing complete"
6. I'll run the bug report command again

**Which scenario are you in?**
