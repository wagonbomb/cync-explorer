# What You Need To Do Now

**Goal**: Capture Bluetooth traffic while pairing and controlling the bulb with GE Cync app
**Time Required**: 10-15 minutes
**Difficulty**: Easy (just follow steps)

---

## Quick Steps (Android - Easiest)

### 1. Enable HCI Logging (2 minutes)
```
Phone Settings
  → About Phone
  → Tap "Build Number" 7 times (enables Developer Options)
  → Back to Settings
  → System → Developer Options
  → Find "Bluetooth HCI snoop log"
  → Turn it ON
```

### 2. Use GE Cync App (5 minutes)
```
Open GE Cync app
  → Add new device (the factory reset bulb)
  → Follow pairing process
  → Complete WiFi setup if required
  → Once paired and working:

Control the bulb in this EXACT order:
  1. Turn OFF (tap OFF button)
  2. Wait 2 seconds
  3. Turn ON (tap ON button)
  4. Wait 2 seconds
  5. Turn OFF again
  6. Wait 2 seconds
  7. Set brightness to 50% (if app has slider)
  8. Turn ON one more time
```

### 3. Copy Log File to PC (3 minutes)
```
Connect phone to PC via USB
  → Enable "File Transfer" mode on phone
  → On PC, browse phone storage
  → Find file at one of these locations:
     /sdcard/Android/data/btsnoop_hci.log
     /data/misc/bluetooth/logs/btsnoop_hci.log
     /sdcard/btsnoop_hci.log
  → Copy file to:
     C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\hci_logs\
  → Rename to: cync_pairing_capture.log
```

### 4. Turn Off HCI Logging
```
Phone Settings
  → Developer Options
  → Turn OFF "Bluetooth HCI snoop log"
  (prevents filling up storage)
```

### 5. Let Me Know
```
Just say: "HCI log ready"
```

---

## That's It!

Once you say "HCI log ready", I will:
- Parse the log file (5 min)
- Extract session key (10 min)
- Extract control commands (15 min)
- Implement working control (30 min)
- Test with your bulb (10 min)

**Total time to working control: ~1 hour after you provide the log**

---

## Detailed Guide

If you need more details, see: `md/HCI_CAPTURE_GUIDE.md`

---

## Don't Have Android?

If you're using iPhone or prefer Windows-based capture, let me know and I'll guide you through an alternative method.
