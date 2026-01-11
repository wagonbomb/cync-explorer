# Quick Test Guide for GE Cync BLE Control

**Test Device**: `34:13:43:46:ca:85`
**Server**: http://localhost:8080

---

## Start the Server

```bash
cd C:\Users\Meow\Documents\Projects\cync-explorer
python src/cync_server.py
```

Server will start on http://localhost:8080

---

## Test Sequence (Using Web UI or Curl)

### Option 1: Web UI (Easiest)

1. Open http://localhost:8080 in browser
2. Click "Scan" button
3. Find device `34:13:43:46:ca:85` in list
4. Click "Connect"
5. Click "Handshake"
6. Click "ON" or "OFF" to test basic control

### Option 2: Command Line (For Advanced Testing)

#### 1. Scan for Device
```bash
curl http://localhost:8080/api/scan
```

#### 2. Connect
```bash
curl -X POST http://localhost:8080/api/connect \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\"}"
```

#### 3. Handshake
```bash
curl -X POST http://localhost:8080/api/handshake \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\"}"
```

Expected response:
```json
{
  "success": true,
  "session_id": "05",  // Example
  "prefix": "f0"       // Calculated from session_id
}
```

#### 4. Test Power Control (Original Method)
```bash
# Turn ON
curl -X POST http://localhost:8080/api/control \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"action\":\"on\"}"

# Turn OFF
curl -X POST http://localhost:8080/api/control \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"action\":\"off\"}"
```

#### 5. Test Power Control (Protocol Method) ⭐ NEW
```bash
# Turn ON using protocol
curl -X POST http://localhost:8080/api/power_protocol \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"action\":\"on\"}"
```

Expected command (example): `f0c001010101`
- `f0` = Session prefix
- `c0` = Marker byte
- `01` = DP ID (Power)
- `01` = Type (BOOL)
- `01` = Length
- `01` = Value (ON)

#### 6. Test Brightness Control ⭐ NEW
```bash
# Set to 50%
curl -X POST http://localhost:8080/api/brightness \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"level\":50}"

# Set to 100%
curl -X POST http://localhost:8080/api/brightness \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"level\":100}"

# Set to 25%
curl -X POST http://localhost:8080/api/brightness \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"level\":25}"
```

Expected command (50%): `f0c00202017f`
- `f0` = Session prefix
- `c0` = Marker byte
- `02` = DP ID (Brightness)
- `02` = Type (VALUE)
- `01` = Length
- `7f` = Value (127 = ~50%)

#### 7. Test Color Temperature ⭐ NEW
```bash
# Warm white (2700K)
curl -X POST http://localhost:8080/api/color_temp \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"kelvin\":2700}"

# Neutral (4000K)
curl -X POST http://localhost:8080/api/color_temp \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"kelvin\":4000}"

# Cool white (6500K)
curl -X POST http://localhost:8080/api/color_temp \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"34:13:43:46:ca:85\",\"kelvin\":6500}"
```

Expected command (4000K): `f0c0030202​0fa0`
- `f0` = Session prefix
- `c0` = Marker byte
- `03` = DP ID (Color Temp)
- `02` = Type (VALUE)
- `02` = Length (2 bytes for 4000)
- `0fa0` = Value (4000 in hex)

---

## Observing Results

### Watch Server Logs
The server will log:
```
INFO:cync_server:[34:13:43:46:ca:85] Starting Mesh Handshake Protocol...
INFO:cync_server:   ✨ Session ID Found: 05
INFO:cync_server:   🚀 Session Active: ID=05, Transformed ID=F0
INFO:cync_server:[34:13:43:46:ca:85] Brightness 50%: f0c00202017f
```

### Watch Light Response
- Light should respond immediately (within 100ms)
- For power commands: Light turns on/off
- For brightness: Light dims/brightens smoothly
- For color temp: Light changes from warm to cool white

---

## Troubleshooting

### Light Doesn't Respond

**1. Check Connection**
- Run `/api/scan` again
- Verify device is in range (RSSI > -80)
- Try reconnecting

**2. Check Handshake**
- Look for "Session ID Found" in logs
- Verify prefix was calculated
- Try manual session ID: `/api/set_session_id` with `session_id: "05"`

**3. Try Different Strategies**
- Use original `/api/control` endpoint (known to work)
- Compare command bytes between original and protocol method
- Try without session prefix (modify endpoint temporarily)

### Commands Work But Wrong Effect

**Brightness inverted** (0% is bright, 100% is dim):
- Brightness mapping might be reversed
- Try inverting: `255 - level`

**Color temp wrong direction**:
- Kelvin mapping might be reversed
- Check if device uses mireds instead of Kelvin

---

## Expected Results

| Command | Expected Behavior | Time |
| --- | --- | --- |
| Power ON | Light turns on at last brightness | Immediate |
| Power OFF | Light turns off | Immediate |
| Brightness 0% | Light very dim or off | Smooth (500ms) |
| Brightness 50% | Light at half brightness | Smooth (500ms) |
| Brightness 100% | Light at full brightness | Smooth (500ms) |
| Color Temp 2700K | Warm white (yellowish) | Smooth (500ms) |
| Color Temp 6500K | Cool white (bluish) | Smooth (500ms) |

---

## Next Steps After Success

1. **Document Working Commands**
   - Create `md/WORKING_COMMANDS.md`
   - Record exact command bytes that work
   - Note any quirks or special behaviors

2. **Test Edge Cases**
   - Rapid commands (spam ON/OFF)
   - Invalid values (brightness 101%, temp 1000K)
   - Connection loss and recovery
   - Multiple lights simultaneously

3. **Add Web UI Enhancements**
   - Brightness slider
   - Color temperature slider
   - Real-time state display

4. **Advanced Features**
   - State queries (read current values)
   - Scenes
   - Timers/scheduling
   - Groups

---

## Quick Commands Cheat Sheet

```bash
# Full test sequence (copy-paste)
curl -X POST http://localhost:8080/api/connect -H "Content-Type: application/json" -d "{\"mac\":\"34:13:43:46:ca:85\"}"
curl -X POST http://localhost:8080/api/handshake -H "Content-Type: application/json" -d "{\"mac\":\"34:13:43:46:ca:85\"}"
curl -X POST http://localhost:8080/api/power_protocol -H "Content-Type: application/json" -d "{\"mac\":\"34:13:43:46:ca:85\",\"action\":\"on\"}"
curl -X POST http://localhost:8080/api/brightness -H "Content-Type: application/json" -d "{\"mac\":\"34:13:43:46:ca:85\",\"level\":50}"
curl -X POST http://localhost:8080/api/color_temp -H "Content-Type: application/json" -d "{\"mac\":\"34:13:43:46:ca:85\",\"kelvin\":4000}"
```

---

## Success Criteria

✅ **Phase 1 (Basic)**: Power ON/OFF works
✅ **Phase 2 (Brightness)**: Brightness 0-100% works smoothly
✅ **Phase 3 (Color)**: Color temperature changes visible
✅ **Phase 4 (Reliability)**: Commands work consistently (>95% success rate)

**When all phases pass → Ready for production use!**
