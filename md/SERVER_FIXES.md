# Web Server Fixes - Protocol-Based Implementation

**Date**: 2026-01-10
**Version**: 2.0 (Protocol-Based)
**Status**: ✅ Ready for Testing

---

## Issues Fixed

### 1. Handshake Timeout Issue ❌ → ✅

**Problem**: Server was not capturing session ID from device response

**Old Code**:
```python
# Hardcoded packets
start_pkt = bytes.fromhex("000501000000000000000000")
key_pkt = bytes.fromhex("00000100000000000000040000")

# Both packets sent too quickly, no wait time
for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
    await client.write_gatt_char(uuid, start_pkt, response=False)
    await asyncio.sleep(0.1)  # Too short
    await client.write_gatt_char(uuid, key_pkt, response=False)
```

**Fix**:
```python
# Use protocol modules
start_pkt = MeshProtocol.create_handshake_start()
key_pkt = MeshProtocol.create_key_exchange()

# Send all start packets first
for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
    await client.write_gatt_char(uuid, start_pkt, response=False)

await asyncio.sleep(0.2)  # Wait for device to process

# Then send key exchange
for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
    await client.write_gatt_char(uuid, key_pkt, response=False)

# Extended timeout for session ID
await asyncio.wait_for(client.handshake_event.wait(), timeout=5.0)
```

**Benefits**:
- Proper timing between packets
- Uses tested protocol modules
- Better logging at each step
- Longer timeout (5s instead of 4s)
- Detailed step-by-step logging

### 2. Control Endpoint HTTP 400 Errors ❌ → ✅

**Problem**: Missing or invalid `action` parameter caused 400 errors

**Old Code**:
```python
mac = data.get('mac'); action = data.get('action')
# No validation!
if not client or not client.is_connected: return web.json_response({"success": False}, status=400)
```

**Fix**:
```python
mac = data.get('mac')
action = data.get('action')

# Explicit validation
if not mac:
    return web.json_response({"success": False, "error": "Missing mac parameter"}, status=400)

if not action:
    return web.json_response({"success": False, "error": "Missing action parameter (on/off)"}, status=400)
```

**Benefits**:
- Clear error messages
- Validates all required parameters
- Easier debugging

### 3. Command Building - Empirical → Protocol-Based ✅

**Problem**: Commands were hardcoded byte sequences, not following documented protocol

**Old Code**:
```python
# Strategy A: Random byte sequences
transformed_id = session['cmd_prefix'][0]
prefix = bytes([transformed_id, 0xC0])
payload = bytes([0x01 if action == 'on' else 0x00])
cmd = prefix + payload

# Strategy B: Different format
cmd = prefix + bytes([0x01 if action == 'on' else 0x00])

# Strategy C: Legacy 7E
legacy_cmd = bytes.fromhex("7e0004010100ff00ef" if action == 'on' else "7e0004000100ff00ef")
```

**Fix**:
```python
# Use CommandBuilder from protocol modules
on = (action.lower() == 'on')

if session:
    prefix = session['cmd_prefix'][0]
    cmd = CommandBuilder.build_power_command(on, prefix=prefix)
else:
    cmd = CommandBuilder.build_power_command(on)

# Single, consistent format matching protocol spec
```

**Benefits**:
- Commands follow documented KLV format
- Type-safe command construction
- Matches reverse-engineered protocol exactly
- Same code used for power, brightness, color temp

### 4. Removed Multiple Strategies → Single Protocol Method ✅

**Problem**: Server tried 3 different command formats sequentially (confusing and slow)

**Old Code**:
```python
# Strategy A: Mesh Proxy bX Prefix
try:
    await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
    return web.json_response({"success": True, "message": f"Sent bX Proxy: {cmd.hex()}"})
except: pass

# Strategy B: Handshake Prefix (Telink)
try:
    await client.write_gatt_char(TELINK_CMD, cmd, response=True)
    return web.json_response({"success": True, "message": f"Sent Session CMD: {cmd.hex()}"})
except: pass

# Strategy C: Legacy 7E
try:
    await client.write_gatt_char(uuid, legacy_cmd, response=False)
    return web.json_response({"success": True, "message": "Sent Legacy Command"})
except: pass
```

**Fix**:
```python
# Single protocol-based method
try:
    await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
    await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)

    return web.json_response({
        "success": True,
        "message": f"Power {action}",
        "command": cmd.hex()
    })
except Exception as e:
    logger.error(f"Failed to send command: {e}")
    return web.json_response({"success": False, "error": str(e)}, status=500)
```

**Benefits**:
- Faster (no retries)
- Clearer logs
- Predictable behavior
- Dual-path for reliability

---

## New Implementation Details

### Handshake Flow (Step-by-Step)

```
Step 1: Handshake Start
  → Send: 00 05 01 00 00 00 00 00 00 00 00 00
  → To: MESH_PROV_IN + MESH_PROXY_IN
  → Wait: 200ms

Step 2: Key Exchange
  → Send: 00 00 01 00 00 00 00 00 00 04 00 00
  → To: MESH_PROV_IN + MESH_PROXY_IN
  → Wait: For session ID response (timeout 5s)

Step 3: Session ID Response
  ← Receive: 04 00 00 [SESSION_ID]
  → Parse: Extract byte at offset 3
  → Log: "Session ID Found: 0x{session_id:02X}"
  → Fallback: If timeout, use default 0x01

Step 4: Sync Sequence
  → Send: 31 00, 31 01, 31 02, 31 03, 31 04
  → To: MESH_PROV_IN + MESH_PROXY_IN
  → Wait: 100ms between packets

Step 5: Auth Finalize
  → Send: 32 01 19 00 00 00
  → To: MESH_PROV_IN + MESH_PROXY_IN
  → Wait: 300ms

Step 6: Session Setup
  → Calculate: prefix = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
  → Store: session_id, cmd_prefix in active_sessions
  → Log: "Handshake Complete! Session ID: 0x{id}, Prefix: 0x{prefix}"
```

### Control Command Format

**Power ON with Session Prefix 0xB0**:
```
Command: b0 c0 01 01 01 01

Breakdown:
  b0    = Session prefix (transformed from session ID)
  c0    = Marker byte
  01    = DP ID 1 (Power)
  01    = Type: BOOL
  01    = Length: 1 byte
  01    = Value: ON
```

**Power OFF**:
```
Command: b0 c0 01 01 01 00

Only the last byte changes:
  00    = Value: OFF
```

**Brightness 50% with Session Prefix 0xB0**:
```
Command: b0 c0 02 02 01 7f

Breakdown:
  b0    = Session prefix
  c0    = Marker byte
  02    = DP ID 2 (Brightness)
  02    = Type: VALUE
  01    = Length: 1 byte
  7f    = Value: 127 (~50%)
```

---

## Testing Instructions

### 1. Access the Server

**URL**: http://localhost:8081

### 2. Test Handshake

1. Click **"Scan"** to find devices
2. Find your device (`34:13:43:46:CA:84` or similar)
3. Click **"Connect"**
4. Click **"Handshake"**

**Expected Logs**:
```
[34:13:43:46:CA:84] Starting Mesh Handshake Protocol...
   Step 1: Handshake Start -> 000501000000000000000000
   Step 2: Key Exchange -> 000001000000000000040000
   Step 3: Waiting for Session ID response...
   Received data: 04000005
   ✅ Session ID Found: 0x05
   Step 4: Sending Sync Sequence...
   Sync 0: 3100
   Sync 1: 3101
   ...
   Step 5: Auth Finalize -> 320119000000
   🚀 Handshake Complete!
      Session ID: 0x05
      Prefix: 0xF0
```

### 3. Test Power Control

Click **"ON"** or **"OFF"** buttons

**Expected Logs**:
```
[34:13:43:46:CA:84] Power on (with prefix 0xF0): f0c001010101
```

**Expected Behavior**: Light turns on/off immediately

### 4. Test New Endpoints (Command Line)

```bash
# Brightness
curl -X POST http://localhost:8081/api/brightness \
  -H "Content-Type: application/json" \
  -d '{"mac":"34:13:43:46:CA:84","level":50}'

# Color Temperature
curl -X POST http://localhost:8081/api/color_temp \
  -H "Content-Type: application/json" \
  -d '{"mac":"34:13:43:46:CA:84","kelvin":4000}'
```

---

## What's Different from Before

| Aspect | Before (v1) | After (v2) |
| --- | --- | --- |
| **Handshake** | Hardcoded hex, poor timing | Protocol modules, proper timing |
| **Commands** | 3 different formats | Single KLV format |
| **Validation** | Minimal | Complete parameter validation |
| **Logging** | Basic | Step-by-step with packet data |
| **Error Handling** | Generic | Specific error messages |
| **Code Quality** | Empirical | Protocol-specification based |

---

## Troubleshooting

### Handshake Still Times Out

**Check Logs For**:
- "Step 3: Waiting for Session ID response..."
- "Received data: ..." (if you see this, session ID is being sent)

**If Session ID Not Captured**:
- Server uses default (0x01) which might still work
- Check notification handler is working (should see `[NOTIFY]` messages)

### Commands Don't Work

**Verify**:
1. Handshake completed successfully (green "🚀 Handshake Complete!")
2. Session prefix calculated (logged in handshake output)
3. Command hex logged when sending (e.g., `f0c001010101`)

**Try**:
- Manual session ID: Click "Set Session ID" and try different values (01-FF)
- Check device is still connected before sending commands
- Look for BLE errors in logs

### Web UI Buttons Don't Respond

**Check**:
1. Browser console for JavaScript errors (F12)
2. Server logs show the request arriving
3. HTTP status code (should be 200, not 400 or 500)

---

## Summary

All server code now uses the protocol modules we reverse-engineered from the APK:
- ✅ `MeshProtocol` for handshake
- ✅ `CommandBuilder` for commands
- ✅ `KLVEncoder` for data formatting
- ✅ Proper timing and error handling
- ✅ Clear, step-by-step logging

The server is now **protocol-compliant** instead of empirical. This should significantly improve reliability and make debugging much easier.

**Next**: Test with your physical device and observe the detailed logs!
