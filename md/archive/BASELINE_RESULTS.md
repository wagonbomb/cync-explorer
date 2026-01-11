# Baseline Test Results - 2026-01-07

## Summary
Completed 5 foundational baseline tests on target device `34:13:43:46:CA:84`.

---

## Test 1: Basic Connectivity ✅ PASS

**Status:** 100% Success Rate

**Results:**
- Scan: Found 31 Cync devices
- Connect: Successful to `34:13:43:46:CA:84`
- Stability: 3/3 connections successful
- MTU: 247 bytes

**Key Finding:** BLE connectivity is solid and reliable.

---

## Test 2: Characteristic Discovery ✅ PASS

**Status:** All Expected Characteristics Found

**Device Structure:**
- 6 GATT Services
- 5/5 Expected Characteristics Present

**Critical Characteristics:**
| Name | UUID | Handle | Properties |
|------|------|--------|------------|
| Mesh Provisioning In | `00002adb-0000-1000-8000-00805f9b34fb` | 33 | WRITE-NO-RESP |
| Mesh Proxy In | `00002add-0000-1000-8000-00805f9b34fb` | 39 | WRITE-NO-RESP |
| Mesh Proxy Out | `00002ade-0000-1000-8000-00805f9b34fb` | 41 | NOTIFY |
| Telink Command | `00010203-0405-0607-0809-0a0b0c0d1912` | 20 | READ, WRITE, WRITE-NO-RESP |
| Telink Status | `00010203-0405-0607-0809-0a0b0c0d1911` | 17 | READ, WRITE, WRITE-NO-RESP, NOTIFY |

**Key Finding:** Device has full Bluetooth Mesh + Telink support.

---

## Test 3: Raw HCI Analysis ⏭️ SKIPPED

Moved directly to notification testing.

---

## Test 4: Notification Testing ⚠️ PARTIAL

**Status:** Mesh Works, Telink Blocked

**Results:**

### Mesh Proxy Out (Handle 41): ✅ SUCCESS
- Subscription: Successful
- Immediate notification received on connect:
  ```
  010100efbb755d239432fc0000000032bd9bc1d371a887 (23 bytes)
  ```
- This appears to be an unsolicited status message from the device

### Telink Status (Handle 17): ❌ BLOCKED
- Subscription: **Failed**
- Error: `Protocol Error 0x03: Write Not Permitted`
- Despite having NOTIFY property, Windows BLE won't allow CCCD write

**Key Finding:** Must use Mesh Proxy path, not Telink characteristics.

---

## Test 5: Simple Command Baseline ⚠️ PARTIAL

**Status:** Commands Send Successfully, No Responses

**Commands Tested:**
1. ✅ Write to Mesh Provisioning In: `000501`
2. ✅ Handshake sequence: `000501` + `000001040000` 
3. ✅ Write to Mesh Proxy In: `3100`

**Observations:**
- All writes succeed (no errors)
- Only receive initial status notification on connect
- No responses to any commands sent
- Device may disconnect after commands

**Key Finding:** Commands accepted but not triggering responses. Need to investigate:
- Correct command format
- Required authentication/pairing
- Command sequencing
- Payload structure

---

## Critical Discoveries

###✅ What Works
1. **BLE Connection** - Stable, reliable, 247-byte MTU
2. **Characteristic Discovery** - All expected UUIDs present
3. **Mesh Proxy Out Subscription** - Receives notifications
4. **Command Writes** - No errors when sending data
5. **Device Pairing** - Successfully reads device info ("C by GE")
6. **Initial Notification** - Always receives `010100efbb755d239432fc0000000032bd9bc1d371a887` on connect

### ❌ What Doesn't Work
1. **Telink Status Subscription** - Windows blocks CCCD write
2. **Command Responses** - No replies to handshake or control commands
3. **Session ID Capture** - Not seeing `04 00 00 XX` pattern
4. **Connection Stability** - Device disconnects after 3-4 commands sent

### 🔍 What's Unknown
1. **Correct Command Format** - Are our payloads right?
2. **Authentication Required** - Do we need pairing first? (Pairing works but doesn't help)
3. **Initial Notification Meaning** - What is `010100efbb755d239432fc...`?
4. **Why Device Disconnects** - Timeout? Invalid commands? Protection mechanism?
5. **Physical Light Response** - Does it actually change when we send commands?

---

## Next Steps

### Option A: Deep Dive into HCI Logs
- Extract exact byte sequences from working HCI captures
- Identify minimal command set that actually works
- Map out full handshake protocol

### Option B: Analyze Initial Notification
- Decode the `010100efbb...` message structure
- Understand what the device is telling us
- May reveal required response format

### Option C: Try Alternative Approaches
- Test with bonding/pairing enabled
- Try different command payloads from HCI logs
- Investigate if device needs specific initialization

---

## Recommended Path Forward

**Priority 1:** Analyze HCI logs for:
- Exact successful command sequences
- Response patterns
- Session ID extraction method

**Priority 2:** Decode initial notification:
- Understand device status message format
- Check if it contains session info

**Priority 3:** Test alternative commands:
- Use exact payloads from successful HCI sessions
- Try longer/complete command structures
- Test if timing matters

---

## Device Testbed Confirmed

**MAC:** `34:13:43:46:CA:84`  
**Status:** Fully functional for testing  
**Capabilities:** Mesh Proxy + Telink dual-mode support  
**Ready for:** Command protocol development

