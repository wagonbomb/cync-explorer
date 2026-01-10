# Cync Project Context Dump - 2026-01-07

## Overview
The goal of this project is to achieve local ON/OFF control of GE Cync (formerly C by GE) smart lights via BLE on Windows. We have successfully pivoted from a Telink-only strategy to a **Mesh Proxy** strategy based on HCI log analysis.

## Key Information

### BLE Architecture
- **Mesh Provisioning In (0x25)**: `00002adb-0000-1000-8000-00805f9b34fb` (Used for handshake)
- **Mesh Proxy In (0x27)**: `00002add-0000-1000-8000-00805f9b34fb` (Used for commands)
- **Mesh Proxy Out (0x29)**: `00002ade-0000-1000-8000-00805f9b34fb` (Notifications)
- **Telink Command**: `00010203-0405-0607-0809-0a0b0c0d1912` (Fallback)
- **Telink Status**: `00010203-0405-0607-0809-0a0b0c0d1911` (Fallback)

### Protocol breakthrough: "31/32" Handshake
The official app performs a specific authentication dance:
1.  **START**: `000501...` sent to Mesh Provisioning In.
2.  **KEY**: `000001...040000` sent to Mesh Provisioning In.
3.  **Capture ID**: Listen for `04 00 00` in notifications. The byte after `00` is the `session_id`.
4.  **Sync**: Send `3100`, `3101`, `3102`, `3103`, `3104` sequentially.
5.  **Finalize**: Send `320119000000`.

### Protocol breakthrough: Dynamic `bX` Control
Commands use an incrementing prefix mapped to the Session ID:
- **Transformed ID**: `(((session_id & 0x0F) + 0x0A) << 4) & 0xFF`
- **Command Header**: `[Transformed ID] [C0]` (e.g., `b0c0` if ID is 1).
- **Control Strategy**: Prioritize sending `Header + [01/00]` to **Mesh Proxy In**.

## Current Implementation

### Backend (`src/cync_server.py`)
- **`handle_connect`**: CCCD flood + listener setup.
- **`handle_handshake`**: Dual-path (Provisioning + Proxy) "31/32" sequence.
- **`handle_control`**: Multi-strategy (Strategy A: bX Proxy, Strategy B: Session CMD, Strategy C: Legacy 7E).
- **`handle_set_session_id`**: Manual bypass for capture timeouts.

### Frontend GUI (`static/index.html`)
- **Device Grid**: Multi-card layout with RSSI and alias matching.
- **Action Panel**: Live logs, Smart Handshake button, Toggle switches.
- **Nuclear Discovery**: Brute force prefix button, Manual Session ID/Prefix entry.

## Next Steps
1.  **Verify Control**: Test if `Strategy A (bX Proxy)` with the `bX + C0 + Payload` structure actually toggles the light.
2.  **Refine Payload**: If short payloads (01/00) fail, investigate if a full Telink packet (7E...) needs to be encapsulated in the Proxy header.
3.  **Stability**: Resolve the handshake capture timeout on Windows BLE drivers.

## Blockers
- Windows `Bleak` driver sometimes fails to deliver notifications fast enough during the handshake, requiring the manual Session ID bypass.
