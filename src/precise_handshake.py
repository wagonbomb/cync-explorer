#!/usr/bin/env python3
"""
Precise BLE Handshake - Matches HCI Log Exactly

This script replicates the exact connection sequence from the HCI log:
1. Enable indications on Service Changed (0x2a05)
2. Enable notifications on Telink Status (1911)
3. Enable notifications on response characteristic
4. Send handshake sequence
"""

import asyncio
from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic

TARGET_MAC = "34:13:43:46:CA:84"

# UUIDs we know about
UUID_TELINK_STATUS = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"
UUID_MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
UUID_MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
UUID_MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
UUID_MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"
UUID_SERVICE_CHANGED = "00002a05-0000-1000-8000-00805f9b34fb"

# HCI Log sequence (from frame 344 onwards)
HANDSHAKE_SEQUENCE = [
    ("START", bytes.fromhex("000501000000000000000000")),
    ("KEY_EXCHANGE", bytes.fromhex("00000100000000000000040000")),
    ("SYNC_0", bytes.fromhex("3100")),
    ("SYNC_1", bytes.fromhex("3101")),
    ("SYNC_2", bytes.fromhex("3102")),
    ("SYNC_3", bytes.fromhex("3103")),
    ("SYNC_4", bytes.fromhex("3104")),
    ("MSG_1", bytes.fromhex("00000100000000000000160000")),
    ("MSG_2", bytes.fromhex("00000100000000000000010002")),
    ("AUTH_FINALIZE", bytes.fromhex("320119000000")),
]

responses = []
response_event = asyncio.Event()

def notification_handler(char: BleakGATTCharacteristic, data: bytearray):
    """Handle all notifications"""
    hex_data = data.hex()
    uuid_short = char.uuid.split('-')[0][-4:]
    print(f"  NOTIFY [{uuid_short}]: {hex_data}")
    responses.append((char.uuid, bytes(data)))
    response_event.set()

async def wait_response(timeout=3.0):
    """Wait for a response"""
    global response_event
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.1)  # Collect any additional responses
        response_event.clear()
        return True
    except asyncio.TimeoutError:
        response_event.clear()
        return False

async def discover_and_print(client: BleakClient):
    """Discover all services and characteristics"""
    print("\n" + "=" * 70)
    print("GATT SERVICE DISCOVERY")
    print("=" * 70)

    for service in client.services:
        print(f"\nService: {service.uuid}")
        for char in service.characteristics:
            props = ", ".join(char.properties)
            print(f"  Char: {char.uuid}")
            print(f"    Handle: 0x{char.handle:04x}")
            print(f"    Properties: {props}")
            for desc in char.descriptors:
                print(f"    Descriptor: {desc.uuid} (handle 0x{desc.handle:04x})")

async def enable_notifications_safe(client: BleakClient, uuid: str, handler) -> bool:
    """Try to enable notifications on a characteristic"""
    try:
        for service in client.services:
            for char in service.characteristics:
                if char.uuid.lower() == uuid.lower():
                    if "notify" in char.properties or "indicate" in char.properties:
                        await client.start_notify(char, handler)
                        print(f"  [OK] Subscribed to {uuid}")
                        return True
        return False
    except Exception as e:
        print(f"  [FAIL] {uuid}: {e}")
        return False

async def write_characteristic(client: BleakClient, uuid: str, data: bytes) -> bool:
    """Write to a characteristic"""
    try:
        await client.write_gatt_char(uuid, data, response=False)
        return True
    except Exception as e:
        print(f"  [FAIL] Write to {uuid}: {e}")
        return False

async def main():
    print("=" * 70)
    print("PRECISE BLE HANDSHAKE - MATCHING HCI LOG")
    print("=" * 70)
    print(f"Target: {TARGET_MAC}")
    print()

    print("Scanning...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=15.0)
    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name} ({device.address})")
    print()

    async with BleakClient(device, timeout=30.0) as client:
        print(f"[CONNECTED] MTU: {client.mtu_size}")

        # Discover services
        await discover_and_print(client)

        print("\n" + "=" * 70)
        print("STEP 1: ENABLE NOTIFICATIONS/INDICATIONS")
        print("=" * 70)

        # Try to enable on all notify-capable characteristics
        # This matches HCI frames 302, 315, 319
        notify_uuids = [
            UUID_SERVICE_CHANGED,  # Frame 302: "0200" (indications)
            UUID_TELINK_STATUS,    # Frame 315: "0100" (notifications)
            UUID_MESH_PROV_OUT,    # Frame 319: "0100" (notifications)
            UUID_MESH_PROXY_OUT,   # Also enable this
        ]

        for uuid in notify_uuids:
            await enable_notifications_safe(client, uuid, notification_handler)
            await asyncio.sleep(0.2)

        await asyncio.sleep(0.5)

        print("\n" + "=" * 70)
        print("STEP 2: FIND WRITE CHARACTERISTIC")
        print("=" * 70)

        # The HCI log writes to handle 0x0025
        # We need to find the equivalent characteristic
        # Try writing to multiple characteristics
        write_targets = [
            ("TELINK_CMD (1912)", UUID_TELINK_CMD),
            ("MESH_PROV_IN (2adb)", UUID_MESH_PROV_IN),
            ("MESH_PROXY_IN (2add)", UUID_MESH_PROXY_IN),
        ]

        print("\n" + "=" * 70)
        print("STEP 3: SEND HANDSHAKE SEQUENCE")
        print("=" * 70)

        # Try each write target
        for target_name, write_uuid in write_targets:
            responses.clear()
            print(f"\n--- Testing: {target_name} ---")

            # Send first handshake message
            name, data = HANDSHAKE_SEQUENCE[0]
            print(f"\n[{name}] -> {data.hex()}")

            success = await write_characteristic(client, write_uuid, data)
            if not success:
                print(f"  Write failed, skipping this target")
                continue

            # Wait for response
            got_response = await wait_response(timeout=3.0)
            if got_response:
                print(f"  *** GOT RESPONSE! ***")

                # This is the right characteristic! Continue with full sequence
                for name, data in HANDSHAKE_SEQUENCE[1:]:
                    responses.clear()
                    print(f"\n[{name}] -> {data.hex()}")
                    await write_characteristic(client, write_uuid, data)
                    await wait_response(timeout=2.0)

                print("\n" + "=" * 70)
                print("HANDSHAKE COMPLETE ON: " + target_name)
                print("=" * 70)

                # Try a control command
                if responses:
                    # Look for session ID in responses
                    for uuid, resp_data in responses:
                        print(f"Response: {resp_data.hex()}")
                        if resp_data.startswith(b'\x04') or resp_data.startswith(b'\x32'):
                            print("  Found session marker!")

                return
            else:
                print(f"  No response")

        print("\n" + "=" * 70)
        print("NO WRITE TARGET RESPONDED")
        print("=" * 70)
        print()
        print("Trying EVERYTHING - write to each characteristic and wait...")

        # Last resort: enumerate all writable characteristics
        for service in client.services:
            for char in service.characteristics:
                if "write" in char.properties or "write-without-response" in char.properties:
                    responses.clear()
                    print(f"\nTrying: {char.uuid} (handle 0x{char.handle:04x})")
                    try:
                        await client.write_gatt_char(char, HANDSHAKE_SEQUENCE[0][1], response=False)
                        got = await wait_response(timeout=2.0)
                        if got:
                            print(f"  *** RESPONSE ON {char.uuid}! ***")
                    except Exception as e:
                        print(f"  Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
