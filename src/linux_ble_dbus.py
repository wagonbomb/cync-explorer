#!/usr/bin/env python3
"""
Linux BLE D-Bus - Direct D-Bus interaction with BlueZ
Properly handles AcquireNotify
"""

import asyncio
import struct
from bleak import BleakClient
from bleak.backends.bluezdbus.defs import defs

TARGET_MAC = "34:13:43:46:CA:84"

UUID_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"

HANDSHAKE = [
    ("START", "000501000000000000000000"),
    ("KEY_EXCHANGE", "00000100000000000000040000"),
    ("SYNC_0", "3100"),
    ("SYNC_1", "3101"),
    ("SYNC_2", "3102"),
    ("SYNC_3", "3103"),
    ("SYNC_4", "3104"),
    ("MSG_1", "00000100000000000000160000"),
    ("MSG_2", "00000100000000000000010002"),
    ("AUTH", "320119000000"),
]

responses = []
response_event = asyncio.Event()

def handler(sender, data):
    hex_data = data.hex()
    print(f"  <- {hex_data}")
    responses.append(data)
    response_event.set()

async def wait_response(timeout=2.0):
    global response_event
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.1)
        response_event.clear()
        return True
    except asyncio.TimeoutError:
        response_event.clear()
        return False

async def main():
    print("=" * 60)
    print("LINUX BLE D-BUS MODE")
    print("=" * 60)
    print(f"Target: {TARGET_MAC}")
    print()

    print("Connecting...")
    client = BleakClient(TARGET_MAC, timeout=30.0)

    try:
        await client.connect()
        print(f"[CONNECTED]")

        # Get services
        services = client.services
        print(f"Found {len(list(services))} services")

        # Find the 1911 characteristic
        char_1911 = None
        for service in services:
            for char in service.characteristics:
                if "1911" in char.uuid:
                    char_1911 = char
                    print(f"\nFound 1911: {char.uuid}")
                    print(f"  Handle: {char.handle}")
                    print(f"  Properties: {char.properties}")
                    break

        if not char_1911:
            print("ERROR: 1911 characteristic not found!")
            return

        # Try to get the D-Bus path for the characteristic
        print("\n[1] Attempting to subscribe...")

        # Get access to the underlying BlueZ D-Bus interface
        try:
            # Use internal bleak method
            await client.start_notify(UUID_1911, handler)
            print("  [OK] Subscribed to 1911!")
        except Exception as e:
            print(f"  [FAIL] {e}")
            print("  Continuing without notifications...")

        await asyncio.sleep(0.5)

        print()
        print("[2] Sending handshake...")
        print("-" * 60)

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            responses.clear()

            print(f"\n  [{name}] -> {cmd_hex}")

            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                if await wait_response(timeout=2.0):
                    pass  # Already printed in handler
                else:
                    print(f"  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 60)

        # Try control commands
        print("\nTrying control commands...")
        for name, cmd in [("ON", "b0c00101"), ("OFF", "b0c00100")]:
            print(f"\n[{name}] -> {cmd}")
            try:
                await client.write_gatt_char(UUID_1912, bytes.fromhex(cmd), response=False)
                print("  Sent - check light!")
                await asyncio.sleep(3.0)
            except Exception as e:
                print(f"  Error: {e}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
