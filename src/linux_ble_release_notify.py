#!/usr/bin/env python3
"""
Release BlueZ notification lock and run protocol test
Uses dbus_fast to interact with BlueZ directly
"""

import asyncio
from bleak import BleakScanner, BleakClient
from bleak.backends.bluezdbus.manager import get_global_bluez_manager

TARGET_MAC = "34:13:43:46:CA:84"
TARGET_DEVICE_PATH = f"/org/bluez/hci0/dev_{TARGET_MAC.replace(':', '_')}"

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
    print(f"  <- NOTIFY: {hex_data}")
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
    print("BLE WITH NOTIFY RELEASE")
    print("=" * 60)
    print()

    print("[0] Finding device...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=30.0)

    if not device:
        print("  Device not found!")
        return

    print(f"  Found: {device.name} ({device.address})")

    print()
    print("[1] Connecting...")

    # Create client without using context manager for more control
    client = BleakClient(device, timeout=30.0)

    try:
        await client.connect()
        print(f"  Connected! MTU: {client.mtu_size}")

        # Wait for services
        await asyncio.sleep(2.0)
        services = client.services
        print(f"  Found {len(list(services))} services")

        print()
        print("[2] Attempting notification subscription...")

        # Try multiple times with delays
        subscribed = False
        for attempt in range(3):
            try:
                await client.start_notify(UUID_1911, handler)
                print(f"  [OK] Subscribed on attempt {attempt + 1}!")
                subscribed = True
                break
            except Exception as e:
                err_str = str(e)
                print(f"  Attempt {attempt + 1}: {err_str}")
                if "NotPermitted" in err_str:
                    # Try disconnecting and reconnecting
                    if attempt < 2:
                        print(f"  Retrying after disconnect...")
                        await client.disconnect()
                        await asyncio.sleep(1.0)
                        await client.connect()
                        await asyncio.sleep(1.0)

        if not subscribed:
            print("  [WARN] Could not subscribe - continuing without notifications")

        await asyncio.sleep(0.5)

        print()
        print("[3] Sending handshake...")
        print("-" * 60)

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            responses.clear()

            print(f"\n  [{name}] -> {cmd_hex}")

            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                if subscribed:
                    if await wait_response(timeout=2.0):
                        pass
                    else:
                        print(f"  (no response)")
                else:
                    await asyncio.sleep(0.3)
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 60)

        # Control commands
        print("\n[4] Control commands...")
        for name, cmd in [("ON", "b0c00101"), ("OFF", "b0c00100")]:
            print(f"\n  [{name}] -> {cmd}")
            try:
                await client.write_gatt_char(UUID_1912, bytes.fromhex(cmd), response=False)
                print("  Sent - check light!")
                await asyncio.sleep(3.0)
            except Exception as e:
                print(f"  Error: {e}")

    finally:
        if subscribed:
            try:
                await client.stop_notify(UUID_1911)
            except:
                pass
        await client.disconnect()

    print()
    print("Done!")

if __name__ == "__main__":
    asyncio.run(main())
