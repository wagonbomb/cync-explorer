#!/usr/bin/env python3
"""
Linux BLE v5 - Proper service discovery and notification handling
"""

import asyncio
from bleak import BleakClient, BleakScanner

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
    print("LINUX BLE v5 - PROPER SERVICE DISCOVERY")
    print("=" * 60)
    print(f"Target: {TARGET_MAC}")
    print()

    # Scan first to ensure device is in BlueZ cache
    print("[0] Scanning for device...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=15.0)

    if not device:
        print("  Device not found during scan")
        print("  Trying direct connection anyway...")
        device = TARGET_MAC
    else:
        print(f"  Found: {device.name} ({device.address})")

    print()
    print("[1] Connecting...")

    # Use context manager for proper cleanup
    async with BleakClient(device, timeout=30.0) as client:
        print(f"  Connected! MTU: {client.mtu_size}")

        # Explicit service discovery wait
        print()
        print("[2] Waiting for service discovery...")
        await asyncio.sleep(2.0)

        # List services
        services = client.services
        print(f"  Found {len(list(services))} services")

        for service in services:
            if "1910" in service.uuid:
                print(f"\n  Telink Service: {service.uuid}")
                for char in service.characteristics:
                    props = ", ".join(char.properties)
                    print(f"    {char.uuid[-4:]} Handle:{char.handle:3d} ({props})")

        # Try subscribing
        print()
        print("[3] Subscribing to notifications (1911)...")
        subscribed = False
        try:
            await client.start_notify(UUID_1911, handler)
            print("  [OK] Subscribed!")
            subscribed = True
        except Exception as e:
            err_str = str(e)
            print(f"  [FAIL] {err_str}")
            if "NotPermitted" in err_str or "acquired" in err_str.lower():
                print("  Note: BlueZ has notification lock. Will continue without notifications.")

        await asyncio.sleep(0.5)

        print()
        print("[4] Sending handshake...")
        print("-" * 60)

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            responses.clear()

            print(f"\n  [{name}] -> {cmd_hex}")

            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                if subscribed:
                    if await wait_response(timeout=2.0):
                        pass  # Already printed in handler
                    else:
                        print(f"  (no response)")
                else:
                    # Try reading instead
                    await asyncio.sleep(0.3)
                    try:
                        data = await client.read_gatt_char(UUID_1911)
                        if data:
                            print(f"  <- READ: {data.hex()}")
                    except:
                        print(f"  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 60)

        # Try control commands
        print("\n[5] Trying control commands...")
        for name, cmd in [("ON", "b0c00101"), ("OFF", "b0c00100")]:
            print(f"\n  [{name}] -> {cmd}")
            try:
                await client.write_gatt_char(UUID_1912, bytes.fromhex(cmd), response=False)
                print("  Sent - check light!")
                await asyncio.sleep(3.0)
            except Exception as e:
                print(f"  Error: {e}")

        # Cleanup
        if subscribed:
            try:
                await client.stop_notify(UUID_1911)
            except:
                pass

    print()
    print("Done!")

if __name__ == "__main__":
    asyncio.run(main())
