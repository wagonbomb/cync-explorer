#!/usr/bin/env python3
"""
Linux BLE Test v4 - Keep scanner active during connect
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
    print(f"  <- {data.hex()}")
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
    print("LINUX BLE TEST v4 - SCANNER STAYS ACTIVE")
    print("=" * 60)
    print(f"Target: {TARGET_MAC}")
    print()

    print("Starting continuous scan...")
    scanner = BleakScanner()
    await scanner.start()

    # Wait for device to appear
    device = None
    for _ in range(30):
        await asyncio.sleep(0.5)
        for d in scanner.discovered_devices:
            if d.address.upper() == TARGET_MAC.upper():
                device = d
                print(f"Found: {d.name} ({d.address})")
                break
        if device:
            break

    if not device:
        await scanner.stop()
        print("[ERROR] Device not found")
        return

    # Keep scanner running while we connect
    print("\nConnecting (scanner still active)...")

    try:
        client = BleakClient(device, timeout=30.0)
        connected = await client.connect()

        if not connected:
            print("[ERROR] Connection failed")
            await scanner.stop()
            return

        print(f"[CONNECTED]")

        # Now we can stop the scanner
        await scanner.stop()

        # Get services
        print("\nDiscovering services...")
        await asyncio.sleep(1.0)
        services = client.services

        for service in services:
            if "1910" in service.uuid:
                print(f"\n  Telink Service: {service.uuid}")
                for char in service.characteristics:
                    print(f"    {char.uuid} ({', '.join(char.properties)})")

        print()
        print("[1] Subscribing to 1911...")
        try:
            await client.start_notify(UUID_1911, handler)
            print("  [OK] Subscribed!")
        except Exception as e:
            print(f"  [FAIL] {e}")

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

        await client.disconnect()

    except Exception as e:
        print(f"Error: {e}")
        await scanner.stop()

if __name__ == "__main__":
    asyncio.run(main())
