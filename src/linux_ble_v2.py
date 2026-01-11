#!/usr/bin/env python3
"""
Linux BLE Test v2 - Direct connection without pre-scan
"""

import asyncio
from bleak import BleakClient, BleakScanner
from bleak.backends.bluezdbus.scanner import BlueZScannerArgs

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
    print("LINUX BLE TEST v2")
    print("=" * 60)
    print(f"Target: {TARGET_MAC}")
    print()

    # Scan with active scanning to ensure device is in BlueZ cache
    print("Scanning (active mode)...")
    scanner = BleakScanner(
        scanning_mode="active",
        bluez=BlueZScannerArgs(or_patterns=[{"PatternType": 1}])
    )

    device = None
    async with scanner:
        await asyncio.sleep(3.0)
        devices = scanner.discovered_devices
        for d in devices:
            if d.address.upper() == TARGET_MAC.upper():
                device = d
                break

    if not device:
        # Try passive scanning
        print("Trying passive scan...")
        device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)

    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name} ({device.address})")
    print()

    # Connect with longer timeout
    print("Connecting...")
    try:
        client = BleakClient(device, timeout=60.0)
        await client.connect()
    except Exception as e:
        print(f"Connection failed: {e}")
        print()
        print("Try running in WSL terminal:")
        print("  bluetoothctl")
        print("  scan on")
        print("  (wait for device to appear)")
        print("  connect 34:13:43:46:CA:84")
        return

    print(f"[CONNECTED] MTU: {client.mtu_size}")
    print()

    try:
        # Subscribe to notifications
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
                    for r in responses:
                        print(f"  <- {r.hex()}")
                else:
                    print(f"  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 60)

        if any(responses):
            print("Got responses! Trying control...")
            await asyncio.sleep(1.0)

            for name, cmd in [("ON", "b0c00101"), ("OFF", "b0c00100")]:
                print(f"\n[{name}] -> {cmd}")
                await client.write_gatt_char(UUID_1912, bytes.fromhex(cmd), response=False)
                print("  Watch the light!")
                await asyncio.sleep(3.0)
        else:
            print("No responses - handshake may have failed")

    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
