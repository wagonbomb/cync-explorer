#!/usr/bin/env python3
"""
Simple BLE test - just send commands, no notifications
"""

import asyncio
from bleak import BleakScanner, BleakClient

TARGET_MAC = "34:13:43:46:CA:84"
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

async def main():
    print("=" * 60)
    print("SIMPLE BLE TEST - NO NOTIFICATIONS")
    print("=" * 60)
    print()

    print("[1] Finding device...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=20.0)
    if not device:
        print("Device not found!")
        return
    print(f"Found: {device.name}")

    print()
    print("[2] Connecting...")
    async with BleakClient(device, timeout=30.0) as client:
        print(f"Connected! MTU: {client.mtu_size}")

        await asyncio.sleep(1.0)

        print()
        print("[3] Sending handshake...")
        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            print(f"  {name}: {cmd_hex}")
            await client.write_gatt_char(UUID_1912, cmd, response=False)
            await asyncio.sleep(0.2)

        print()
        print("[4] Control commands...")
        print()
        print(">>> Sending ON command - WATCH THE LIGHT! <<<")
        await client.write_gatt_char(UUID_1912, bytes.fromhex("b0c00101"), response=False)
        await asyncio.sleep(5.0)

        print()
        print(">>> Sending OFF command - WATCH THE LIGHT! <<<")
        await client.write_gatt_char(UUID_1912, bytes.fromhex("b0c00100"), response=False)
        await asyncio.sleep(5.0)

    print()
    print("Done! Did you see the light change?")

if __name__ == "__main__":
    asyncio.run(main())
