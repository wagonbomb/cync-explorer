#!/usr/bin/env python3
"""
Linux BLE Test - With Notification Support

This test should work on Linux where Windows failed.
Linux BlueZ can subscribe to notifications without a CCCD.
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

def notification_handler(sender, data):
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
    print("LINUX BLE TEST - WITH NOTIFICATIONS")
    print("=" * 60)
    print(f"Target: {TARGET_MAC}")
    print()

    print("Scanning...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=15.0)
    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name}")
    print()

    async with BleakClient(device, timeout=30.0) as client:
        print(f"[CONNECTED] MTU: {client.mtu_size}")
        print()

        # Try to subscribe to Telink Status (1911)
        print("[1] Subscribing to Telink Status (1911)...")
        try:
            await client.start_notify(UUID_1911, notification_handler)
            print("  [OK] Subscribed to 1911!")
            subscribed = True
        except Exception as e:
            print(f"  [FAIL] {e}")
            subscribed = False

        await asyncio.sleep(0.5)

        print()
        print("[2] Sending handshake with response monitoring...")
        print("-" * 60)

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            responses.clear()

            print(f"\n  [{name}]")
            print(f"    -> {cmd_hex}")

            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)

                # Wait for response
                if await wait_response(timeout=2.0):
                    print(f"    <- Got {len(responses)} response(s)")
                else:
                    print(f"    (no response)")

            except Exception as e:
                print(f"    Error: {e}")

        print()
        print("=" * 60)
        print("HANDSHAKE COMPLETE")
        print("=" * 60)

        # Check if we got any responses
        if responses:
            print(f"\nLast response: {responses[-1].hex()}")

            # Try control command
            print("\n[3] Trying control commands...")
            await asyncio.sleep(1.0)

            control_cmds = [
                ("ON", "b0c00101"),
                ("OFF", "b0c00100"),
            ]

            for name, cmd_hex in control_cmds:
                cmd = bytes.fromhex(cmd_hex)
                responses.clear()
                print(f"\n  [{name}] -> {cmd_hex}")
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                await wait_response(timeout=1.0)
                print("  Check light!")
                await asyncio.sleep(2.0)
        else:
            print("\nNo responses received from handshake.")
            print("The protocol may require different initialization.")

if __name__ == "__main__":
    asyncio.run(main())
