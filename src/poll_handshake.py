#!/usr/bin/env python3
"""
Poll Handshake - Send commands and poll for responses

Since we can't use notifications, we poll the 1911 characteristic
for responses after each command.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

UUID_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"

# Full handshake sequence from HCI log
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

async def poll_characteristic(client, uuid, duration=1.0, interval=0.05):
    """Poll a characteristic for changes"""
    readings = []
    start = asyncio.get_event_loop().time()

    while (asyncio.get_event_loop().time() - start) < duration:
        try:
            value = await client.read_gatt_char(uuid)
            if value:
                hex_val = value.hex()
                if hex_val not in [r[1] for r in readings]:  # New unique value
                    readings.append((asyncio.get_event_loop().time() - start, hex_val))
        except Exception as e:
            pass
        await asyncio.sleep(interval)

    return readings

async def main():
    print("=" * 70)
    print("POLL HANDSHAKE - RESPONSE DETECTION VIA POLLING")
    print("=" * 70)
    print(f"Target: {TARGET_MAC}")
    print()

    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=15.0)
    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name}")
    print()

    async with BleakClient(device, timeout=30.0) as client:
        print(f"[CONNECTED] MTU: {client.mtu_size}")
        print()

        # Initial read of 1911
        print("[1] Initial read of 1911...")
        try:
            initial = await client.read_gatt_char(UUID_1911)
            print(f"    Initial value: {initial.hex() if initial else 'empty'}")
        except Exception as e:
            print(f"    Read error: {e}")

        print()
        print("[2] Sending handshake with polling...")
        print("-" * 70)

        all_responses = []

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            print(f"\n  [{name}]")
            print(f"    -> {cmd_hex}")

            try:
                # Send command
                await client.write_gatt_char(UUID_1912, cmd, response=False)

                # Poll for response
                readings = await poll_characteristic(client, UUID_1911, duration=0.5)

                if readings:
                    for t, val in readings:
                        print(f"    <- {val} (at +{t:.2f}s)")
                        all_responses.append((name, val))
                else:
                    print(f"    (no change)")

            except Exception as e:
                print(f"    Error: {e}")
                if "Not connected" in str(e):
                    print("\n[DISCONNECTED]")
                    return

        print()
        print("=" * 70)
        print("HANDSHAKE SENT")
        print("=" * 70)
        print()

        if all_responses:
            print(f"Detected {len(all_responses)} unique responses:")
            for name, val in all_responses:
                print(f"  [{name}] {val}")
        else:
            print("No responses detected via polling.")
            print()
            print("This could mean:")
            print("1. The device responds via notifications only (not readable)")
            print("2. The handshake failed silently")
            print("3. The protocol requires different data")

        # Try control commands regardless
        print()
        print("[3] Attempting control commands...")
        print("-" * 70)

        # Try both prefixed and unprefixed commands
        commands = [
            ("ON (b0c0 prefix)", "b0c00101"),
            ("OFF (b0c0 prefix)", "b0c00100"),
            ("ON (raw)", "0101"),
            ("OFF (raw)", "0100"),
            ("ON (D0 prefix)", "d0c00101"),
            ("Brightness 100%", "b0c002ff"),
        ]

        for name, cmd_hex in commands:
            cmd = bytes.fromhex(cmd_hex)
            print(f"\n  [{name}]")
            print(f"    -> {cmd_hex}")

            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                await asyncio.sleep(1.0)
                print(f"    Sent - check if light changed!")
            except Exception as e:
                print(f"    Error: {e}")

        print()
        print("=" * 70)
        print("TEST COMPLETE")
        print("=" * 70)
        print()
        print("Please report:")
        print("1. Did the light blink or change at any point?")
        print("2. If so, which command caused it?")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
