#!/usr/bin/env python3
"""
Linux BLE Poll - Use polling instead of notifications
Since BlueZ is blocking notifications, we poll the characteristic
"""

import asyncio
from bleak import BleakClient

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

async def main():
    print("=" * 60)
    print("LINUX BLE POLL MODE")
    print("=" * 60)
    print(f"Target: {TARGET_MAC}")
    print()

    print("Connecting...")
    try:
        async with BleakClient(TARGET_MAC, timeout=30.0) as client:
            print(f"[CONNECTED] MTU: {client.mtu_size}")

            # Read initial value
            print("\n[1] Reading 1911 initial value...")
            try:
                data = await client.read_gatt_char(UUID_1911)
                print(f"  Initial: {data.hex()}")
            except Exception as e:
                print(f"  Error reading: {e}")

            print()
            print("[2] Sending handshake with polling...")
            print("-" * 60)

            for name, cmd_hex in HANDSHAKE:
                cmd = bytes.fromhex(cmd_hex)

                print(f"\n  [{name}] -> {cmd_hex}")

                try:
                    await client.write_gatt_char(UUID_1912, cmd, response=False)
                    await asyncio.sleep(0.3)

                    # Poll for response
                    try:
                        data = await client.read_gatt_char(UUID_1911)
                        if data and len(data) > 0:
                            print(f"  <- {data.hex()}")
                        else:
                            print(f"  (empty)")
                    except Exception as e:
                        print(f"  (read error: {e})")

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
        print(f"Connection error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
