#!/usr/bin/env python3
"""
Simple Connect Test - No Notifications

Just connect, write to the device, and poll for responses.
Don't try to subscribe to any notifications since that seems
to cause issues on Windows.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

UUID_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"
UUID_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"

# Handshake commands
HANDSHAKE = [
    bytes.fromhex("000501000000000000000000"),  # START
    bytes.fromhex("00000100000000000000040000"),  # KEY_EXCHANGE
    bytes.fromhex("3100"),
    bytes.fromhex("3101"),
    bytes.fromhex("3102"),
    bytes.fromhex("3103"),
    bytes.fromhex("3104"),
    bytes.fromhex("320119000000"),  # AUTH_FINALIZE
]

async def main():
    print("=" * 70)
    print("SIMPLE CONNECT TEST - NO NOTIFICATIONS")
    print("=" * 70)
    print(f"Target: {TARGET_MAC}")
    print()

    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=15.0)
    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name or 'Unknown'}")
    print()

    async with BleakClient(device, timeout=30.0) as client:
        print(f"[CONNECTED] MTU: {client.mtu_size}")

        # Just check connection
        print("\n[1] Connection established. Reading device info...")
        await asyncio.sleep(1.0)

        if not client.is_connected:
            print("[DISCONNECTED] Lost connection immediately!")
            return

        # Read some characteristics to verify connection
        try:
            name = await client.read_gatt_char("00002a00-0000-1000-8000-00805f9b34fb")
            print(f"  Device Name: {name.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"  Could not read device name: {e}")

        await asyncio.sleep(0.5)

        if not client.is_connected:
            print("[DISCONNECTED] Lost connection after read!")
            return

        print("\n[2] Attempting handshake WITHOUT notifications...")
        print("-" * 50)

        # Try writing and immediately reading
        for i, cmd in enumerate(HANDSHAKE):
            if not client.is_connected:
                print(f"\n[DISCONNECTED] Connection lost at step {i}")
                return

            print(f"\n  [{i}] -> {cmd.hex()}")

            try:
                # Write to 1912
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                print(f"      Wrote to 1912")

                # Immediately try to read 1911
                await asyncio.sleep(0.3)
                try:
                    resp = await client.read_gatt_char(UUID_1911)
                    if resp:
                        print(f"      1911 read: {resp.hex()}")
                except:
                    print(f"      1911 read failed")

            except Exception as e:
                print(f"      Error: {e}")
                if "Not connected" in str(e):
                    print("\n[DISCONNECTED]")
                    return

            await asyncio.sleep(0.2)

        print("\n" + "=" * 70)
        print("HANDSHAKE COMPLETE (or connection lost)")
        print("=" * 70)

        # Try a control command
        if client.is_connected:
            print("\n[3] Trying control command...")
            control = bytes.fromhex("b0c00101")  # ON command guess
            try:
                await client.write_gatt_char(UUID_1912, control, response=False)
                print(f"  Sent: {control.hex()}")
                await asyncio.sleep(2.0)
                print("  Check if light changed!")
            except Exception as e:
                print(f"  Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
