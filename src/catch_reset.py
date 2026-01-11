#!/usr/bin/env python3
"""
Catch device immediately after factory reset.
Run this script, then do the factory reset while it's scanning.
"""

import asyncio
from bleak import BleakClient, BleakScanner, BleakError

TARGET_MAC = "34:13:43:46:CA:84"
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

responses = []

def handler(sender, data):
    print(f"  RESPONSE: {data.hex()}")
    responses.append(data)

async def try_provision():
    """Try to provision immediately after connecting"""
    print("\n[CONNECT] Attempting connection...")

    try:
        device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=5.0)
        if not device:
            return False

        print(f"[FOUND] {device.name}")

        async with BleakClient(device, timeout=10.0) as client:
            print("[CONNECTED]")

            # Subscribe immediately
            await client.start_notify(MESH_PROV_OUT, handler)

            # Send invite immediately
            print("[INVITE] Sending provisioning invite...")
            await client.write_gatt_char(MESH_PROV_IN, bytes([0x00, 0x05]), response=False)

            # Wait for response
            await asyncio.sleep(3.0)

            if responses:
                print(f"[SUCCESS] Got response: {responses[-1].hex()}")
                if responses[-1][0] == 0x01:
                    print("[CAPABILITIES] Device sent capabilities!")
                    print("Press Ctrl+C and run mesh_provision_debug.py")
                return True
            else:
                print("[NO RESPONSE]")
                return False

    except BleakError as e:
        print(f"[ERROR] {e}")
        return False

async def main():
    print("=" * 60)
    print("FACTORY RESET CATCHER")
    print("=" * 60)
    print(f"Target: {TARGET_MAC}")
    print()
    print("Instructions:")
    print("1. Keep this script running")
    print("2. Power off the bulb for 30 seconds")
    print("3. Do rapid 5x power cycle (1s on, 1s off)")
    print("4. Leave bulb ON after 5th cycle")
    print("5. Watch for 'Got response' message")
    print()
    print("Scanning continuously... (Ctrl+C to stop)")
    print("=" * 60)

    attempt = 0
    while True:
        attempt += 1
        print(f"\n[Attempt {attempt}]", end=" ", flush=True)

        success = await try_provision()

        if success and responses:
            print("\n*** DEVICE RESPONDED! ***")
            print("Run: python src/mesh_provision_debug.py")
            break

        # Short delay between attempts
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
