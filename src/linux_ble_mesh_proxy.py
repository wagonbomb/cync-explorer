#!/usr/bin/env python3
"""
Cync BLE test using Mesh Proxy service (which accepts notification subscriptions)
"""

import asyncio
from bleak import BleakScanner, BleakClient

TARGET_MAC = "34:13:43:46:CA:84"

# Mesh Proxy service (standard Bluetooth Mesh)
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"    # Write
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"   # Notify

# Mesh Provisioning (2adc/2adb) also available
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"    # Write
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"   # Notify

# Also try Telink characteristics
TELINK_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"
TELINK_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"

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

def make_handler(name):
    def handler(sender, data):
        hex_data = data.hex()
        print(f"  <- [{name}] {hex_data}")
        responses.append((name, data))
        response_event.set()
    return handler

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
    print("CYNC BLE - MESH PROXY PATH")
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
        print("[3] Subscribing to notifications...")

        # Try Mesh Proxy Out
        try:
            await client.start_notify(MESH_PROXY_OUT, make_handler("PROXY"))
            print(f"  [OK] Mesh Proxy Out (2ade)")
        except Exception as e:
            print(f"  [FAIL] Mesh Proxy Out: {e}")

        # Try Mesh Prov Out
        try:
            await client.start_notify(MESH_PROV_OUT, make_handler("PROV"))
            print(f"  [OK] Mesh Prov Out (2adc)")
        except Exception as e:
            print(f"  [FAIL] Mesh Prov Out: {e}")

        # Try Telink 1911
        try:
            await client.start_notify(TELINK_1911, make_handler("TELINK"))
            print(f"  [OK] Telink 1911")
        except Exception as e:
            print(f"  [FAIL] Telink 1911: {e}")

        await asyncio.sleep(0.5)

        print()
        print("[4] Sending handshake via TELINK 1912...")
        print("-" * 60)

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            responses.clear()

            print(f"\n  [{name}] -> {cmd_hex}")

            try:
                await client.write_gatt_char(TELINK_1912, cmd, response=False)
                if await wait_response(timeout=2.0):
                    pass  # Already printed in handler
                else:
                    print(f"  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 60)

        print()
        print("[5] Trying handshake via MESH PROXY IN...")
        print("-" * 60)

        for name, cmd_hex in HANDSHAKE[:3]:  # Just first few
            cmd = bytes.fromhex(cmd_hex)
            responses.clear()

            print(f"\n  [{name}] -> {cmd_hex}")

            try:
                await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
                if await wait_response(timeout=2.0):
                    pass
                else:
                    print(f"  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 60)

        print()
        print("[6] Control commands via TELINK...")
        for name, cmd in [("ON", "b0c00101"), ("OFF", "b0c00100")]:
            print(f"\n  [{name}] -> {cmd}")
            try:
                await client.write_gatt_char(TELINK_1912, bytes.fromhex(cmd), response=False)
                print("  Sent - check light!")
                await asyncio.sleep(3.0)
            except Exception as e:
                print(f"  Error: {e}")

    print()
    print("Done!")

if __name__ == "__main__":
    asyncio.run(main())
