#!/usr/bin/env python3
"""
BLE Pairing/Bonding Test

The device might require bonding before allowing notification subscriptions.
This script attempts to pair with the device and then retry the handshake.
"""

import asyncio
import subprocess
from bleak import BleakClient, BleakScanner
from bleak.backends.winrt.client import BleakClientWinRT

TARGET_MAC = "34:13:43:46:CA:84"

UUID_TELINK_STATUS = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"
UUID_MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

responses = []
response_event = asyncio.Event()

def handler(char, data):
    print(f"  NOTIFY: {data.hex()}")
    responses.append(bytes(data))
    response_event.set()

async def wait_response(timeout=3.0):
    global response_event
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.1)
        response_event.clear()
        return True
    except asyncio.TimeoutError:
        response_event.clear()
        return False

async def try_pair_and_subscribe(client: BleakClient):
    """Try to pair with the device"""
    print("\n[PAIR] Attempting to pair with device...")

    # Try to trigger pairing by reading a protected characteristic
    # or by attempting to write to the CCCD
    try:
        # On Windows, we can try to access pairing through the backend
        if hasattr(client, '_backend') and hasattr(client._backend, '_requester'):
            requester = client._backend._requester
            if hasattr(requester, 'device_information'):
                print("  Accessing device information to trigger pairing...")

        # Try reading various characteristics that might require pairing
        for service in client.services:
            for char in service.characteristics:
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char)
                        print(f"  Read {char.uuid}: {value.hex() if value else 'empty'}")
                    except Exception as e:
                        if "pair" in str(e).lower() or "auth" in str(e).lower():
                            print(f"  Pairing required for {char.uuid}")
                        pass
    except Exception as e:
        print(f"  Pair attempt error: {e}")

async def main():
    print("=" * 70)
    print("BLE PAIRING TEST")
    print("=" * 70)
    print(f"Target: {TARGET_MAC}")
    print()

    # First, try to remove any existing pairing
    print("[1] Checking for existing Bluetooth pairing...")
    print("    (You may need to unpair the device in Windows Bluetooth settings)")
    print()

    print("[2] Scanning for device...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=15.0)
    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name} ({device.address})")
    print()

    # Connect with pairing enabled
    print("[3] Connecting with pairing support...")
    async with BleakClient(device, timeout=30.0) as client:
        print(f"[CONNECTED] MTU: {client.mtu_size}")

        # Try to trigger/check pairing
        await try_pair_and_subscribe(client)

        print("\n[4] Trying to subscribe to Telink Status (1911)...")
        try:
            await client.start_notify(UUID_TELINK_STATUS, handler)
            print("  [SUCCESS] Subscribed to 1911!")
        except Exception as e:
            print(f"  [FAILED] {e}")
            print()
            print("  The Telink Status characteristic requires special permissions")
            print("  that Windows BLE stack doesn't grant by default.")

        print("\n[5] Trying to subscribe to MESH_PROV_OUT...")
        try:
            await client.start_notify(UUID_MESH_PROV_OUT, handler)
            print("  [SUCCESS] Subscribed to MESH_PROV_OUT!")
        except Exception as e:
            print(f"  [FAILED] {e}")

        print("\n[6] Attempting handshake anyway...")
        await asyncio.sleep(0.5)

        # Try different write characteristics
        write_targets = [
            ("1911", UUID_TELINK_STATUS),
            ("1912", UUID_TELINK_CMD),
        ]

        handshake = bytes.fromhex("000501000000000000000000")

        for name, uuid in write_targets:
            responses.clear()
            print(f"\n  Trying {name}...")
            try:
                await client.write_gatt_char(uuid, handshake, response=False)
                print(f"    Sent: {handshake.hex()}")
                if await wait_response(timeout=3.0):
                    print(f"    *** GOT RESPONSE! ***")
                    for r in responses:
                        print(f"    <- {r.hex()}")
                else:
                    print(f"    No response")
            except Exception as e:
                print(f"    Error: {e}")

        print("\n" + "=" * 70)
        print("PAIRING TEST COMPLETE")
        print("=" * 70)
        print()
        print("If pairing is required, you have a few options:")
        print("1. Use Windows Bluetooth settings to manually pair with the device")
        print("2. Use Android emulation (Bluestacks/Android-x86) with Cync app")
        print("3. Use a Linux system where BLE permissions work differently")
        print()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
