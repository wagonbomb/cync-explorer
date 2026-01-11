#!/usr/bin/env python3
"""
Direct CCCD Write Test

Try to directly write to the CCCD handle to enable notifications.
The CCCD (0x2902) handle should be right after the characteristic handle.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

UUID_TELINK_STATUS = "00010203-0405-0607-0809-0a0b0c0d1911"
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

async def main():
    print("=" * 70)
    print("DIRECT CCCD WRITE TEST")
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

        # List all services, characteristics, and descriptors with their handles
        print("=" * 70)
        print("COMPLETE GATT STRUCTURE WITH HANDLES")
        print("=" * 70)

        telink_status_char = None
        telink_status_desc_handles = []

        for service in client.services:
            print(f"\nService: {service.uuid} (handle: 0x{service.handle:04x})")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"  Char: {char.uuid}")
                print(f"    Handle: 0x{char.handle:04x}")
                print(f"    Props: {props}")

                if char.uuid.lower() == UUID_TELINK_STATUS.lower():
                    telink_status_char = char
                    print(f"    *** THIS IS TELINK STATUS ***")

                for desc in char.descriptors:
                    print(f"    Desc: {desc.uuid} (handle: 0x{desc.handle:04x})")
                    if char.uuid.lower() == UUID_TELINK_STATUS.lower():
                        telink_status_desc_handles.append(desc.handle)

        print()
        print("=" * 70)
        print("TELINK STATUS CHARACTERISTIC ANALYSIS")
        print("=" * 70)

        if telink_status_char:
            print(f"Characteristic handle: 0x{telink_status_char.handle:04x}")
            print(f"Known descriptors: {[f'0x{h:04x}' for h in telink_status_desc_handles]}")

            # The CCCD (0x2902) is usually at handle = char_handle + 1 or + 2
            # Let's try writing to potential CCCD handles
            potential_cccd_handles = [
                telink_status_char.handle + 1,  # Immediately after
                telink_status_char.handle + 2,  # Skip one
            ]

            print(f"Potential CCCD handles to try: {[f'0x{h:04x}' for h in potential_cccd_handles]}")
            print()

            # First, subscribe to MESH_PROV_OUT so we can receive notifications
            print("[1] Subscribing to MESH_PROV_OUT first...")
            try:
                await client.start_notify(UUID_MESH_PROV_OUT, handler)
                print("  [OK] Subscribed to MESH_PROV_OUT")
            except Exception as e:
                print(f"  [FAIL] {e}")

            await asyncio.sleep(0.5)

            # Try direct GATT write to potential CCCD handles
            print("\n[2] Trying direct writes to potential CCCD handles...")
            print("    (Note: Windows may block this at the OS level)")

            for cccd_handle in potential_cccd_handles:
                print(f"\n  Trying handle 0x{cccd_handle:04x}...")
                try:
                    # Try to find a descriptor with this handle
                    for service in client.services:
                        for char in service.characteristics:
                            for desc in char.descriptors:
                                if desc.handle == cccd_handle:
                                    print(f"    Found descriptor: {desc.uuid}")
                                    # Try to write notification enable
                                    await client.write_gatt_descriptor(desc.handle, b'\x01\x00')
                                    print(f"    [OK] Wrote 0x0001 to handle 0x{cccd_handle:04x}")
                except Exception as e:
                    print(f"    [FAIL] {e}")

            print("\n[3] Trying handshake after CCCD writes...")
            handshake = bytes.fromhex("000501000000000000000000")

            # Try writing to 1911 directly (it has write property)
            print("\n  Writing handshake to 1911...")
            try:
                await client.write_gatt_char(UUID_TELINK_STATUS, handshake, response=False)
                print(f"    Sent: {handshake.hex()}")
                if await wait_response(timeout=3.0):
                    print("    *** GOT RESPONSE! ***")
                    for r in responses:
                        print(f"    <- {r.hex()}")
                else:
                    print("    No response")
            except Exception as e:
                print(f"    Error: {e}")

            # Also try 1912
            responses.clear()
            print("\n  Writing handshake to 1912...")
            try:
                await client.write_gatt_char("00010203-0405-0607-0809-0a0b0c0d1912", handshake, response=False)
                print(f"    Sent: {handshake.hex()}")
                if await wait_response(timeout=3.0):
                    print("    *** GOT RESPONSE! ***")
                    for r in responses:
                        print(f"    <- {r.hex()}")
                else:
                    print("    No response")
            except Exception as e:
                print(f"    Error: {e}")

        print("\n" + "=" * 70)
        print("TEST COMPLETE")
        print("=" * 70)
        print()
        print("If CCCD writes are blocked, the Windows BLE stack is preventing")
        print("notification subscriptions on this characteristic.")
        print()
        print("Solutions:")
        print("1. Try on Linux (different BLE stack)")
        print("2. Try Android emulator with USB BLE passthrough")
        print("3. Try with a physical Android phone running Cync app")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
