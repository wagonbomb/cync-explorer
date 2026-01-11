#!/usr/bin/env python3
"""
Raw GATT Test - Attempt Low-Level BLE Communication

This script attempts to bypass Bleak's CCCD abstraction and
communicate directly with the device using Windows-specific APIs.

Theory: Maybe Windows blocks notification subscription but not
direct writes/reads to the characteristic value handle.
"""

import asyncio
from bleak import BleakClient, BleakScanner
from bleak.backends.winrt.client import BleakClientWinRT

TARGET_MAC = "34:13:43:46:CA:84"

UUID_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"
UUID_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
UUID_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

# Handshake commands from HCI log
HANDSHAKE = [
    bytes.fromhex("000501000000000000000000"),  # START
    bytes.fromhex("00000100000000000000040000"),  # KEY_EXCHANGE
    bytes.fromhex("3100"),  # SYNC_0
    bytes.fromhex("3101"),  # SYNC_1
    bytes.fromhex("3102"),  # SYNC_2
    bytes.fromhex("3103"),  # SYNC_3
    bytes.fromhex("3104"),  # SYNC_4
    bytes.fromhex("00000100000000000000160000"),  # MSG_1
    bytes.fromhex("00000100000000000000010002"),  # MSG_2
    bytes.fromhex("320119000000"),  # AUTH_FINALIZE
]

responses = []
notify_event = asyncio.Event()

def handler(char, data):
    hex_data = data.hex()
    print(f"    <- {hex_data}")
    responses.append(bytes(data))
    notify_event.set()

async def poll_for_response(client, uuid, timeout=2.0, interval=0.1):
    """Poll by reading the characteristic repeatedly"""
    start = asyncio.get_event_loop().time()
    last_value = None

    while (asyncio.get_event_loop().time() - start) < timeout:
        try:
            value = await client.read_gatt_char(uuid)
            if value and value != last_value:
                if value != bytes(len(value)):  # Not all zeros
                    print(f"    <- READ: {value.hex()}")
                    return value
                last_value = value
        except:
            pass
        await asyncio.sleep(interval)

    return None

async def main():
    print("=" * 70)
    print("RAW GATT TEST - LOW-LEVEL BLE COMMUNICATION")
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
        print()

        # Subscribe to available notification characteristics
        print("[1] Setting up notifications...")
        try:
            await client.start_notify(UUID_PROV_OUT, handler)
            print(f"    [OK] PROV_OUT")
        except:
            print(f"    [FAIL] PROV_OUT")

        await asyncio.sleep(0.5)

        # Test 1: Write to 1912, poll 1911 for response
        print("\n[2] Test: Write to 1912, poll 1911 for response")
        print("-" * 50)

        for i, cmd in enumerate(HANDSHAKE):
            print(f"\n  [{i}] -> {cmd.hex()}")
            responses.clear()
            notify_event.clear()

            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)

                # Check if notification came through PROV_OUT
                try:
                    await asyncio.wait_for(notify_event.wait(), timeout=1.0)
                    if responses:
                        print(f"    Got notification via PROV_OUT!")
                        continue
                except asyncio.TimeoutError:
                    pass

                # Poll 1911 for response
                resp = await poll_for_response(client, UUID_1911, timeout=1.0)
                if resp:
                    print(f"    Got response via polling!")
                else:
                    print(f"    No response")

            except Exception as e:
                print(f"    Error: {e}")

        # Test 2: Write to PROV_IN instead
        print("\n\n[3] Test: Write to PROV_IN instead")
        print("-" * 50)

        for i, cmd in enumerate(HANDSHAKE[:3]):  # Just first 3 commands
            print(f"\n  [{i}] -> {cmd.hex()}")
            responses.clear()
            notify_event.clear()

            try:
                await client.write_gatt_char(UUID_PROV_IN, cmd, response=False)

                try:
                    await asyncio.wait_for(notify_event.wait(), timeout=2.0)
                    if responses:
                        print(f"    Got notification!")
                        for r in responses:
                            print(f"    <- {r.hex()}")
                except asyncio.TimeoutError:
                    print(f"    No response")

            except Exception as e:
                print(f"    Error: {e}")

        # Test 3: Continuous read loop
        print("\n\n[4] Test: Continuous read loop while writing")
        print("-" * 50)

        async def read_loop():
            """Continuously read from 1911"""
            while True:
                try:
                    value = await client.read_gatt_char(UUID_1911)
                    if value and value != bytes(len(value)):
                        print(f"    READ 1911: {value.hex()}")
                except:
                    pass
                await asyncio.sleep(0.05)

        # Start read loop in background
        read_task = asyncio.create_task(read_loop())

        # Send handshake
        for i, cmd in enumerate(HANDSHAKE[:5]):
            print(f"\n  [{i}] -> {cmd.hex()} (to 1912)")
            await client.write_gatt_char(UUID_1912, cmd, response=False)
            await asyncio.sleep(0.5)

        # Cancel read loop
        read_task.cancel()
        try:
            await read_task
        except asyncio.CancelledError:
            pass

        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print()
        if responses:
            print(f"Total responses received: {len(responses)}")
            for r in responses:
                print(f"  {r.hex()}")
        else:
            print("No responses received.")
            print()
            print("The device is not sending any data back.")
            print("This confirms the Windows BLE notification issue.")
            print()
            print("REQUIRED: Use Android to complete pairing.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
