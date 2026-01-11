#!/usr/bin/env python3
"""
Wait for Cync device to appear and then run protocol test
The device may be in sleep mode - toggle the light switch to wake it
"""

import asyncio
from bleak import BleakScanner, BleakClient

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

def detection_callback(device, adv_data):
    """Called when any BLE device is detected"""
    if device.address.upper() == TARGET_MAC.upper():
        print(f"\n*** FOUND: {device.name} ({device.address}) RSSI:{adv_data.rssi} ***\n")

async def wait_for_device(timeout=120):
    """Wait for target device to appear in scan"""
    print(f"Waiting for device {TARGET_MAC} to appear...")
    print("TIP: Toggle the light switch OFF then ON to wake the device")
    print()

    # Use simple find_device_by_address
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=timeout)
    return device

async def run_protocol_test(device):
    """Run the BLE protocol test"""
    print()
    print("=" * 60)
    print("RUNNING PROTOCOL TEST")
    print("=" * 60)
    print()

    print("[1] Connecting...")
    async with BleakClient(device, timeout=30.0) as client:
        print(f"  Connected! MTU: {client.mtu_size}")

        # Wait for service discovery
        await asyncio.sleep(2.0)

        services = client.services
        print(f"  Found {len(list(services))} services")

        # Show Telink service
        for service in services:
            if "1910" in service.uuid:
                print(f"\n  Telink Service: {service.uuid}")
                for char in service.characteristics:
                    props = ", ".join(char.properties)
                    print(f"    {char.uuid[-4:]} Handle:{char.handle:3d} ({props})")

        print()
        print("[2] Subscribing to notifications...")
        subscribed = False
        try:
            await client.start_notify(UUID_1911, notification_handler)
            print("  [OK] Subscribed to 1911!")
            subscribed = True
        except Exception as e:
            err_str = str(e)
            print(f"  [WARN] {err_str}")
            print("  Continuing without notifications...")

        await asyncio.sleep(0.5)

        print()
        print("[3] Sending handshake...")
        print("-" * 60)

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            responses.clear()

            print(f"\n  [{name}] -> {cmd_hex}")

            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                if subscribed:
                    if await wait_response(timeout=2.0):
                        pass  # Already printed
                    else:
                        print(f"  (no response)")
                else:
                    await asyncio.sleep(0.3)
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 60)

        # Try control
        print("\n[4] Control commands...")
        for name, cmd in [("ON", "b0c00101"), ("OFF", "b0c00100")]:
            print(f"\n  [{name}] -> {cmd}")
            try:
                await client.write_gatt_char(UUID_1912, bytes.fromhex(cmd), response=False)
                print("  Sent - check light!")
                await asyncio.sleep(3.0)
            except Exception as e:
                print(f"  Error: {e}")

        if subscribed:
            try:
                await client.stop_notify(UUID_1911)
            except:
                pass

    print()
    print("Test complete!")

async def main():
    print("=" * 60)
    print("CYNC BLE PROTOCOL CAPTURE")
    print("=" * 60)
    print()

    device = await wait_for_device(timeout=120)

    if device:
        await run_protocol_test(device)
    else:
        print()
        print("Device not found after timeout.")
        print("Please make sure:")
        print("  1. The light bulb is powered ON")
        print("  2. You are within BLE range (~10m)")
        print("  3. The light is not paired to another controller")
        print("  4. Try toggling the light switch OFF then ON")

if __name__ == "__main__":
    asyncio.run(main())
