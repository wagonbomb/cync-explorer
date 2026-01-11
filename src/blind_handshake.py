#!/usr/bin/env python3
"""
Blind Handshake - Send all commands without reading/notifications

Just blast out the full handshake and control commands
to see if the light responds.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

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

# Control commands with different prefixes
CONTROL_COMMANDS = [
    ("ON (b0c0)", "b0c00101"),
    ("OFF (b0c0)", "b0c00100"),
    ("Brightness 50%", "b0c00280"),
    ("Brightness 100%", "b0c002ff"),
    ("ON (raw 01)", "01"),
    ("ON (d001)", "d001"),
    ("ON (c001)", "c001"),
]

async def main():
    print("=" * 70)
    print("BLIND HANDSHAKE - NO READS")
    print("=" * 70)
    print(f"Target: {TARGET_MAC}")
    print()
    print("This test sends all handshake commands blindly")
    print("without reading or subscribing to any characteristics.")
    print()
    print("WATCH THE LIGHT for any changes!")
    print()
    print("Starting in 2 seconds...")
    await asyncio.sleep(2.0)
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

        # Send handshake
        print("[1] Sending handshake sequence...")
        print("-" * 70)

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                print(f"  [{name}] -> {cmd_hex}")
                await asyncio.sleep(0.3)
            except Exception as e:
                print(f"  [{name}] ERROR: {e}")
                if "Not connected" in str(e):
                    print("\n[DISCONNECTED]")
                    return

        print()
        print("Handshake sent. Waiting 2 seconds...")
        await asyncio.sleep(2.0)

        if not client.is_connected:
            print("[DISCONNECTED] after handshake")
            return

        print()
        print("[2] Sending control commands...")
        print("-" * 70)
        print()
        print("WATCH THE LIGHT NOW!")
        print()

        for name, cmd_hex in CONTROL_COMMANDS:
            if not client.is_connected:
                print("[DISCONNECTED]")
                return

            cmd = bytes.fromhex(cmd_hex)
            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                print(f"  [{name}] -> {cmd_hex}")
                print(f"     Wait 3s and check light...")
                await asyncio.sleep(3.0)
            except Exception as e:
                print(f"  [{name}] ERROR: {e}")
                if "Not connected" in str(e):
                    break

        print()
        print("=" * 70)
        print("TEST COMPLETE")
        print("=" * 70)
        print()
        print("Did the light change at any point?")
        print("If yes, which command caused it?")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
