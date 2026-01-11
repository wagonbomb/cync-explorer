#!/usr/bin/env python3
"""
Replay Attack Test - Send captured HCI packets to bulb to identify control commands
This tests the 14 writes to handle 0x0015 that occurred after pairing
"""

import asyncio
from bleak import BleakClient, BleakScanner
import sys

# Target bulb
TARGET_MAC = "34:13:43:46:CA:84"

# Discovered from HCI log - the critical characteristic that receives commands
COMMAND_CHAR_UUID = "00002adb-0000-1000-8000-00805f9b34fb"  # Mesh Prov In (handle 0x0014 in some devices)

# Post-pairing commands from HCI log (writes 31-44 to handle 0x0015)
# These should contain: OFF, ON, OFF, Brightness 50%, ON
CAPTURED_COMMANDS = {
    "cmd_31": bytes.fromhex("71f4005d0d6a71e29e3e134f"),      # Packet 8513 (12 bytes)
    "cmd_32": bytes.fromhex("ed4600fd4e997a2b0f9fa3a3e5"),    # Packet 8529 (13 bytes)
    "cmd_33": bytes.fromhex("7e6100a835e322681373d6be9cf6fc4737478683"),  # Packet 8554 (20 bytes)
    "cmd_34": bytes.fromhex("020000fb62c82c7dbefbf76d4d"),    # Packet 8728 (13 bytes)
    "cmd_35": bytes.fromhex("fc5500445c0441d68b2ee45a"),      # Packet 8917 (12 bytes)
    "cmd_36": bytes.fromhex("8e8a0076587cd75d5fc613a4"),      # Packet 8953 (12 bytes)
    "cmd_37": bytes.fromhex("4d6a00f4fd2dae3c58aae72f"),      # Packet 9833 (12 bytes)
    "cmd_38": bytes.fromhex("dfad00e3b5d71fd46d3dd4fe"),      # Packet 9850 (12 bytes)
    "cmd_39": bytes.fromhex("1f8b0053ac634c49e6c70115"),      # Packet 9874 (12 bytes)
    "cmd_40": bytes.fromhex("201c00c79c5ee37262aae5f4070ff27a0a8f1c94"),  # Packet 9875 (20 bytes)
    "cmd_41": bytes.fromhex("be50002fa9ee72df694dd682"),      # Packet 9972 (12 bytes)
    "cmd_42": bytes.fromhex("fd4b003567d1109fb7a2aec6"),      # Packet 10909 (12 bytes)
    "cmd_43": bytes.fromhex("5f2b00ef343485eaef9ac8e4"),      # Packet 11153 (12 bytes)
    "cmd_44": bytes.fromhex("f5cd001a2fcb0ba6b1de6707"),      # Packet 11481 (12 bytes)
}

async def find_command_characteristic(client):
    """Find the characteristic with handle 0x0015 from HCI log"""
    print("\nEnumerating all characteristics:")

    for service in client.services:
        print(f"\nService: {service.uuid}")
        for char in service.characteristics:
            print(f"  Char: {char.uuid}")
            print(f"    Handle: 0x{char.handle:04x}")
            print(f"    Properties: {char.properties}")

            # Handle 0x0015 from HCI log
            if char.handle == 0x0015:
                print(f"    >>> FOUND TARGET CHARACTERISTIC (0x0015)!")
                return char.uuid

    return None

async def replay_commands():
    """Try replaying captured commands to identify which does what"""
    print(f"Scanning for {TARGET_MAC}...")

    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print(f"[ERROR] Device not found")
        return

    print(f"Connecting to {device.name} ({device.address})...")

    async with BleakClient(device) as client:
        if not client.is_connected:
            print("[ERROR] Failed to connect")
            return

        print("[OK] Connected")

        # Find the command characteristic
        target_uuid = await find_command_characteristic(client)

        if not target_uuid:
            print("\n[ERROR] Could not find handle 0x0015")
            print("Trying known mesh characteristics instead...")
            target_uuid = "00002adb-0000-1000-8000-00805f9b34fb"  # Mesh Prov In

        print(f"\nUsing characteristic: {target_uuid}")
        print("\n" + "="*80)
        print("REPLAY ATTACK TEST")
        print("="*80)
        print("Watch the bulb and note what each command does!")
        print("Expected sequence: OFF, ON, OFF, Brightness 50%, ON")
        print("="*80)

        input("\nPress ENTER to start replay test...")

        for name, data in CAPTURED_COMMANDS.items():
            print(f"\n[{name}] Sending {len(data)} bytes: {data.hex()}")

            try:
                await client.write_gatt_char(target_uuid, data, response=True)
                print("  Sent successfully")

                # Wait for user observation
                await asyncio.sleep(2.0)

                response = input("  What happened? (on/off/dim/bright/nothing): ")
                print(f"  >>> USER: {response}")

            except Exception as e:
                print(f"  [ERROR] {e}")

        print("\n" + "="*80)
        print("Replay test complete!")
        print("="*80)

if __name__ == "__main__":
    try:
        asyncio.run(replay_commands())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
