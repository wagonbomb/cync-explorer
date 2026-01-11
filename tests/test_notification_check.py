#!/usr/bin/env python3
"""Quick test: Check if device sends initial notification on connection"""
import asyncio
from bleak import BleakClient

TARGET_MAC = "34:13:43:46:CA:84"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

notifications = []

def notification_handler(sender, data):
    print(f"[NOTIFY] {sender.uuid}: {data.hex()}")
    notifications.append((sender.uuid, data))

async def main():
    print("Connecting to device...")
    client = BleakClient(TARGET_MAC, timeout=20.0)
    await client.connect()
    print(f"[OK] Connected")

    # Subscribe
    print("Subscribing to notifications...")
    for service in client.services:
        for char in service.characteristics:
            if "notify" in char.properties:
                try:
                    await client.start_notify(char, notification_handler)
                    print(f"  [OK] {char.uuid}")
                except Exception as e:
                    print(f"  [FAIL] {char.uuid}: {e}")

    # Wait for notifications
    print("\nWaiting 3 seconds for notifications...")
    await asyncio.sleep(3.0)

    print(f"\n[RESULT] Received {len(notifications)} notifications")

    if notifications:
        print("\nNotification details:")
        for uuid, data in notifications:
            print(f"  UUID: {uuid}")
            print(f"  Data: {data.hex()}")
            print(f"  Length: {len(data)} bytes")
    else:
        print("\n[WARN] No notifications received - device is silent")

    await client.disconnect()
    return len(notifications) > 0

if __name__ == "__main__":
    got_notification = asyncio.run(main())
    exit(0 if got_notification else 1)
