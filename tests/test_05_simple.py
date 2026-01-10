"""
BASELINE TEST 5: Simple Command Baseline (Simplified)
Just the essentials - no long waits

Target Device: 34:13:43:46:CA:84
"""

import asyncio
from bleak import BleakClient
from datetime import datetime

TARGET_DEVICE = "34:13:43:46:CA:84"

MESH_PROVISIONING_IN_UUID = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN_UUID = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT_UUID = "00002ade-0000-1000-8000-00805f9b34fb"

notifications = []

def notification_handler(sender, data):
    hex_data = data.hex()
    notifications.append(data)
    print(f"  RX: {hex_data} ({len(data)} bytes)")
    if len(data) >= 4 and data[0] == 0x04 and data[1] == 0x00 and data[2] == 0x00:
        print(f"    → Session ID: 0x{data[3]:02x}")


async def main():
    print("="*60)
    print("BASELINE TEST 5: COMMAND BASELINE (SIMPLIFIED)")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}\n")
    
    notifications.clear()
    
    print("Connecting...")
    async with BleakClient(TARGET_DEVICE, timeout=10.0) as client:
        print("✓ Connected\n")
        
        # Subscribe
        print("Subscribing to Mesh Proxy Out...")
        await client.start_notify(MESH_PROXY_OUT_UUID, notification_handler)
        print("✓ Subscribed\n")
        await asyncio.sleep(0.3)
        
        # Test 1: Write to Provisioning
        print("TEST 1: Write to Mesh Provisioning In")
        print(f"  TX: 000501")
        await client.write_gatt_char(MESH_PROVISIONING_IN_UUID, bytes.fromhex("000501"), response=False)
        await asyncio.sleep(0.8)
        print()
        
        # Test 2: Handshake
        print("TEST 2: Handshake Sequence")
        print("  TX: 000501 (START)")
        await client.write_gatt_char(MESH_PROVISIONING_IN_UUID, bytes.fromhex("000501"), response=False)
        await asyncio.sleep(0.5)
        
        print("  TX: 000001040000 (KEY)")
        await client.write_gatt_char(MESH_PROVISIONING_IN_UUID, bytes.fromhex("000001040000"), response=False)
        await asyncio.sleep(0.8)
        print()
        
        # Test 3: Write to Proxy
        print("TEST 3: Write to Mesh Proxy In")
        print("  TX: 3100")
        await client.write_gatt_char(MESH_PROXY_IN_UUID, bytes.fromhex("3100"), response=False)
        await asyncio.sleep(0.8)
        print()
        
        # Cleanup
        try:
            await client.stop_notify(MESH_PROXY_OUT_UUID)
        except:
            pass  # May already be disconnected
        
    print("="*60)
    print(f"SUMMARY: Received {len(notifications)} total notifications")
    print("="*60)
    
    if len(notifications) > 0:
        print("✓ Communication working!")
    else:
        print("⚠ No notifications received")

if __name__ == "__main__":
    asyncio.run(main())
