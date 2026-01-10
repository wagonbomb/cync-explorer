
import asyncio
from bleak import BleakScanner, BleakClient

# MAC from user logs
TARGET_MAC = "34:13:43:46:CA:84"

async def map_handles():
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=20.0)
    if not device:
        print(f"Device {TARGET_MAC} not found.")
        return

    print(f"Connecting to {device.name} ({device.address})...")
    async with BleakClient(device) as client:
        print("Connected. Listing Services and Characteristics...")
        
        for service in client.services:
            print(f"\n[Service] {service.uuid} ({service.description})")
            for char in service.characteristics:
                print(f"  [Char] {char.uuid} (Handle: {char.handle}) | Props: {char.properties}")
                for desc in char.descriptors:
                    print(f"    [Desc] {desc.uuid} (Handle: {desc.handle})")

if __name__ == "__main__":
    asyncio.run(map_handles())
