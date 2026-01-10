"""
Alternative Telink pairing - try NO password and direct commands.
Device in telink_mesh1 mode may accept commands without formal pairing.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

responses = []

def handler(sender, data):
    print(f"  ← {data.hex()}")
    responses.append(data.hex())

async def main():
    print("Testing unpaired control on telink_mesh1\n")
    
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print("✗ Not found")
        return
    
    print(f"Device: {device.name}\n")
    
    async with BleakClient(device, timeout=15.0) as client:
        print(f"✓ Connected\n")
        
        await client.start_notify(MESH_PROV_OUT, handler)
        await client.start_notify(MESH_PROXY_OUT, handler)
        await asyncio.sleep(1.0)
        
        # Try every possible single-byte command
        print("Brute forcing single-byte commands on Telink CMD:\n")
        
        for i in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0C, 0x10, 0x11, 0xFF]:
            responses.clear()
            print(f"→ {i:02x}", end=" ")
            await client.write_gatt_char(TELINK_CMD, bytes([i]), response=False)
            await asyncio.sleep(1.5)
            
            if responses:
                print(f"✓ RESPONSE!")
                print("="*60)
                print(f"COMMAND 0x{i:02X} GOT A RESPONSE - TRY THIS!")
                print("="*60)
                break
            else:
                print("(no response)")
        
        print("\n\nDid the light change at any point?")
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    asyncio.run(main())
