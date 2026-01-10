"""
Try standard Bluetooth Mesh provisioning on reset device.
Uses proper mesh provisioning PDUs.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

responses = []
response_event = asyncio.Event()

def notification_handler(sender, data):
    global responses
    hex_data = data.hex()
    print(f"  ← {hex_data}")
    responses.append(hex_data)
    response_event.set()

async def send_and_wait(client, cmd_hex, timeout=3.0):
    global responses, response_event
    responses.clear()
    response_event.clear()
    
    cmd = bytes.fromhex(cmd_hex)
    print(f"  → {cmd_hex}")
    await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
    
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        return responses[-1] if responses else None
    except asyncio.TimeoutError:
        print(f"     (no response)")
        return None

async def main():
    print(f"Standard Bluetooth Mesh Provisioning on {TARGET_MAC}\n")
    
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print(f"✗ Not found")
        return
    
    async with BleakClient(device, timeout=15.0) as client:
        print(f"✓ Connected (MTU: {client.mtu_size})\n")
        
        await client.start_notify(MESH_PROV_OUT, notification_handler)
        await asyncio.sleep(1.0)
        
        print("Trying standard mesh provisioning PDUs:\n")
        
        # Mesh Provisioning Invite (0x00)
        print("1. Invite (0x00 + attention duration 0s)")
        resp = await send_and_wait(client, "0000")
        
        if resp:
            print("\n✓ DEVICE RESPONDED! Continuing...\n")
            
            # Should get Capabilities back
            print("2. Send Start Provisioning (0x02)")
            resp = await send_and_wait(client, "02")
            
        else:
            # Try Telink-style provisioning
            print("\n\nTrying Telink provisioning style:\n")
            
            print("1. Telink Pair Request")
            resp = await send_and_wait(client, "0c")
            
            if resp:
                print("\n✓ RESPONSE! Continuing Telink flow...\n")
            else:
                print("\n\nTrying raw commands:\n")
                
                # Try simple commands
                for cmd in ["00", "01", "02", "03", "04", "05", "ff"]:
                    print(f"\nSingle byte: 0x{cmd}")
                    resp = await send_and_wait(client, cmd, timeout=2.0)
                    if resp:
                        print(f"  ✓ GOT RESPONSE TO 0x{cmd}!")
                        break
        
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    asyncio.run(main())
