"""
Provision unprovisioned mesh device (name = None after reset).
Try Telink's specific provisioning sequence.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"
TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"

responses = []

def notification_handler(sender, data):
    hex_data = data.hex()
    print(f"  ← {hex_data}")
    responses.append(hex_data)

async def send_cmd(client, uuid, cmd_hex, delay=0.5):
    global responses
    responses.clear()
    cmd = bytes.fromhex(cmd_hex)
    print(f"  → {cmd_hex}")
    await client.write_gatt_char(uuid, cmd, response=False)
    await asyncio.sleep(delay)
    return responses.copy()

async def main():
    print(f"Provisioning fresh device {TARGET_MAC}\n")
    
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print("✗ Not found")
        return
    
    print(f"Device name: {device.name} (None = unprovisioned)\n")
    
    async with BleakClient(device, timeout=15.0) as client:
        print(f"✓ Connected (MTU: {client.mtu_size})\n")
        
        # Subscribe to all notify characteristics
        await client.start_notify(MESH_PROV_OUT, notification_handler)
        await client.start_notify(MESH_PROXY_OUT, notification_handler)
        await asyncio.sleep(1.0)
        
        print("="*60)
        print("TELINK PROVISIONING SEQUENCE")
        print("="*60 + "\n")
        
        # Try Telink pairing command on Command characteristic
        print("1. Telink Pair ON (7E 07 04 10 00 01 01 00 69)")
        resps = await send_cmd(client, TELINK_CMD, "7e0704100001010069", 2.0)
        
        if resps:
            print(f"\n✓ GOT RESPONSE! Device is responding via Telink!")
            
            # Try OFF
            print("\n2. Telink Pair OFF")
            await send_cmd(client, TELINK_CMD, "7e0704100001000068", 2.0)
            
            # Try ON again
            print("\n3. Telink Pair ON again")
            await send_cmd(client, TELINK_CMD, "7e0704100001010069", 2.0)
            
        else:
            print("\n\nTrying Mesh Provisioning path:\n")
            
            # Standard mesh provisioning invite
            print("1. Mesh Invite (attention 5s)")
            resps = await send_cmd(client, MESH_PROV_IN, "0005", 2.0)
            
            if resps:
                print("\n✓ DEVICE SENT CAPABILITIES!")
                # Parse capabilities if we got them
                if resps[0].startswith("01"):
                    print(f"   Capabilities: {resps[0]}")
                    
                    # Send provisioning start
                    print("\n2. Send Provisioning Start")
                    # Algorithm=0, Public Key=0, Auth Method=0, Auth Action=0, Auth Size=0
                    await send_cmd(client, MESH_PROV_IN, "020000000000", 2.0)
                    
                    # Send public key (dummy for now)
                    print("\n3. Send Public Key (64 bytes)")
                    pubkey = "03" + ("00" * 64)
                    await send_cmd(client, MESH_PROV_IN, pubkey, 2.0)
                    
            else:
                print("\n\nNo response to standard provisioning either.")
                print("Trying simple ON/OFF commands:\n")
                
                # Try simple commands
                for char_name, char_uuid, cmd_name, cmd_hex in [
                    ("Telink CMD", TELINK_CMD, "Telink ON simple", "01"),
                    ("Telink CMD", TELINK_CMD, "Telink OFF simple", "00"),
                    ("Mesh Proxy", MESH_PROXY_IN, "Proxy ON", "01"),
                    ("Mesh Proxy", MESH_PROXY_IN, "Proxy OFF", "00"),
                ]:
                    print(f"{cmd_name} on {char_name}")
                    resps = await send_cmd(client, char_uuid, cmd_hex, 1.0)
                    if resps:
                        print(f"  ✓ RESPONSE!")
        
        print("\n" + "="*60)
        print("CHECK IF LIGHT CHANGED PHYSICALLY")
        print("="*60)
        
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    asyncio.run(main())
