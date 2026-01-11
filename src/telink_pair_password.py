"""
Telink Mesh Pairing with Default Password
Device is in "telink_mesh1" mode - need to use Telink's pairing protocol
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"
TELINK_STATUS = "00010203-0405-0607-0809-0a0b0c0d1911"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

# Telink default mesh password (16 bytes)
# Common default: "123" or "telink_mesh1" or all zeros
DEFAULT_PASSWORDS = [
    bytes.fromhex("313233" + "00" * 13),  # "123" + padding
    bytes.fromhex("74656c696e6b5f6d657368" + "00" * 5),  # "telink_mesh" + padding  
    bytes.fromhex("00" * 16),  # All zeros
    bytes.fromhex("ff" * 16),  # All FF
]

responses = []

def notification_handler(sender, data):
    hex_data = data.hex()
    print(f"    RX: {hex_data}")
    responses.append(hex_data)

async def try_pairing(client, password):
    global responses
    responses.clear()
    
    # Telink mesh login packet structure:
    # 0x0C + mesh_name (16 bytes) + password (16 bytes) + checksum
    mesh_name = b"telink_mesh1" + b"\x00" * 4  # Pad to 16 bytes
    
    # Build login packet
    packet = bytearray([0x0c])  # Telink pair command
    packet.extend(mesh_name)
    packet.extend(password)
    
    # Calculate simple checksum (sum of all bytes)
    checksum = sum(packet) & 0xFF
    packet.append(checksum)
    
    print(f"  TX: Login packet: {packet.hex()}")
    
    try:
        await client.write_gatt_char(TELINK_CMD, bytes(packet), response=False)
        await asyncio.sleep(2.0)
        return len(responses) > 0
    except Exception as e:
        print(f"    Error: {e}")
        return False

async def send_simple_on_off(client):
    """Try simple ON/OFF after pairing"""
    print("\n  Trying ON command...")
    await client.write_gatt_char(TELINK_CMD, bytes.fromhex("7e0704100001010069"), response=False)
    await asyncio.sleep(2.0)
    
    print("  Trying OFF command...")
    await client.write_gatt_char(TELINK_CMD, bytes.fromhex("7e0704100001000068"), response=False)
    await asyncio.sleep(2.0)
    
    print("  Trying ON again...")
    await client.write_gatt_char(TELINK_CMD, bytes.fromhex("7e0704100001010069"), response=False)
    await asyncio.sleep(2.0)

async def main():
    print(f"Telink Mesh Pairing on {TARGET_MAC}\n")
    
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print("[X] Not found")
        return
    
    print(f"Device name: {device.name}")
    if device.name != "telink_mesh1":
        print("[WARN] Expected 'telink_mesh1', got something else\n")
    
    async with BleakClient(device, timeout=15.0) as client:
        print(f"\n[OK] Connected (MTU: {client.mtu_size})\n")
        
        # Subscribe to notifications
        try:
            await client.start_notify(TELINK_STATUS, notification_handler)
            print("[OK] Subscribed to Telink Status\n")
        except Exception as e:
            print(f"[WARN] Could not subscribe: {e}\n")
        
        await asyncio.sleep(1.0)
        
        print("="*60)
        print("TRYING DEFAULT PASSWORDS")
        print("="*60)
        
        # Try each password
        for i, password in enumerate(DEFAULT_PASSWORDS, 1):
            print(f"\nPassword {i}: {password.hex()}")
            if await try_pairing(client, password):
                print(f"\n[SUCCESS] PAIRING SUCCESS WITH PASSWORD {i}!")
                print(f"Password was: {password.hex()}\n")
                print("="*60)
                print("TESTING LIGHT CONTROL")
                print("="*60)
                await send_simple_on_off(client)
                break
        else:
            print("\n\n[FAILED] None of the default passwords worked.")
            print("The device may require a custom password or different pairing method.")
        
        print("\n" + "="*60)
        print("DID THE LIGHT CHANGE?")
        print("="*60)
        
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    asyncio.run(main())
