"""
Attempt to reset/unpair device via BLE commands.
Tries various reset patterns on all writable characteristics.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

# UUIDs
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"

# Common reset command patterns
RESET_COMMANDS = [
    # Factory reset patterns
    ("FACTORY_RESET_FF", "ff"),
    ("FACTORY_RESET_FFFF", "ffff"),
    ("FACTORY_RESET_FFFFFFFF", "ffffffff"),
    
    # Unpair/clear patterns
    ("UNPAIR_FE", "fe"),
    ("CLEAR_00", "00"),
    ("CLEAR_0000", "0000"),
    
    # Reset codes
    ("RESET_RST", "52535400"),  # "RST\0"
    ("RESET_AA55", "aa55"),
    ("RESET_5AA5", "5aa5"),
    
    # Mesh reset patterns
    ("MESH_RESET_01", "0005ff000000000000000000"),
    ("MESH_RESET_02", "00000f000000000000000000"),
    ("MESH_RESET_03", "ffff00000000000000000000"),
    
    # Provisioning reset
    ("PROV_RESET_01", "00ff01000000000000000000"),
    ("PROV_RESET_02", "00000100000000000000ff00"),
    
    # Telink reset patterns
    ("TELINK_RESET_01", "7eff0000000000"),
    ("TELINK_RESET_02", "7e0f00000000"),
    ("TELINK_FACTORY", "7e0704100001ff00ff"),
]

responses = []

def notification_handler(sender, data):
    """Capture responses"""
    hex_data = data.hex()
    print(f"    ← RESPONSE: {hex_data}")
    responses.append(hex_data)

async def try_reset_command(client, uuid_name, uuid, cmd_name, cmd_hex):
    """Try a single reset command"""
    global responses
    responses.clear()
    
    try:
        command = bytes.fromhex(cmd_hex)
        print(f"  {cmd_name:20s} on {uuid_name:20s} -> ", end="")
        await client.write_gatt_char(uuid, command, response=False)
        await asyncio.sleep(0.5)
        
        if responses:
            print(f"✓ Got response!")
            return True
        else:
            print("✗ No response")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

async def main():
    print(f"Attempting BLE reset on {TARGET_MAC}\n")
    print("WARNING: This may unbind the device from the Cync app!")
    print("="*60)
    
    # Find device
    print("\nScanning...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print(f"✗ Device not found")
        return
    print(f"✓ Found device")
    
    # Connect
    async with BleakClient(device, timeout=15.0) as client:
        print(f"✓ Connected (MTU: {client.mtu_size})\n")
        
        # Subscribe to all notification characteristics
        print("Subscribing to notifications...")
        try:
            await client.start_notify("00002adc-0000-1000-8000-00805f9b34fb", notification_handler)
            await client.start_notify("00002ade-0000-1000-8000-00805f9b34fb", notification_handler)
            await client.start_notify("00010203-0405-0607-0809-0a0b0c0d1911", notification_handler)
        except Exception as e:
            print(f"  Some subscriptions failed (expected): {e}")
        
        await asyncio.sleep(1.0)
        print("✓ Subscribed\n")
        
        print("="*60)
        print("TRYING RESET COMMANDS")
        print("="*60)
        
        # Try each reset command on each writable characteristic
        writable_chars = [
            ("MESH_PROV_IN", MESH_PROV_IN),
            ("MESH_PROXY_IN", MESH_PROXY_IN),
            ("TELINK_CMD", TELINK_CMD),
        ]
        
        success_count = 0
        
        for cmd_name, cmd_hex in RESET_COMMANDS:
            print(f"\n{cmd_name}:")
            for uuid_name, uuid in writable_chars:
                if await try_reset_command(client, uuid_name, uuid, cmd_name, cmd_hex):
                    success_count += 1
                    print(f"\n⚠️  POTENTIAL RESET COMMAND FOUND!")
                    print(f"    Characteristic: {uuid_name}")
                    print(f"    Command: {cmd_hex}")
                    print(f"    Waiting to see if device resets...")
                    await asyncio.sleep(3.0)
        
        print("\n" + "="*60)
        print("RESET ATTEMPT SUMMARY")
        print("="*60)
        print(f"Commands tested: {len(RESET_COMMANDS) * len(writable_chars)}")
        print(f"Responses received: {success_count}")
        
        if success_count == 0:
            print("\n✗ No reset commands found via BLE")
            print("   Factory reset requires physical power cycling:")
            print("   1. Turn light ON")
            print("   2. OFF 2s, ON 2s, repeat 5 times")
            print("   3. Light should flash on 5th cycle")
        
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    asyncio.run(main())
