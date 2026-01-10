"""
Focused Discovery: Pairing + Command Testing
Target: 34:13:43:46:CA:84

Simplified approach focusing on what's most likely to work:
1. Connect and read device info
2. Test commands with proper error handling
3. Try brute force control commands
"""

import asyncio
from bleak import BleakClient
from datetime import datetime

TARGET = "34:13:43:46:CA:84"

MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

notifications = []

def notif_handler(sender, data):
    hex_data = data.hex()
    notifications.append(hex_data)
    print(f"    << {hex_data}")

async def test_pairing_and_read():
    """Connect, pair if needed, and read device info"""
    print("="*60)
    print("STEP 1: PAIRING & DEVICE INFO")
    print("="*60)
    
    async with BleakClient(TARGET, timeout=12.0) as client:
        print("✓ Connected\n")
        
        # Read device name
        device_name_uuid = "00002a00-0000-1000-8000-00805f9b34fb"
        try:
            name_bytes = await client.read_gatt_char(device_name_uuid)
            name = name_bytes.decode('utf-8', errors='ignore')
            print(f"Device Name: {name}")
            print(f"  Hex: {name_bytes.hex()}\n")
        except Exception as e:
            print(f"Could not read name: {e}\n")
        
        print("✓ Device accessible (pairing successful if needed)\n")

async def test_control_commands():
    """Try actual ON/OFF control commands"""
    print("="*60)
    print("STEP 2: CONTROL COMMAND TESTING")
    print("="*60)
    
    notifications.clear()
    
    async with BleakClient(TARGET, timeout=12.0) as client:
        print("✓ Connected\n")
        
        # Subscribe
        print("Subscribing...")
        await client.start_notify(MESH_PROXY_OUT, notif_handler)
        await asyncio.sleep(0.5)
        print()
        
        # Test various command structures
        test_commands = [
            # From HCI logs / context dump
            ("Mesh Prov: START", MESH_PROV_IN, "000501"),
            ("Mesh Prov: KEY", MESH_PROV_IN, "000001040000"),
            
            # Mesh Proxy commands
            ("Mesh Proxy: 3100", MESH_PROXY_IN, "3100"),
            ("Mesh Proxy: 3101", MESH_PROXY_IN, "3101"),
            
            # bX prefix attempts (b0-b5 most likely based on session IDs 0-5)
            ("Control: b0c001 (ON)", MESH_PROXY_IN, "b0c001"),
            ("Control: b0c000 (OFF)", MESH_PROXY_IN, "b0c000"),
            ("Control: b1c001 (ON)", MESH_PROXY_IN, "b1c001"),
            ("Control: b1c000 (OFF)", MESH_PROXY_IN, "b1c000"),
            
            # Simple payloads
            ("Simple: 01", MESH_PROXY_IN, "01"),
            ("Simple: 00", MESH_PROXY_IN, "00"),
        ]
        
        for name, uuid, cmd_hex in test_commands:
            print(f"{name}")
            print(f"  >> {cmd_hex}")
            try:
                await client.write_gatt_char(uuid, bytes.fromhex(cmd_hex), response=False)
                await asyncio.sleep(0.7)
            except Exception as e:
                print(f"  ERROR: {e}")
            print()
        
        try:
            await client.stop_notify(MESH_PROXY_OUT)
        except:
            pass
    
    print(f"Total notifications received: {len(notifications)}")

async def test_brute_force_session_ids():
    """Brute force bXc0 commands with session IDs 0-15"""
    print("="*60)
    print("STEP 3: BRUTE FORCE SESSION ID PREFIXES")
    print("="*60)
    print("Testing b0-bf with ON (01) payload\n")
    
    notifications.clear()
    
    async with BleakClient(TARGET, timeout=12.0) as client:
        print("✓ Connected\n")
        
        await client.start_notify(MESH_PROXY_OUT, notif_handler)
        await asyncio.sleep(0.3)
        
        # Clear initial notification
        notifications.clear()
        
        for session_id in range(16):
            # Calculate prefix like in context dump: (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
            prefix = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
            
            cmd_on = bytes([prefix, 0xc0, 0x01])
            print(f"Session {session_id}: {cmd_on.hex()} (ON)", end="")
            
            notif_before = len(notifications)
            await client.write_gatt_char(MESH_PROXY_IN, cmd_on, response=False)
            await asyncio.sleep(0.6)
            
            if len(notifications) > notif_before:
                print(" ← GOT RESPONSE!")
            else:
                print()
        
        try:
            await client.stop_notify(MESH_PROXY_OUT)
        except:
            pass

async def test_observe_light_physically():
    """Send commands and wait for user to observe if light changes"""
    print("="*60)
    print("STEP 4: MANUAL OBSERVATION TEST")
    print("="*60)
    print("Watch the physical light bulb!\n")
    
    async with BleakClient(TARGET, timeout=12.0) as client:
        print("✓ Connected\n")
        
        await client.start_notify(MESH_PROXY_OUT, notif_handler)
        await asyncio.sleep(0.5)
        
        # Send full handshake + control sequence
        sequence = [
            ("START", MESH_PROV_IN, "000501", 0.5),
            ("KEY", MESH_PROV_IN, "000001040000", 0.5),
            ("SYNC-1", MESH_PROXY_IN, "3100", 0.5),
            ("SYNC-2", MESH_PROXY_IN, "3101", 0.5),
            ("SYNC-3", MESH_PROXY_IN, "3102", 0.5),
            ("SYNC-4", MESH_PROXY_IN, "3103", 0.5),
            ("SYNC-5", MESH_PROXY_IN, "3104", 0.5),
            ("FINALIZE", MESH_PROXY_IN, "320119000000", 1.0),
            ("CONTROL-ON", MESH_PROXY_IN, "b0c001", 2.0),
            ("CONTROL-OFF", MESH_PROXY_IN, "b0c000", 2.0),
            ("CONTROL-ON", MESH_PROXY_IN, "b0c001", 2.0),
        ]
        
        print("Sending full command sequence...")
        print("WATCH THE LIGHT!\n")
        
        for name, uuid, cmd, delay in sequence:
            print(f"  >> {name}: {cmd}")
            await client.write_gatt_char(uuid, bytes.fromhex(cmd), response=False)
            await asyncio.sleep(delay)
        
        print("\nDid the light turn on/off? (Check physically)")
        
        try:
            await client.stop_notify(MESH_PROXY_OUT)
        except:
            pass

async def main():
    print("\n" + "="*60)
    print("FOCUSED DISCOVERY: PAIRING + COMMAND TESTING")
    print(f"Target: {TARGET}")
    print("="*60)
    print(f"Started: {datetime.now().strftime('%H:%M:%S')}\n")
    
    try:
        await test_pairing_and_read()
        await asyncio.sleep(1)
        
        await test_control_commands()
        await asyncio.sleep(1)
        
        await test_brute_force_session_ids()
        await asyncio.sleep(1)
        
        await test_observe_light_physically()
        
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    except Exception as e:
        print(f"\n\nError: {e}")
    
    print("\n" + "="*60)
    print("DISCOVERY COMPLETE")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
