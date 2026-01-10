"""
COMPREHENSIVE ATTACK: Try ALL approaches to control the light
1. Telink direct commands
2. Mesh with proper subscriptions  
3. Simple raw commands
4. Exact HCI replay

This is the nuclear option - if ANY method works, we'll find it.
"""
import asyncio
from bleak import BleakClient

TARGET = "34:13:43:46:CA:84"

# All characteristics
TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"
TELINK_STATUS = "00010203-0405-0607-0809-0a0b0c0d1911"
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

all_notifications = []

def universal_handler(sender, data):
    hex_data = data.hex()
    all_notifications.append((str(sender), hex_data))
    print(f"    << {hex_data}")

async def attack_1_telink_direct():
    """Attack 1: Direct Telink commands (legacy protocol)"""
    print("\n" + "="*60)
    print("ATTACK 1: TELINK DIRECT COMMANDS")
    print("="*60)
    
    all_notifications.clear()
    
    try:
        async with BleakClient(TARGET, timeout=12.0) as client:
            print("✓ Connected")
            
            # Try to subscribe to Telink Status (might fail on Windows)
            try:
                await client.start_notify(TELINK_STATUS, universal_handler)
                print("✓ Subscribed to Telink Status")
            except Exception as e:
                print(f"✗ Could not subscribe to Telink Status: {e}")
            
            await asyncio.sleep(0.3)
            
            # Try direct Telink commands
            telink_commands = [
                ("Power ON", "7e0704100001010069"),
                ("Power OFF", "7e0704100001000068"),
            ]
            
            print("\nSending Telink commands:")
            for name, cmd in telink_commands:
                print(f"  {name}: {cmd}")
                try:
                    await client.write_gatt_char(TELINK_CMD, bytes.fromhex(cmd), response=False)
                    await asyncio.sleep(1.5)
                    print(f"    → Did light change? Check physically!")
                except Exception as e:
                    print(f"    ERROR: {e}")
            
            try:
                await client.stop_notify(TELINK_STATUS)
            except:
                pass
                
            return len(all_notifications)
    except Exception as e:
        print(f"✗ Attack 1 failed: {e}")
        return 0

async def attack_2_simple_mesh():
    """Attack 2: Simplest possible mesh commands"""
    print("\n" + "="*60)
    print("ATTACK 2: SIMPLE MESH COMMANDS")
    print("="*60)
    
    all_notifications.clear()
    
    try:
        async with BleakClient(TARGET, timeout=12.0) as client:
            print("✓ Connected")
            
            await client.start_notify(MESH_PROXY_OUT, universal_handler)
            await asyncio.sleep(0.3)
            all_notifications.clear()  # Clear initial notification
            
            # Try the absolute simplest commands from HCI
            simple_commands = [
                ("b0c001", "ON attempt 1"),
                ("b0c000", "OFF attempt 1"),
                ("b1c001", "ON attempt 2"),
                ("b1c000", "OFF attempt 2"),
            ]
            
            print("\nTrying simple bXc0 commands:")
            for cmd, desc in simple_commands:
                print(f"  {desc}: {cmd}")
                await client.write_gatt_char(MESH_PROXY_IN, bytes.fromhex(cmd), response=False)
                await asyncio.sleep(1.5)
                print(f"    → Watch the light!")
            
            await client.stop_notify(MESH_PROXY_OUT)
            return len(all_notifications)
    except Exception as e:
        print(f"✗ Attack 2 failed: {e}")
        return 0

async def attack_3_full_handshake():
    """Attack 3: Complete handshake sequence from HCI"""
    print("\n" + "="*60)
    print("ATTACK 3: FULL HANDSHAKE SEQUENCE")
    print("="*60)
    
    all_notifications.clear()
    
    try:
        async with BleakClient(TARGET, timeout=15.0) as client:
            print("✓ Connected")
            
            # Subscribe to both
            await client.start_notify(MESH_PROV_OUT, universal_handler)
            await client.start_notify(MESH_PROXY_OUT, universal_handler)
            await asyncio.sleep(0.3)
            
            # Full sequence from HCI log with padding
            sequence = [
                ("START", MESH_PROV_IN, "000501000000000000000000"),
                ("KEY", MESH_PROV_IN, "00000100000000000000040000"),
                ("SYNC-1", MESH_PROV_IN, "3100"),
                ("SYNC-2", MESH_PROV_IN, "3101"),
                ("SYNC-3", MESH_PROV_IN, "3102"),
                ("SYNC-4", MESH_PROV_IN, "3103"),
                ("SYNC-5", MESH_PROV_IN, "3104"),
                ("FINALIZE", MESH_PROV_IN, "320119000000"),
                ("CONTROL", MESH_PROV_IN, "b0c0"),
            ]
            
            print("\nSending full handshake:")
            for name, uuid, cmd in sequence:
                print(f"  {name}: {cmd}")
                await client.write_gatt_char(uuid, bytes.fromhex(cmd), response=False)
                await asyncio.sleep(0.8)
                
                if len(all_notifications) > 1:
                    print("    ✓ Got response!")
            
            try:
                await client.stop_notify(MESH_PROV_OUT)
                await client.stop_notify(MESH_PROXY_OUT)
            except:
                pass
                
            return len(all_notifications)
    except Exception as e:
        print(f"✗ Attack 3 failed: {e}")
        return 0

async def attack_4_brute_force_write():
    """Attack 4: Write simple ON/OFF to every writable characteristic"""
    print("\n" + "="*60)
    print("ATTACK 4: BRUTE FORCE ALL WRITABLE CHARS")
    print("="*60)
    
    try:
        async with BleakClient(TARGET, timeout=12.0) as client:
            print("✓ Connected")
            
            # Get all writable characteristics
            writable = []
            for service in client.services:
                for char in service.characteristics:
                    if "write" in char.properties or "write-without-response" in char.properties:
                        writable.append(char)
            
            print(f"\nFound {len(writable)} writable characteristics")
            print("Testing simple 0x01/0x00 writes on each:")
            
            for char in writable:
                name = char.uuid[:8]
                print(f"\n  {name}...")
                
                for val in [b'\x01', b'\x00']:
                    try:
                        await client.write_gatt_char(char.uuid, val, response=False)
                        await asyncio.sleep(0.5)
                        print(f"    {val.hex()} → Check light!")
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        break
            
            return True
    except Exception as e:
        print(f"✗ Attack 4 failed: {e}")
        return False

async def main():
    print("\n" + "="*70)
    print(" COMPREHENSIVE ATTACK SUITE")
    print(" Testing ALL known methods to control the light")
    print("="*70)
    print("\n⚠️  WATCH THE PHYSICAL LIGHT BULB DURING ALL TESTS! ⚠️\n")
    
    input("Press Enter to start attack sequence...")
    
    results = {
        "Telink Direct": await attack_1_telink_direct(),
        "Simple Mesh": await attack_2_simple_mesh(),
        "Full Handshake": await attack_3_full_handshake(),
        "Brute Force": await attack_4_brute_force_write(),
    }
    
    print("\n" + "="*70)
    print(" ATTACK RESULTS")
    print("="*70)
    
    for attack, result in results.items():
        status = "✓" if result else "✗"
        print(f"{status} {attack}: {result} responses" if isinstance(result, int) else f"{status} {attack}: Completed")
    
    print("\n" + "="*70)
    print(" NEXT STEPS")
    print("="*70)
    print("1. Did the light change during ANY test?")
    print("2. If YES → Which test made it work?")
    print("3. If NO → We may need to:")
    print("   - Unpair the device from the official app")
    print("   - Factory reset the bulb")
    print("   - Sniff the actual BLE traffic during app control")
    print("="*70)

if __name__ == "__main__":
    asyncio.run(main())
