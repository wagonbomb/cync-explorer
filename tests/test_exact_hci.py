"""
Test with EXACT HCI commands (with padding)
"""
import asyncio
from bleak import BleakClient

TARGET = "34:13:43:46:CA:84"
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

notifications = []

def handler(sender, data):
    hex_data = data.hex()
    notifications.append(hex_data)
    print(f"  << {hex_data}")

async def main():
    print("="*60)
    print("TESTING EXACT HCI COMMANDS (WITH PADDING)")
    print("="*60)
    print()
    
    async with BleakClient(TARGET, timeout=12.0) as client:
        print("Connected!\n")
        
        await client.start_notify(MESH_PROXY_OUT, handler)
        await asyncio.sleep(0.3)
        
        # EXACT sequence from HCI log
        commands = [
            ("START", "000501000000000000000000"),
            ("KEY", "00000100000000000000040000"),
            ("SYNC-1", "3100"),
            ("SYNC-2", "3101"),
            ("SYNC-3", "3102"),
            ("SYNC-4", "3103"),
            ("SYNC-5", "3104"),
            ("CMD-1", "00000100000000000000160000"),
            ("CMD-2", "00000100000000000000010002"),
            ("FINALIZE", "320119000000"),
            ("CONTROL-1", "b0c0"),
            ("CONTROL-2", "b0c0000235058813a01302962dfffffffffffff1"),
        ]
        
        print("Sending EXACT HCI sequence:")
        print("-"*60)
        
        for name, cmd in commands:
            print(f"{name:12} >> {cmd}")
            await client.write_gatt_char(MESH_PROV_IN, bytes.fromhex(cmd), response=False)
            await asyncio.sleep(1.0)  # Wait longer for responses
            if len(notifications) > 1:
                print(f"             !! Got response!")
        
        print("\nWaiting 3 more seconds for any delayed responses...")
        await asyncio.sleep(3)
        
        print()
        print("-"*60)
        print(f"Total notifications: {len(notifications)}")
        print()
        print("Did the light change?")
        
        try:
            await client.stop_notify(MESH_PROXY_OUT)
        except:
            pass

if __name__ == "__main__":
    asyncio.run(main())
