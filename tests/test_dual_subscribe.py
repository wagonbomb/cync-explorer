"""
Subscribe to BOTH Provisioning Out AND Proxy Out
The HCI log shows notifications on handle 0x0022 (34) which is Provisioning Out!
"""
import asyncio
from bleak import BleakClient

TARGET = "34:13:43:46:CA:84"

# All mesh characteristics
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"   # Handle 33
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"  # Handle 35 (notifications!)
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"  # Handle 39
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb" # Handle 41

prov_notifications = []
proxy_notifications = []

def prov_handler(sender, data):
    hex_data = data.hex()
    prov_notifications.append(hex_data)
    print(f"  PROV << {hex_data}")

def proxy_handler(sender, data):
    hex_data = data.hex()
    proxy_notifications.append(hex_data)
    print(f"  PROXY << {hex_data}")

async def main():
    print("="*60)
    print("DUAL SUBSCRIPTION TEST")
    print("Subscribing to BOTH Provisioning Out AND Proxy Out")
    print("="*60)
    print()
    
    async with BleakClient(TARGET, timeout=12.0) as client:
        print("✓ Connected\n")
        
        # Subscribe to BOTH notification characteristics
        print("Subscribing to Mesh Provisioning Out...")
        await client.start_notify(MESH_PROV_OUT, prov_handler)
        print("✓\n")
        
        print("Subscribing to Mesh Proxy Out...")
        await client.start_notify(MESH_PROXY_OUT, proxy_handler)
        print("✓\n")
        
        await asyncio.sleep(0.5)
        
        # Send handshake to Provisioning In
        print("Sending handshake commands to Provisioning In:")
        print("-"*60)
        
        commands = [
            ("START", "000501"),
            ("KEY", "000001040000"),
        ]
        
        for name, cmd in commands:
            print(f"{name:10} >> {cmd}")
            await client.write_gatt_char(MESH_PROV_IN, bytes.fromhex(cmd), response=False)
            await asyncio.sleep(1.0)
        
        print("\nWaiting for responses...")
        await asyncio.sleep(2)
        
        print("\n" + "="*60)
        print("RESULTS")
        print("="*60)
        print(f"Provisioning Out notifications: {len(prov_notifications)}")
        print(f"Proxy Out notifications: {len(proxy_notifications)}")
        
        if len(prov_notifications) > 0:
            print("\n✓ GOT PROVISIONING RESPONSES!")
            for notif in prov_notifications:
                print(f"  {notif}")
        
        try:
            await client.stop_notify(MESH_PROV_OUT)
            await client.stop_notify(MESH_PROXY_OUT)
        except:
            pass

if __name__ == "__main__":
    asyncio.run(main())
