"""
GE Cync GATT Explorer
Connects to a BLE device and enumerates all GATT services, characteristics, and descriptors.
This helps us understand what the Cync light exposes for control.
"""

import asyncio
import sys
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from datetime import datetime


# Known GATT UUIDs for reference
KNOWN_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute", 
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "0000fee9-0000-1000-8000-00805f9b34fb": "Possible Light Control (Telink)",
}

KNOWN_CHARACTERISTICS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "Peripheral Preferred Connection Parameters",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
}


def format_uuid(uuid: str) -> str:
    """Format UUID with known name if available."""
    uuid_lower = str(uuid).lower()
    if uuid_lower in KNOWN_SERVICES:
        return f"{uuid} ({KNOWN_SERVICES[uuid_lower]})"
    if uuid_lower in KNOWN_CHARACTERISTICS:
        return f"{uuid} ({KNOWN_CHARACTERISTICS[uuid_lower]})"
    return str(uuid)


def format_properties(properties: list) -> str:
    """Format characteristic properties into a readable string."""
    props = []
    for prop in properties:
        props.append(prop)
    return ", ".join(props)


async def explore_device(address: str):
    """
    Connect to a BLE device and enumerate all its GATT services and characteristics.
    
    Args:
        address: The MAC address of the device to connect to
    """
    # Normalize MAC address format
    addr_normalized = address.replace(":", "").replace("-", "").upper()
    # Format with colons for bleak
    addr_formatted = ":".join(addr_normalized[i:i+2] for i in range(0, 12, 2))
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Attempting to connect to: {addr_formatted}")
    print("=" * 80)
    
    # First, try to find the device to ensure it's discoverable
    print("Scanning for device...")
    device = await BleakScanner.find_device_by_address(addr_formatted, timeout=15.0)
    
    if not device:
        # Try with different MAC format (Windows uses dashes)
        addr_dashed = "-".join(addr_normalized[i:i+2] for i in range(0, 12, 2))
        print(f"Trying alternative format: {addr_dashed}")
        device = await BleakScanner.find_device_by_address(addr_dashed, timeout=10.0)
    
    if not device:
        print(f"❌ Could not find device {address}")
        print("Make sure:")
        print("  1. The device is powered on")
        print("  2. You're close enough to the device")
        print("  3. The MAC address is correct")
        print("  4. Bluetooth is enabled on your PC")
        return None
    
    print(f"✅ Found device: {device.name or '(Unknown name)'}")
    print(f"   Address: {device.address}")
    print()
    
    results = {
        "device": {
            "address": device.address,
            "name": device.name
        },
        "services": []
    }
    
    try:
        async with BleakClient(device, timeout=30.0) as client:
            print(f"✅ Connected successfully!")
            print()
            
            # Get all services
            services = client.services
            
            print("=" * 80)
            print("GATT SERVICES AND CHARACTERISTICS")
            print("=" * 80)
            
            for service in services:
                service_info = {
                    "uuid": str(service.uuid),
                    "handle": service.handle,
                    "characteristics": []
                }
                
                print(f"\n📦 SERVICE: {format_uuid(service.uuid)}")
                print(f"   Handle: {service.handle}")
                
                for char in service.characteristics:
                    char_info = {
                        "uuid": str(char.uuid),
                        "handle": char.handle,
                        "properties": char.properties,
                        "value": None,
                        "descriptors": []
                    }
                    
                    print(f"\n   📝 CHARACTERISTIC: {format_uuid(char.uuid)}")
                    print(f"      Handle: {char.handle}")
                    print(f"      Properties: {format_properties(char.properties)}")
                    
                    # Try to read the value if readable
                    if "read" in char.properties:
                        try:
                            value = await client.read_gatt_char(char.uuid)
                            char_info["value"] = value.hex()
                            
                            # Try to decode as string
                            try:
                                value_str = value.decode('utf-8')
                                print(f"      Value (string): '{value_str}'")
                            except:
                                pass
                            print(f"      Value (hex): {value.hex()}")
                            print(f"      Value (bytes): {list(value)}")
                        except BleakError as e:
                            print(f"      Value: <read error: {e}>")
                    
                    # List descriptors
                    for desc in char.descriptors:
                        desc_info = {
                            "uuid": str(desc.uuid),
                            "handle": desc.handle
                        }
                        print(f"      📎 Descriptor: {desc.uuid} (Handle: {desc.handle})")
                        
                        # Try to read descriptor value
                        try:
                            desc_value = await client.read_gatt_descriptor(desc.handle)
                            desc_info["value"] = desc_value.hex()
                            print(f"         Value: {desc_value.hex()}")
                        except:
                            pass
                        
                        char_info["descriptors"].append(desc_info)
                    
                    service_info["characteristics"].append(char_info)
                
                results["services"].append(service_info)
            
            print("\n" + "=" * 80)
            print("SUMMARY")
            print("=" * 80)
            print(f"Total services: {len(results['services'])}")
            total_chars = sum(len(s['characteristics']) for s in results['services'])
            print(f"Total characteristics: {total_chars}")
            
            # Identify potential control characteristics
            print("\n🎮 POTENTIAL CONTROL CHARACTERISTICS:")
            for service in results['services']:
                for char in service['characteristics']:
                    if "write" in char['properties'] or "write-without-response" in char['properties']:
                        print(f"   - {char['uuid']} (Properties: {', '.join(char['properties'])})")
            
            return results
            
    except BleakError as e:
        print(f"❌ Connection error: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return None


async def main():
    if len(sys.argv) < 2:
        print("Usage: python gatt_explorer.py <MAC_ADDRESS>")
        print("Example: python gatt_explorer.py 34:13:43:46:CA:85")
        print("         python gatt_explorer.py 34134346ca85")
        return
    
    address = sys.argv[1]
    await explore_device(address)


if __name__ == "__main__":
    asyncio.run(main())
