"""
BASELINE TEST 2: Characteristic Discovery
Tests: Connect and enumerate all GATT services and characteristics

Target Device: 34:13:43:46:CA:85

Success Criteria:
- Can connect to target device
- Can enumerate all services
- Can identify Mesh Proxy characteristics
- Can identify Telink characteristics
- Can read characteristic properties (read/write/notify)
"""

import asyncio
from bleak import BleakClient
from datetime import datetime

# Target device
TARGET_DEVICE = "34:13:43:46:CA:84"

# Expected UUIDs from context dump
EXPECTED_UUIDS = {
    "Mesh Provisioning In": "00002adb-0000-1000-8000-00805f9b34fb",
    "Mesh Proxy In": "00002add-0000-1000-8000-00805f9b34fb",
    "Mesh Proxy Out": "00002ade-0000-1000-8000-00805f9b34fb",
    "Telink Command": "00010203-0405-0607-0809-0a0b0c0d1912",
    "Telink Status": "00010203-0405-0607-0809-0a0b0c0d1911",
}


def format_properties(char):
    """Format characteristic properties as a readable string."""
    props = []
    if "read" in char.properties:
        props.append("READ")
    if "write" in char.properties:
        props.append("WRITE")
    if "write-without-response" in char.properties:
        props.append("WRITE-NO-RESP")
    if "notify" in char.properties:
        props.append("NOTIFY")
    if "indicate" in char.properties:
        props.append("INDICATE")
    return ", ".join(props) if props else "NONE"


def identify_characteristic(uuid):
    """Try to identify a characteristic by UUID."""
    uuid_lower = uuid.lower()
    for name, expected_uuid in EXPECTED_UUIDS.items():
        if uuid_lower == expected_uuid.lower():
            return f"✓ {name}"
    return ""


async def test_service_discovery():
    """Test 2a: Enumerate all services"""
    print("\n" + "="*60)
    print("TEST 2a: Service Discovery")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}")
    print("Timeout: 15 seconds\n")
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            if not client.is_connected:
                print("✗ Connection failed")
                return None
            
            print(f"✓ Connected (MTU: {client.mtu_size if hasattr(client, 'mtu_size') else 'N/A'})\n")
            
            services = list(client.services)
            print(f"✓ Found {len(services)} services\n")
            
            service_list = []
            for service in services:
                service_info = {
                    "uuid": service.uuid,
                    "handle": service.handle if hasattr(service, 'handle') else None,
                    "characteristics": []
                }
                
                print(f"Service: {service.uuid}")
                print(f"  Handle: {service.handle if hasattr(service, 'handle') else 'N/A'}")
                print(f"  Characteristics: {len(service.characteristics)}")
                
                for char in service.characteristics:
                    char_name = identify_characteristic(char.uuid)
                    char_info = {
                        "uuid": char.uuid,
                        "handle": char.handle if hasattr(char, 'handle') else None,
                        "properties": list(char.properties),
                        "identified": bool(char_name)
                    }
                    service_info["characteristics"].append(char_info)
                    
                    print(f"    Char: {char.uuid} {char_name}")
                    print(f"      Handle: {char.handle if hasattr(char, 'handle') else 'N/A'}")
                    print(f"      Properties: {format_properties(char)}")
                    
                    # Show descriptors if any
                    if char.descriptors:
                        for desc in char.descriptors:
                            print(f"      Descriptor: {desc.uuid} (Handle: {desc.handle if hasattr(desc, 'handle') else 'N/A'})")
                
                print()
                service_list.append(service_info)
            
            return service_list
            
    except asyncio.TimeoutError:
        print("✗ TIMEOUT - Connection timed out")
        return None
    except asyncio.CancelledError:
        print("✗ CANCELLED - Connection was cancelled")
        return None
    except Exception as e:
        print(f"✗ ERROR - {type(e).__name__}: {e}")
        return None


async def test_characteristic_verification(services):
    """Test 2b: Verify expected characteristics exist"""
    print("\n" + "="*60)
    print("TEST 2b: Characteristic Verification")
    print("="*60)
    print("Checking for expected UUIDs...\n")
    
    if not services:
        print("✗ No services available")
        return False
    
    # Flatten all characteristics
    all_chars = []
    for service in services:
        all_chars.extend(service["characteristics"])
    
    found_uuids = {char["uuid"].lower() for char in all_chars}
    
    results = {}
    for name, expected_uuid in EXPECTED_UUIDS.items():
        found = expected_uuid.lower() in found_uuids
        results[name] = found
        status = "✓" if found else "✗"
        print(f"{status} {name}: {expected_uuid}")
        if found:
            # Show properties for found characteristic
            for char in all_chars:
                if char["uuid"].lower() == expected_uuid.lower():
                    props = ", ".join(char["properties"])
                    print(f"    Properties: {props}")
                    break
    
    print()
    found_count = sum(results.values())
    total_count = len(results)
    print(f"Found {found_count}/{total_count} expected characteristics")
    
    return found_count >= 3  # Pass if we find at least 3 of the expected 5


async def test_handle_mapping():
    """Test 2c: Create handle mapping for quick reference"""
    print("\n" + "="*60)
    print("TEST 2c: Handle Mapping")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}\n")
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            if not client.is_connected:
                print("✗ Connection failed")
                return None
            
            handle_map = {}
            
            for service in client.services:
                for char in service.characteristics:
                    char_name = identify_characteristic(char.uuid)
                    if char_name:
                        name = char_name.replace("✓ ", "")
                        handle_map[name] = {
                            "uuid": char.uuid,
                            "handle": char.handle if hasattr(char, 'handle') else None,
                            "properties": list(char.properties)
                        }
            
            if handle_map:
                print("Quick Reference Handle Map:")
                print("-" * 60)
                for name, info in handle_map.items():
                    print(f"{name}:")
                    print(f"  UUID: {info['uuid']}")
                    print(f"  Handle: {info['handle']}")
                    print(f"  Properties: {', '.join(info['properties'])}")
                    print()
                return handle_map
            else:
                print("⚠ No recognized characteristics found")
                return None
                
    except Exception as e:
        print(f"✗ ERROR - {type(e).__name__}: {e}")
        return None


async def main():
    """Run all characteristic discovery tests"""
    print("\n" + "="*60)
    print("BASELINE TEST 2: CHARACTERISTIC DISCOVERY")
    print("="*60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Target Device: {TARGET_DEVICE}")
    
    # Test 2a: Service Discovery
    services = await test_service_discovery()
    
    if not services:
        print("\n✗ BASELINE TEST 2 FAILED: Could not discover services")
        return
    
    # Test 2b: Verify expected characteristics
    verified = await test_characteristic_verification(services)
    
    # Test 2c: Create handle mapping
    handle_map = await test_handle_mapping()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"✓ Service Discovery: PASS ({len(services)} services)")
    print(f"{'✓' if verified else '✗'} Characteristic Verification: {'PASS' if verified else 'FAIL'}")
    print(f"{'✓' if handle_map else '✗'} Handle Mapping: {'PASS' if handle_map else 'FAIL'}")
    
    if services and verified:
        print("\n✓ BASELINE TEST 2: PASS")
        print(f"Device {TARGET_DEVICE} is properly configured")
    else:
        print("\n⚠ BASELINE TEST 2: PARTIAL")
        print("Some characteristics may be missing")


if __name__ == "__main__":
    asyncio.run(main())
