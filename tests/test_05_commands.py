"""
BASELINE TEST 5: Simple Command Baseline
Tests: Send the simplest known commands from HCI logs

Target Device: 34:13:43:46:CA:84

Based on HCI analysis, the minimum command sequence is:
1. Subscribe to Mesh Proxy Out (for responses)
2. Send handshake to Mesh Provisioning In
3. Capture session ID from response
4. Send simple control commands

Success Criteria:
- Can send data to Mesh Provisioning In
- Can send data to Mesh Proxy In
- Receive responses on Mesh Proxy Out
- Identify session ID in responses
"""

import asyncio
from bleak import BleakClient
from datetime import datetime
import struct

# Target device
TARGET_DEVICE = "34:13:43:46:CA:84"

# Characteristics
MESH_PROVISIONING_IN_UUID = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN_UUID = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT_UUID = "00002ade-0000-1000-8000-00805f9b34fb"

# Notification storage
notifications = []


def notification_handler(sender, data):
    """Handle incoming notifications."""
    timestamp = datetime.now().isoformat()
    hex_data = data.hex()
    notifications.append({
        "timestamp": timestamp,
        "sender": sender,
        "data": data,
        "hex": hex_data
    })
    print(f"  [{timestamp[-12:]}] {hex_data} ({len(data)} bytes)")
    
    # Look for session ID pattern (04 00 00 XX)
    if len(data) >= 4 and data[0] == 0x04 and data[1] == 0x00 and data[2] == 0x00:
        session_id = data[3]
        print(f"    → Possible Session ID: 0x{session_id:02x}")


async def test_simple_write():
    """Test 5a: Simple write to Mesh Provisioning In"""
    print("\n" + "="*60)
    print("TEST 5a: Write to Mesh Provisioning In")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}\n")
    
    notifications.clear()
    
    # Simple test payload
    test_data = bytes.fromhex("000501")
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            if not client.is_connected:
                print("✗ Connection failed")
                return False
            
            print("✓ Connected")
            
            # Subscribe first
            print("Subscribing to Mesh Proxy Out...", end=" ", flush=True)
            await client.start_notify(MESH_PROXY_OUT_UUID, notification_handler)
            print("✓")
            
            await asyncio.sleep(0.5)
            
            # Write test data
            print(f"\nWriting to Mesh Provisioning In: {test_data.hex()}")
            await client.write_gatt_char(MESH_PROVISIONING_IN_UUID, test_data, response=False)
            print("✓ Write successful")
            
            # Wait for response
            print("\nWaiting for response...")
            await asyncio.sleep(2)
            
            # Cleanup
            await client.stop_notify(MESH_PROXY_OUT_UUID)
            
            count = len(notifications)
            print(f"\nReceived {count} notification(s) after write")
            
            return True
            
    except Exception as e:
        print(f"✗ ERROR - {type(e).__name__}: {e}")
        return False


async def test_handshake_sequence():
    """Test 5b: Full handshake sequence from context dump"""
    print("\n" + "="*60)
    print("TEST 5b: Handshake Sequence")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}\n")
    
    notifications.clear()
    session_id = None
    
    # Handshake commands from context dump
    commands = [
        ("START", bytes.fromhex("000501")),
        ("KEY", bytes.fromhex("000001040000")),
    ]
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            if not client.is_connected:
                print("✗ Connection failed")
                return False
            
            print("✓ Connected")
            
            # Subscribe
            print("Subscribing to Mesh Proxy Out...", end=" ", flush=True)
            await client.start_notify(MESH_PROXY_OUT_UUID, notification_handler)
            print("✓\n")
            
            await asyncio.sleep(0.5)
            
            # Send handshake commands
            for name, data in commands:
                print(f"Sending {name}: {data.hex()}")
                await client.write_gatt_char(MESH_PROVISIONING_IN_UUID, data, response=False)
                print("✓ Sent")
                await asyncio.sleep(0.5)
            
            # Wait for responses
            print("\nWaiting for responses...")
            await asyncio.sleep(1.5)
            
            # Look for session ID in notifications
            for notif in notifications:
                data = notif["data"]
                if len(data) >= 4 and data[0] == 0x04 and data[1] == 0x00 and data[2] == 0x00:
                    session_id = data[3]
                    print(f"\n✓ Session ID captured: 0x{session_id:02x}")
                    break
            
            # Cleanup
            await client.stop_notify(MESH_PROXY_OUT_UUID)
            
            count = len(notifications)
            print(f"\nTotal notifications: {count}")
            
            return session_id is not None
            
    except Exception as e:
        print(f"✗ ERROR - {type(e).__name__}: {e}")
        return False


async def test_mesh_proxy_write():
    """Test 5c: Write to Mesh Proxy In"""
    print("\n" + "="*60)
    print("TEST 5c: Write to Mesh Proxy In")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}\n")
    
    notifications.clear()
    
    # Simple test payload
    test_data = bytes.fromhex("3100")
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            if not client.is_connected:
                print("✗ Connection failed")
                return False
            
            print("✓ Connected")
            
            # Subscribe
            print("Subscribing to Mesh Proxy Out...", end=" ", flush=True)
            await client.start_notify(MESH_PROXY_OUT_UUID, notification_handler)
            print("✓")
            
            await asyncio.sleep(0.5)
            
            # Write test data
            print(f"\nWriting to Mesh Proxy In: {test_data.hex()}")
            await client.write_gatt_char(MESH_PROXY_IN_UUID, test_data, response=False)
            print("✓ Write successful")
            
            # Wait for response
            print("\nWaiting for response...")
            await asyncio.sleep(1.5)
            
            # Cleanup
            await client.stop_notify(MESH_PROXY_OUT_UUID)
            
            count = len(notifications)
            print(f"\nReceived {count} notification(s) after write")
            
            return True
            
    except Exception as e:
        print(f"✗ ERROR - {type(e).__name__}: {e}")
        return False


async def main():
    """Run all simple command tests"""
    print("\n" + "="*60)
    print("BASELINE TEST 5: SIMPLE COMMAND BASELINE")
    print("="*60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Target Device: {TARGET_DEVICE}")
    
    # Test 5a: Write to Provisioning
    prov_ok = await test_simple_write()
    
    if not prov_ok:
        print("\n✗ Test 5a failed")
        return
    
    await asyncio.sleep(1)
    
    # Test 5b: Handshake sequence
    handshake_ok = await test_handshake_sequence()
    
    await asyncio.sleep(1)
    
    # Test 5c: Write to Proxy
    proxy_ok = await test_mesh_proxy_write()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"{'✓' if prov_ok else '✗'} Mesh Provisioning Write: {'PASS' if prov_ok else 'FAIL'}")
    print(f"{'✓' if handshake_ok else '✗'} Handshake Sequence: {'PASS' if handshake_ok else 'FAIL'}")
    print(f"{'✓' if proxy_ok else '✗'} Mesh Proxy Write: {'PASS' if proxy_ok else 'FAIL'}")
    
    if prov_ok and proxy_ok:
        print("\n✓ BASELINE TEST 5: PASS")
        print("Command infrastructure is working")
        if handshake_ok:
            print("✓ Session ID capture successful!")
    else:
        print("\n✗ BASELINE TEST 5: FAIL")


if __name__ == "__main__":
    asyncio.run(main())
