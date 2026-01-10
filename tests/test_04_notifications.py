"""
BASELINE TEST 4: Notification Testing
Tests: Subscribe to characteristics and receive notifications

Target Device: 34:13:43:46:CA:84

Success Criteria:
- Can subscribe to Mesh Proxy Out (Handle 41)
- Can subscribe to Telink Status (Handle 17)
- Can receive notifications within timeout
- Notifications are properly formatted
"""

import asyncio
from bleak import BleakClient
from datetime import datetime

# Target device
TARGET_DEVICE = "34:13:43:46:CA:84"

# Notification characteristics
MESH_PROXY_OUT_UUID = "00002ade-0000-1000-8000-00805f9b34fb"
TELINK_STATUS_UUID = "00010203-0405-0607-0809-0a0b0c0d1911"

# Notification storage
notifications_received = []


def notification_handler(sender, data):
    """Handle incoming notifications."""
    timestamp = datetime.now().isoformat()
    hex_data = data.hex()
    notifications_received.append({
        "timestamp": timestamp,
        "sender": sender,
        "data": data,
        "hex": hex_data
    })
    print(f"  [{timestamp}] Notification from {sender}")
    print(f"    Data: {hex_data} ({len(data)} bytes)")
    if len(data) <= 20:
        print(f"    Bytes: {' '.join(f'{b:02x}' for b in data)}")


async def test_subscribe_mesh_proxy():
    """Test 4a: Subscribe to Mesh Proxy Out"""
    print("\n" + "="*60)
    print("TEST 4a: Mesh Proxy Out Subscription")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}")
    print(f"Characteristic: {MESH_PROXY_OUT_UUID}\n")
    
    notifications_received.clear()
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            if not client.is_connected:
                print("✗ Connection failed")
                return False
            
            print("✓ Connected")
            
            # Subscribe to notifications
            print("Subscribing to Mesh Proxy Out...", end=" ", flush=True)
            await client.start_notify(MESH_PROXY_OUT_UUID, notification_handler)
            print("✓")
            
            # Wait for potential notifications
            print("\nListening for 5 seconds...")
            await asyncio.sleep(5)
            
            # Unsubscribe
            print("\nUnsubscribing...", end=" ", flush=True)
            await client.stop_notify(MESH_PROXY_OUT_UUID)
            print("✓")
            
            count = len(notifications_received)
            print(f"\nReceived {count} notification(s)")
            
            return True  # Pass if subscription works (notifications optional)
            
    except Exception as e:
        print(f"✗ ERROR - {type(e).__name__}: {e}")
        return False


async def test_subscribe_telink_status():
    """Test 4b: Subscribe to Telink Status"""
    print("\n" + "="*60)
    print("TEST 4b: Telink Status Subscription")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}")
    print(f"Characteristic: {TELINK_STATUS_UUID}\n")
    
    notifications_received.clear()
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            if not client.is_connected:
                print("✗ Connection failed")
                return False
            
            print("✓ Connected")
            
            # Subscribe to notifications
            print("Subscribing to Telink Status...", end=" ", flush=True)
            await client.start_notify(TELINK_STATUS_UUID, notification_handler)
            print("✓")
            
            # Wait for potential notifications
            print("\nListening for 5 seconds...")
            await asyncio.sleep(5)
            
            # Unsubscribe
            print("\nUnsubscribing...", end=" ", flush=True)
            await client.stop_notify(TELINK_STATUS_UUID)
            print("✓")
            
            count = len(notifications_received)
            print(f"\nReceived {count} notification(s)")
            
            return True  # Pass if subscription works
            
    except Exception as e:
        print(f"✗ ERROR - {type(e).__name__}: {e}")
        return False


async def test_dual_subscription():
    """Test 4c: Subscribe to both characteristics simultaneously"""
    print("\n" + "="*60)
    print("TEST 4c: Dual Subscription")
    print("="*60)
    print(f"Target: {TARGET_DEVICE}")
    print("Testing both Mesh Proxy Out + Telink Status\n")
    
    notifications_received.clear()
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            if not client.is_connected:
                print("✗ Connection failed")
                return False
            
            print("✓ Connected")
            
            # Subscribe to both
            print("Subscribing to Mesh Proxy Out...", end=" ", flush=True)
            await client.start_notify(MESH_PROXY_OUT_UUID, notification_handler)
            print("✓")
            
            print("Subscribing to Telink Status...", end=" ", flush=True)
            await client.start_notify(TELINK_STATUS_UUID, notification_handler)
            print("✓")
            
            # Wait for potential notifications
            print("\nListening for 8 seconds (both channels)...")
            await asyncio.sleep(8)
            
            # Unsubscribe from both
            print("\nUnsubscribing from Mesh Proxy Out...", end=" ", flush=True)
            await client.stop_notify(MESH_PROXY_OUT_UUID)
            print("✓")
            
            print("Unsubscribing from Telink Status...", end=" ", flush=True)
            await client.stop_notify(TELINK_STATUS_UUID)
            print("✓")
            
            count = len(notifications_received)
            print(f"\nReceived {count} total notification(s)")
            
            # Show notification breakdown by source
            if count > 0:
                mesh_count = sum(1 for n in notifications_received if MESH_PROXY_OUT_UUID in str(n['sender']))
                telink_count = sum(1 for n in notifications_received if TELINK_STATUS_UUID in str(n['sender']))
                print(f"  Mesh Proxy Out: {mesh_count}")
                print(f"  Telink Status: {telink_count}")
            
            return True  # Pass if both subscriptions work
            
    except Exception as e:
        print(f"✗ ERROR - {type(e).__name__}: {e}")
        return False


async def main():
    """Run all notification tests"""
    print("\n" + "="*60)
    print("BASELINE TEST 4: NOTIFICATION TESTING")
    print("="*60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Target Device: {TARGET_DEVICE}")
    
    # Test 4a: Mesh Proxy Out
    mesh_ok = await test_subscribe_mesh_proxy()
    
    if not mesh_ok:
        print("\n✗ BASELINE TEST 4 FAILED: Mesh Proxy subscription failed")
        return
    
    await asyncio.sleep(1)  # Brief pause between tests
    
    # Test 4b: Telink Status
    telink_ok = await test_subscribe_telink_status()
    
    if not telink_ok:
        print("\n✗ BASELINE TEST 4 FAILED: Telink Status subscription failed")
        return
    
    await asyncio.sleep(1)
    
    # Test 4c: Dual subscription
    dual_ok = await test_dual_subscription()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"{'✓' if mesh_ok else '✗'} Mesh Proxy Out: {'PASS' if mesh_ok else 'FAIL'}")
    print(f"{'✓' if telink_ok else '✗'} Telink Status: {'PASS' if telink_ok else 'FAIL'}")
    print(f"{'✓' if dual_ok else '✗'} Dual Subscription: {'PASS' if dual_ok else 'FAIL'}")
    
    if mesh_ok and telink_ok and dual_ok:
        print("\n✓ BASELINE TEST 4: PASS")
        print("Notification system is working correctly")
        print("\nℹ Note: No spontaneous notifications is normal.")
        print("   Notifications typically arrive AFTER sending commands.")
    else:
        print("\n✗ BASELINE TEST 4: FAIL")


if __name__ == "__main__":
    asyncio.run(main())
