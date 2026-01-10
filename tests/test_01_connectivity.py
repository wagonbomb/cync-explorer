"""
BASELINE TEST 1: Basic Connectivity
Tests: Scan, Discover, and Connect to Cync devices

Success Criteria:
- Can discover BLE devices
- Can identify Cync devices by MAC prefix
- Can successfully connect to a Cync device
- Can disconnect cleanly
"""

import asyncio
from bleak import BleakScanner, BleakClient
from datetime import datetime

# Known GE/Cync MAC prefixes (OUI)
GE_MAC_PREFIXES = ["341343", "786DEB", "78D6EB"]

def normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase with no separators."""
    return mac.replace(":", "").replace("-", "").upper()

def is_cync_device(mac: str) -> bool:
    """Check if MAC has a known GE/Cync prefix."""
    return normalize_mac(mac)[:6] in GE_MAC_PREFIXES

async def test_scan(duration=10):
    """Test 1a: Scan for BLE devices"""
    print("\n" + "="*60)
    print("TEST 1a: BLE Device Scan")
    print("="*60)
    print(f"Scanning for {duration} seconds...\n")
    
    devices = await BleakScanner.discover(timeout=duration)
    
    cync_devices = []
    other_devices = []
    
    for device in devices:
        if is_cync_device(device.address):
            cync_devices.append(device)
        else:
            other_devices.append(device)
    
    print(f"✓ Found {len(devices)} total BLE devices")
    print(f"✓ Found {len(cync_devices)} Cync devices\n")
    
    if cync_devices:
        print("Cync Devices:")
        for i, device in enumerate(cync_devices, 1):
            print(f"  {i}. {device.address} - {device.name or '(No Name)'}")
            print(f"     RSSI: {device.rssi if hasattr(device, 'rssi') else 'N/A'}")
    else:
        print("⚠ No Cync devices found")
        print("\nOther devices (showing first 5):")
        for i, device in enumerate(other_devices[:5], 1):
            print(f"  {i}. {device.address} - {device.name or '(No Name)'}")
    
    return cync_devices

async def test_connect(device_address):
    """Test 1b: Connect to a specific device"""
    print("\n" + "="*60)
    print("TEST 1b: Device Connection")
    print("="*60)
    print(f"Target: {device_address}")
    print("Timeout: 10 seconds\n")
    
    try:
        print("Connecting...", end=" ", flush=True)
        async with BleakClient(device_address, timeout=10.0) as client:
            is_connected = client.is_connected
            print(f"{'✓' if is_connected else '✗'}")
            
            if is_connected:
                print(f"✓ MTU Size: {client.mtu_size if hasattr(client, 'mtu_size') else 'N/A'}")
                print("✓ Disconnecting...", end=" ", flush=True)
                await asyncio.sleep(0.2)
                print("Done")
                return True
            else:
                print("✗ Connection failed - not connected")
                return False
                
    except asyncio.TimeoutError:
        print("✗ TIMEOUT")
        print(f"✗ Connection timed out after 10 seconds")
        return False
    except asyncio.CancelledError:
        print("✗ CANCELLED")
        print(f"✗ Connection was cancelled")
        return False
    except Exception as e:
        print(f"✗ ERROR")
        print(f"✗ Connection error: {type(e).__name__}: {e}")
        return False

async def test_repeated_connection(device_address, attempts=3):
    """Test 1c: Multiple connect/disconnect cycles"""
    print("\n" + "="*60)
    print("TEST 1c: Connection Stability")
    print("="*60)
    print(f"Testing {attempts} connect/disconnect cycles (8s timeout each)...\n")
    
    results = []
    for i in range(attempts):
        print(f"Attempt {i+1}/{attempts}...", end=" ", flush=True)
        try:
            async with BleakClient(device_address, timeout=8.0) as client:
                if client.is_connected:
                    print("✓")
                    results.append(True)
                    await asyncio.sleep(0.3)  # Brief hold
                else:
                    print("✗ (not connected)")
                    results.append(False)
        except asyncio.TimeoutError:
            print("✗ (timeout)")
            results.append(False)
        except asyncio.CancelledError:
            print("✗ (cancelled)")
            results.append(False)
        except Exception as e:
            print(f"✗ ({type(e).__name__})")
            results.append(False)
        
        if i < attempts - 1:
            await asyncio.sleep(0.5)  # Brief wait between attempts
    
    success_rate = sum(results) / len(results) * 100 if results else 0
    print(f"\nSuccess Rate: {success_rate:.1f}% ({sum(results)}/{len(results)})")
    return success_rate >= 80  # Pass if 80%+ successful

async def main():
    """Run all baseline connectivity tests"""
    print("\n" + "="*60)
    print("BASELINE TEST 1: CONNECTIVITY")
    print("="*60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # Test 1a: Scan
    cync_devices = await test_scan(duration=10)
    
    if not cync_devices:
        print("\n⚠ Cannot proceed without Cync devices. Ensure device is:")
        print("  - Powered on")
        print("  - In range")
        print("  - Bluetooth enabled")
        return
    
    # Use first discovered Cync device
    target_device = cync_devices[0]
    target_address = target_device.address
    
    # Test 1b: Single connection
    connected = await test_connect(target_address)
    
    if not connected:
        print("\n✗ BASELINE TEST 1 FAILED: Cannot establish connection")
        return
    
    # Test 1c: Connection stability
    stable = await test_repeated_connection(target_address, attempts=3)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"✓ Scan: PASS ({len(cync_devices)} Cync devices found)")
    print(f"{'✓' if connected else '✗'} Connect: {'PASS' if connected else 'FAIL'}")
    print(f"{'✓' if stable else '✗'} Stability: {'PASS' if stable else 'FAIL'}")
    
    if connected and stable:
        print("\n✓ BASELINE TEST 1: PASS")
        print(f"Ready device: {target_address}")
    else:
        print("\n✗ BASELINE TEST 1: FAIL")

if __name__ == "__main__":
    asyncio.run(main())
