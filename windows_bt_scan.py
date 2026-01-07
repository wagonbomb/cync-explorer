"""
Windows Bluetooth Device Lister
Uses Windows APIs to list paired and discovered Bluetooth devices.
This can find Bluetooth Classic devices that BLE-only scanners miss.
"""

import asyncio
import subprocess
import sys


def get_windows_bt_devices_powershell():
    """Get Bluetooth devices using PowerShell."""
    print("Querying Windows Bluetooth devices via PowerShell...")
    print("-" * 60)
    
    ps_script = '''
    # Get all Bluetooth devices
    $devices = Get-PnpDevice -Class Bluetooth | Where-Object { $_.Status -eq 'OK' }
    foreach ($device in $devices) {
        Write-Host "Device: $($device.FriendlyName)"
        Write-Host "  Status: $($device.Status)"
        Write-Host "  InstanceId: $($device.InstanceId)"
        Write-Host ""
    }
    
    # Try to get Bluetooth radios
    Write-Host "=== Bluetooth Radios ==="
    Get-PnpDevice -Class Bluetooth | Where-Object { $_.FriendlyName -like '*Radio*' -or $_.FriendlyName -like '*Adapter*' }
    '''
    
    try:
        result = subprocess.run(
            ['powershell', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=30
        )
        print(result.stdout)
        if result.stderr:
            print(f"Errors: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("PowerShell command timed out")
    except FileNotFoundError:
        print("PowerShell not found")


def get_bt_devices_wmi():
    """Get Bluetooth devices using WMI."""
    print("\nQuerying via WMI...")
    print("-" * 60)
    
    ps_script = '''
    Get-WmiObject -Query "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%Bluetooth%'" | 
    ForEach-Object { 
        Write-Host "$($_.Name) - $($_.DeviceID)"
    }
    '''
    
    try:
        result = subprocess.run(
            ['powershell', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=30
        )
        print(result.stdout)
    except Exception as e:
        print(f"WMI query failed: {e}")


async def enhanced_ble_scan(target_mac: str = None, duration: float = 30.0):
    """
    Enhanced BLE scan with continuous monitoring.
    """
    from bleak import BleakScanner
    
    print(f"\n{'='*60}")
    print("ENHANCED BLE SCAN")
    print(f"{'='*60}")
    print(f"Scanning for {duration} seconds...")
    print("(Try toggling the light off/on during the scan)")
    print()
    
    if target_mac:
        target_normalized = target_mac.replace(":", "").replace("-", "").upper()
        print(f"Looking for MAC containing: {target_normalized}")
    
    discovered = {}
    
    def callback(device, adv_data):
        addr = device.address.replace(":", "").replace("-", "").upper()
        
        if addr not in discovered:
            discovered[addr] = {
                "device": device,
                "adv": adv_data,
                "count": 1
            }
            name = device.name or adv_data.local_name or "(Unknown)"
            rssi = adv_data.rssi
            
            # Check if this matches our target
            is_target = target_mac and target_normalized in addr
            marker = "🎯 TARGET: " if is_target else ""
            
            print(f"{marker}Found: {device.address} - {name} (RSSI: {rssi})")
            
            if adv_data.manufacturer_data:
                for mfr_id, data in adv_data.manufacturer_data.items():
                    print(f"    Mfr ID: {mfr_id:#06x}, Data: {data.hex()[:40]}")
        else:
            discovered[addr]["count"] += 1
    
    scanner = BleakScanner(detection_callback=callback)
    
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()
    
    print(f"\n{'='*60}")
    print(f"Scan complete. Found {len(discovered)} unique BLE devices.")
    
    if target_mac and target_normalized not in [k.upper() for k in discovered.keys()]:
        print(f"\n⚠️  Target MAC {target_mac} was NOT found via BLE.")
        print("\nPossible reasons:")
        print("  1. Device uses Bluetooth Classic, not BLE")
        print("  2. Device needs to be in pairing mode")
        print("  3. Another app has exclusive connection")
        print("  4. MAC address might be different than expected")
        print("\nTry:")
        print("  - Close the Cync app on your phone")
        print("  - Toggle the light off/on 3-5 times quickly")
        print("  - Check Windows Bluetooth settings for the device")


def main():
    print("=" * 60)
    print("WINDOWS BLUETOOTH DEVICE DISCOVERY")
    print("=" * 60)
    print()
    
    # First show Windows known devices
    get_windows_bt_devices_powershell()
    get_bt_devices_wmi()
    
    # Then do BLE scan
    target = sys.argv[1] if len(sys.argv) > 1 else None
    asyncio.run(enhanced_ble_scan(target, duration=20.0))


if __name__ == "__main__":
    main()
