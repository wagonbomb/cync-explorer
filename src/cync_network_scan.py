"""
Cync Network Scanner
Scans for all known Cync devices in the network and reports which ones are visible via BLE.
"""

import asyncio
from bleak import BleakScanner
from datetime import datetime
from known_devices import KNOWN_CYNC_MACS, GE_MAC_PREFIXES, format_mac, normalize_mac


async def scan_for_cync_network(timeout: float = 30.0):
    """
    Scan for known Cync devices in the network.
    Reports which devices from the known list are visible.
    """
    print("=" * 70)
    print("CYNC NETWORK SCANNER")
    print("=" * 70)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning for {timeout} seconds...")
    print(f"Looking for {len(KNOWN_CYNC_MACS)} known devices...")
    print()
    
    found_devices = {}
    
    def detection_callback(device, adv_data):
        # Normalize the MAC
        mac_normalized = normalize_mac(device.address)
        
        if mac_normalized not in found_devices:
            # Check if it's a known device or has GE prefix
            is_known = mac_normalized in KNOWN_CYNC_MACS
            has_ge_prefix = mac_normalized[:6] in GE_MAC_PREFIXES
            
            if is_known or has_ge_prefix:
                found_devices[mac_normalized] = {
                    "device": device,
                    "adv": adv_data,
                    "known": is_known
                }
                
                name = device.name or adv_data.local_name or "(No name)"
                status = "✅ KNOWN" if is_known else "❓ NEW GE DEVICE"
                print(f"  {status}: {format_mac(mac_normalized)} - {name} (RSSI: {adv_data.rssi})")
    
    scanner = BleakScanner(detection_callback=detection_callback)
    
    print("Discovered devices:")
    print("-" * 70)
    
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()
    
    # Summary
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    known_found = [m for m, d in found_devices.items() if d["known"]]
    known_missing = [m for m in KNOWN_CYNC_MACS if m not in found_devices]
    new_ge_devices = [m for m, d in found_devices.items() if not d["known"]]
    
    print(f"\n✅ Found {len(known_found)}/{len(KNOWN_CYNC_MACS)} known devices:")
    for mac in sorted(known_found):
        info = found_devices[mac]
        name = info["device"].name or info["adv"].local_name or "(No name)"
        print(f"   {format_mac(mac)}: {name}")
    
    if new_ge_devices:
        print(f"\n❓ Found {len(new_ge_devices)} NEW GE devices (not in known list):")
        for mac in sorted(new_ge_devices):
            info = found_devices[mac]
            name = info["device"].name or info["adv"].local_name or "(No name)"
            print(f"   {format_mac(mac)}: {name}")
    
    print(f"\n❌ Missing {len(known_missing)}/{len(KNOWN_CYNC_MACS)} known devices:")
    if len(known_missing) <= 10:
        for mac in sorted(known_missing):
            print(f"   {format_mac(mac)}")
    else:
        print(f"   (Too many to list - {len(known_missing)} devices not responding)")
    
    return found_devices, known_missing


if __name__ == "__main__":
    import sys
    
    timeout = 30.0
    if len(sys.argv) > 1:
        try:
            timeout = float(sys.argv[1])
        except ValueError:
            pass
    
    asyncio.run(scan_for_cync_network(timeout))
