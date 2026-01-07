"""
GE Cync BLE Scanner - Enhanced Edition
Scans for BLE devices with comprehensive identification and logging.
Attempts to connect and gather detailed information from each GE device.
"""

import asyncio
import json
import os
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakError
from datetime import datetime

# Known GE/Cync MAC prefixes (OUI)
GE_MAC_PREFIXES = ["341343", "786DEB"]

# Log directory
LOG_DIR = os.path.dirname(os.path.abspath(__file__))


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase with no separators."""
    return mac.replace(":", "").replace("-", "").upper()


def format_mac(mac: str) -> str:
    """Format MAC with colons for display."""
    mac = normalize_mac(mac)
    return ":".join(mac[i:i+2] for i in range(0, 12, 2))


def is_ge_device(mac: str) -> bool:
    """Check if MAC has a known GE/Cync prefix."""
    return normalize_mac(mac)[:6] in GE_MAC_PREFIXES


def get_oui_info(mac: str) -> str:
    """Get manufacturer info based on MAC OUI (first 3 bytes)."""
    oui = normalize_mac(mac)[:6]
    # Known OUIs
    oui_db = {
        "341343": "GE Lighting (Cync)",
        "786DEB": "GE Lighting (Cync)",
        "78D6EB": "GE Lighting (Cync) - variant",
        "001A7D": "Cyber-Blue(ShenZhen)Ltd",  # Common smart bulb
        "A4C138": "Telink Semiconductor",  # Common BLE chip
        "38F7CD": "Shenzhen Aimitech",  # Smart home devices
    }
    return oui_db.get(oui, f"Unknown OUI ({oui})")


class DeviceLogger:
    """Logger for discovered devices."""
    
    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(log_dir, f"scan_log_{self.timestamp}.txt")
        self.json_file = os.path.join(log_dir, f"devices_{self.timestamp}.json")
        self.devices = []
        
        # Start log file
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(f"Cync BLE Scan Log - {datetime.now().isoformat()}\n")
            f.write("=" * 80 + "\n\n")
    
    def log(self, message: str):
        """Log a message to both console and file."""
        print(message)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(message + "\n")
    
    def add_device(self, device_info: dict):
        """Add a device to the JSON log."""
        self.devices.append(device_info)
        with open(self.json_file, "w", encoding="utf-8") as f:
            json.dump(self.devices, f, indent=2, default=str)
    
    def get_log_paths(self):
        """Get paths to log files."""
        return self.log_file, self.json_file


async def deep_scan_device(address: str, adv_data, logger: DeviceLogger) -> dict:
    """
    Attempt to connect to a device and gather detailed GATT information.
    """
    device_info = {
        "address": format_mac(address),
        "address_raw": address,
        "manufacturer": get_oui_info(address),
        "is_ge": is_ge_device(address),
        "scan_time": datetime.now().isoformat(),
        "advertisement": {},
        "gatt_services": [],
        "connection_successful": False,
        "error": None
    }
    
    # Capture advertisement data
    if adv_data:
        device_info["advertisement"] = {
            "local_name": adv_data.local_name,
            "rssi": adv_data.rssi,
            "service_uuids": list(adv_data.service_uuids) if adv_data.service_uuids else [],
            "manufacturer_data": {
                str(k): v.hex() for k, v in adv_data.manufacturer_data.items()
            } if adv_data.manufacturer_data else {},
            "service_data": {
                str(k): v.hex() for k, v in adv_data.service_data.items()
            } if adv_data.service_data else {},
            "tx_power": adv_data.tx_power
        }
    
    logger.log(f"\n   📡 Attempting connection to {format_mac(address)}...")
    
    try:
        async with BleakClient(address, timeout=10.0) as client:
            device_info["connection_successful"] = True
            logger.log(f"   ✅ Connected!")
            
            # Enumerate services and characteristics
            for service in client.services:
                service_info = {
                    "uuid": str(service.uuid),
                    "handle": service.handle,
                    "characteristics": []
                }
                
                for char in service.characteristics:
                    char_info = {
                        "uuid": str(char.uuid),
                        "handle": char.handle,
                        "properties": list(char.properties),
                        "value": None,
                        "value_decoded": None
                    }
                    
                    # Try to read if readable
                    if "read" in char.properties:
                        try:
                            value = await client.read_gatt_char(char.uuid)
                            char_info["value"] = value.hex()
                            # Try to decode as string
                            try:
                                char_info["value_decoded"] = value.decode('utf-8')
                            except:
                                pass
                        except Exception as e:
                            char_info["value"] = f"<error: {str(e)[:50]}>"
                    
                    service_info["characteristics"].append(char_info)
                
                device_info["gatt_services"].append(service_info)
            
            logger.log(f"   📦 Found {len(device_info['gatt_services'])} services")
            
    except BleakError as e:
        device_info["error"] = str(e)
        logger.log(f"   ❌ Connection failed: {e}")
    except Exception as e:
        device_info["error"] = str(e)
        logger.log(f"   ❌ Error: {e}")
    
    return device_info


async def enhanced_scan(timeout: float = 20.0, connect_to_ge: bool = True):
    """
    Enhanced BLE scan with device identification and optional deep scanning.
    """
    logger = DeviceLogger(LOG_DIR)
    
    logger.log("=" * 80)
    logger.log("CYNC BLE SCANNER - ENHANCED EDITION")
    logger.log("=" * 80)
    logger.log(f"Scan started: {datetime.now().isoformat()}")
    logger.log(f"Scan duration: {timeout} seconds")
    logger.log(f"Deep scan GE devices: {connect_to_ge}")
    logger.log("")
    
    # Discover devices
    logger.log("Phase 1: Discovering BLE devices...")
    logger.log("-" * 80)
    
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    
    # Sort by signal strength
    sorted_devices = sorted(devices.items(), key=lambda x: x[1][1].rssi, reverse=True)
    
    logger.log(f"\nFound {len(devices)} BLE devices total")
    logger.log("")
    
    # Categorize
    ge_devices = []
    other_devices = []
    
    for address, (device, adv_data) in sorted_devices:
        if is_ge_device(address):
            ge_devices.append((address, device, adv_data))
        else:
            other_devices.append((address, device, adv_data))
    
    # Display all devices
    logger.log("=" * 80)
    logger.log("DISCOVERED DEVICES")
    logger.log("=" * 80)
    logger.log(f"\n{'Type':<8} {'MAC Address':<20} {'Name':<25} {'RSSI':<6} {'Manufacturer'}")
    logger.log("-" * 80)
    
    for address, (device, adv_data) in sorted_devices:
        name = device.name or adv_data.local_name or "(Unknown)"
        rssi = adv_data.rssi
        mfr = get_oui_info(address)[:20]
        is_ge = "🔆 GE" if is_ge_device(address) else "   "
        
        logger.log(f"{is_ge:<8} {format_mac(address):<20} {name:<25} {rssi:<6} {mfr}")
        
        # Show extra details for GE devices
        if is_ge_device(address):
            if adv_data.manufacturer_data:
                for mfr_id, data in adv_data.manufacturer_data.items():
                    logger.log(f"         └─ Mfr Data [{mfr_id:#06x}]: {data.hex()}")
            if adv_data.service_uuids:
                logger.log(f"         └─ Services: {', '.join(str(u)[:8] + '...' for u in adv_data.service_uuids)}")
    
    # Deep scan GE devices
    if connect_to_ge and ge_devices:
        logger.log("")
        logger.log("=" * 80)
        logger.log(f"Phase 2: Deep scanning {len(ge_devices)} GE device(s)...")
        logger.log("=" * 80)
        
        for address, device, adv_data in ge_devices:
            name = device.name or adv_data.local_name or "(Unknown)"
            logger.log(f"\n🔆 DEVICE: {format_mac(address)} - {name}")
            
            device_info = await deep_scan_device(address, adv_data, logger)
            logger.add_device(device_info)
            
            # Print interesting findings
            if device_info["connection_successful"]:
                for svc in device_info["gatt_services"]:
                    writable_chars = [c for c in svc["characteristics"] 
                                     if "write" in c["properties"] or "write-without-response" in c["properties"]]
                    if writable_chars:
                        logger.log(f"   🎮 Writable characteristic in {svc['uuid'][:8]}...")
                        for c in writable_chars:
                            props = ", ".join(c["properties"])
                            logger.log(f"      - {c['uuid'][:8]}... [{props}]")
                
                # Look for device info characteristics
                for svc in device_info["gatt_services"]:
                    for c in svc["characteristics"]:
                        if c["value_decoded"]:
                            logger.log(f"   📝 Readable: {c['uuid'][:8]}... = '{c['value_decoded']}'")
    
    # Summary
    logger.log("")
    logger.log("=" * 80)
    logger.log("SUMMARY")
    logger.log("=" * 80)
    logger.log(f"Total devices: {len(devices)}")
    logger.log(f"GE/Cync devices: {len(ge_devices)}")
    logger.log(f"Other devices: {len(other_devices)}")
    
    if ge_devices:
        logger.log(f"\n🔆 GE DEVICES FOUND:")
        for address, device, adv_data in ge_devices:
            name = device.name or adv_data.local_name or "(Unknown)"
            
            # Check for aliasing
            scan_mac = normalize_mac(address)
            alias_info = ""
            
            # Check if this maps to a known MAC via alias
            try:
                msg_int = int(scan_mac, 16)
                plus_1 = f"{msg_int + 1:012X}"
                minus_1 = f"{msg_int - 1:012X}"
                
                # Check known_devices module if available
                try: 
                    from known_devices import KNOWN_CYNC_MACS
                    if scan_mac in KNOWN_CYNC_MACS:
                        alias_info = " [Exact Match]"
                    elif plus_1 in KNOWN_CYNC_MACS:
                        alias_info = f" [Alias of {format_mac(plus_1)}]"
                    elif minus_1 in KNOWN_CYNC_MACS:
                        alias_info = f" [Alias of {format_mac(minus_1)}]"
                except ImportError:
                    pass
            except:
                pass

            logger.log(f"   {format_mac(address)}: {name} (RSSI: {adv_data.rssi}){alias_info}")
    
    log_file, json_file = logger.get_log_paths()
    logger.log(f"\n📁 Log files saved:")
    logger.log(f"   Text: {log_file}")
    logger.log(f"   JSON: {json_file}")
    
    return {
        "ge_devices": ge_devices,
        "other_devices": other_devices,
        "log_file": log_file,
        "json_file": json_file
    }


if __name__ == "__main__":
    import sys
    
    timeout = 20.0
    connect = True
    
    # Parse arguments
    for arg in sys.argv[1:]:
        if arg == "--no-connect":
            connect = False
        elif arg == "--fast":
            timeout = 10.0
        elif arg == "--long":
            timeout = 60.0
        else:
            try:
                timeout = float(arg)
            except ValueError:
                pass
    
    print(f"Usage: python {sys.argv[0]} [timeout] [--no-connect] [--fast] [--long]")
    print("")
    
    asyncio.run(enhanced_scan(timeout=timeout, connect_to_ge=connect))
