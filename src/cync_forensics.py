
import asyncio
import logging
import sys
import json
from datetime import datetime
from pathlib import Path
from bleak import BleakScanner, BleakClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("forensics")

TARGET_SUFFIX = "85" # The one user wants to debug
REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "artifacts" / "outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def main():
    print(f"🕵️ CYNC FORENSICS TOOL - Target: ...{TARGET_SUFFIX}")
    print("Scanning...")
    
    device = None
    devices = await BleakScanner.discover(timeout=8.0)
    
    for d in devices:
        key = d.address.replace(":", "").upper()
        if key.endswith(TARGET_SUFFIX):
            device = d
            break
        # Alias check
        if key.endswith("84"): # Common alias for 85
            print(f"Found potential alias ending in 84: {d.address}")
            device = d
            
    if not device:
        print("❌ Device not found. Move closer?")
        return

    print(f"found {device.name} ({device.address})")
    print("Connecting for DEEP DUMP...")
    
    async with BleakClient(device.address) as client:
        print("✅ Connected.")
        
        report = {
            "address": device.address,
            "name": device.name,
            "services": []
        }
        
        print("\n--- SERVICES & CHARACTERISTICS ---")
        for service in client.services:
            srv_info = {
                "uuid": str(service.uuid),
                "description": service.description,
                "chars": []
            }
            print(f"\nService: {service.uuid} ({service.description})")
            
            for char in service.characteristics:
                char_info = {
                    "uuid": str(char.uuid),
                    "properties": char.properties,
                    "handle": char.handle,
                    "value": None,
                    "descriptors": []
                }
                
                print(f"  [Char] {char.uuid} ({', '.join(char.properties)})")
                
                # 1. Force Read
                if "read" in char.properties:
                    try:
                        val = await client.read_gatt_char(char.uuid)
                        char_info["value"] = val.hex()
                        print(f"      Value: 0x{val.hex()} | {val}")
                    except Exception as e:
                        print(f"      Read Fail: {e}")
                
                # 2. Read Descriptors
                for descriptor in char.descriptors:
                    try:
                        desc_val = await client.read_gatt_descriptor(descriptor.handle)
                        char_info["descriptors"].append({
                            "uuid": str(descriptor.uuid),
                            "value": desc_val.hex(),
                            "text": str(desc_val)
                        })
                        print(f"      [Desc] {descriptor.uuid}: {desc_val}")
                    except Exception as e:
                        print(f"      Desc Fail: {e}")

                # 3. Subscribe to Notify (to see if it talks to us)
                if "notify" in char.properties:
                    try:
                        def callback(sender, data):
                            print(f"      🔔 NOTIFICATION from {sender}: {data.hex()}")
                        
                        await client.start_notify(char.uuid, callback)
                        print("      Subscribed to notifications...")
                        char_info["notifications_active"] = True
                    except Exception as e:
                        print(f"      Notify Fail: {e}")

                srv_info["chars"].append(char_info)
            report["services"].append(srv_info)

        print("\n--- LISTENING FOR EVENTS (10s) ---")
        print("Watching for handshake/challenges...")
        await asyncio.sleep(10.0)
        
        # Save Report
        filename = OUTPUT_DIR / f"forensics_{datetime.now().strftime('%H%M%S')}.json"
        with filename.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Saved full forensic report to {filename}")

if __name__ == "__main__":
    asyncio.run(main())
