
import asyncio
import sys
import logging
from pathlib import Path
from bleak import BleakScanner, BleakClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("debugger")

# Target suffix
TARGET_SUFFIX = "85"
REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "artifacts" / "outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Known Cync Magic Packets (Source: Common reverse engineering)
TEST_PACKETS = [
    ("Simple On", bytes([0x01])),
    ("Simple Off", bytes([0x00])),
    ("Magic On 1", bytes.fromhex("7e0004010100ff00ef")),
    ("Magic Off 1", bytes.fromhex("7e0004000100ff00ef")),
    ("Magic On 2 (RGB)", bytes.fromhex("7e0404f00001ff000000007e")), # some other variant
    ("Telink On", bytes.fromhex("010101")),
    ("Telink Off", bytes.fromhex("010100")),
]

async def main():
    logger.info(f"Scanning for device ending in ':{TARGET_SUFFIX}'...")
    
    device = None
    devices = await BleakScanner.discover(timeout=10.0)
    
    for d in devices:
        if d.address.replace(":", "").upper().endswith(TARGET_SUFFIX):
            device = d
            break
            
    if not device:
        logger.error(f"Device ending in {TARGET_SUFFIX} not found!")
        # Fallback to search for alias
        # If user meant 85 but it shows as 84
        logger.info("Checking for potential alias (84)...")
        for d in devices:
            if d.address.replace(":", "").upper().endswith("84"): # Alias check
                device = d
                logger.info(f"Found alias device: {d.address} (assuming this is the target)")
                break
    
    if not device:
         logger.error("Could not find device or alias.")
         return

    logger.info(f"Found Device: {device.name} [{device.address}]")
    logger.info("Connecting...")
    
    async with BleakClient(device.address) as client:
        logger.info("✅ Connected!")
        
        logger.info("--- GATT SERVICE DUMP ---")
        writable_chars = []
        
        for service in client.services:
            logger.info(f"Service: {service.uuid} ({service.description})")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                logger.info(f"  ├─ Char: {char.uuid} [{props}]")
                
                # READ TEST
                if "read" in char.properties:
                    try:
                        val = await client.read_gatt_char(char.uuid)
                        logger.info(f"  │    Current Value: {val.hex()} | {val}")
                    except Exception as e:
                         logger.info(f"  │    Read Error: {e}")
                
                if "write" in char.properties or "write-without-response" in char.properties:
                    writable_chars.append(char)
        
        print("\n" + "="*50)
        print("ATTEMPTING ACTIVE CONTROL TESTS")
        print("="*50)
        
        # Focus on the known Mesh Control Char first, then others
        # Mesh Char: ...1911 (from previous scan) or ...0000 (standard)
        
        target_chars = [c for c in writable_chars if "1911" in str(c.uuid) or "1912" in str(c.uuid)]
        if not target_chars:
            target_chars = writable_chars # Try everything if specific ones missed
            
        for char in target_chars:
            print(f"\n🎯 TARGETING CHARACTERISTIC: {char.uuid}")
            
            for name, packet in TEST_PACKETS:
                print(f"   Testing: {name} | Data: {packet.hex()}")
                try:
                    await client.write_gatt_char(char.uuid, packet, response=True)
                    print("     ✅ Write Success. Sending notification check...")
                    await asyncio.sleep(1.0)
                except Exception as e:
                    print(f"     ❌ Write Failed: {e}")
                    
                user_feedback = input("     Did the light change? (y/n/q): ").strip().lower()
                if user_feedback == 'y':
                    print(f"🎉 SUCCESS! Command '{name}' works on {char.uuid}")
                    out_path = OUTPUT_DIR / "working_command.txt"
                    with out_path.open("w", encoding="utf-8") as f:
                        f.write(f"MAC: {device.address}\nChar: {char.uuid}\nCmd: {name}\nHex: {packet.hex()}")
                    return
                elif user_feedback == 'q':
                    return

if __name__ == "__main__":
    asyncio.run(main())
