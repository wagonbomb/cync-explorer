"""Quick scan to see device advertisement data after reset"""
import asyncio
from bleak import BleakScanner

async def main():
    print("Scanning for Cync devices...\n")
    
    devices = await BleakScanner.discover(timeout=10.0)
    
    for d in devices:
        if "34:13:43:46:CA:84" in str(d.address) or "C by GE" in str(d.name) or "cync" in str(d.name).lower():
            print(f"Address: {d.address}")
            print(f"Name: {d.name}")
            print(f"RSSI: {d.rssi}")
            print(f"Details: {d.details}")
            if hasattr(d, 'metadata'):
                print(f"Metadata: {d.metadata}")
            print("\n")

if __name__ == "__main__":
    asyncio.run(main())
