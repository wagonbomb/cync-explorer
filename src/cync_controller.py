"""
GE Cync Light Controller
Attempts to control a Cync light via BLE by writing to discovered characteristics.
"""

import asyncio
import sys
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from datetime import datetime


class CyncLightController:
    """Controller for GE Cync lights via BLE."""
    
    # Common UUIDs found in smart bulbs (we'll discover the actual ones)
    # These are placeholders - the GATT explorer will help us find the real ones
    POTENTIAL_CONTROL_UUIDS = [
        "0000fee9-0000-1000-8000-00805f9b34fb",  # Telink light control
        "0000fff3-0000-1000-8000-00805f9b34fb",  # Common control UUID
        "0000fff1-0000-1000-8000-00805f9b34fb",  # Common control UUID
    ]
    
    def __init__(self, address: str):
        """
        Initialize controller with device MAC address.
        
        Args:
            address: MAC address of the Cync light
        """
        # Normalize MAC address
        addr_normalized = address.replace(":", "").replace("-", "").upper()
        self.address = ":".join(addr_normalized[i:i+2] for i in range(0, 12, 2))
        self.client = None
        self.connected = False
        self.control_char = None
        self.writable_chars = []
    
    async def connect(self):
        """Connect to the light."""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Connecting to {self.address}...")
        
        device = await BleakScanner.find_device_by_address(self.address, timeout=15.0)
        if not device:
            # Try with dashes
            addr_dashed = self.address.replace(":", "-")
            device = await BleakScanner.find_device_by_address(addr_dashed, timeout=10.0)
        
        if not device:
            raise Exception(f"Device {self.address} not found")
        
        self.client = BleakClient(device, timeout=30.0)
        await self.client.connect()
        self.connected = True
        print(f"✅ Connected to {device.name or self.address}")
        
        # Find writable characteristics
        await self._discover_writable_chars()
        
        return self
    
    async def _discover_writable_chars(self):
        """Discover all writable characteristics."""
        self.writable_chars = []
        
        for service in self.client.services:
            for char in service.characteristics:
                if "write" in char.properties or "write-without-response" in char.properties:
                    self.writable_chars.append({
                        "uuid": str(char.uuid),
                        "handle": char.handle,
                        "properties": char.properties
                    })
        
        print(f"Found {len(self.writable_chars)} writable characteristics")
        for wc in self.writable_chars:
            print(f"   - {wc['uuid']}: {', '.join(wc['properties'])}")
    
    async def disconnect(self):
        """Disconnect from the light."""
        if self.client and self.connected:
            await self.client.disconnect()
            self.connected = False
            print("Disconnected")
    
    async def write_to_characteristic(self, uuid: str, data: bytes, with_response: bool = True):
        """
        Write data to a specific characteristic.
        
        Args:
            uuid: The characteristic UUID to write to
            data: The data to write
            with_response: Whether to wait for write response
        """
        if not self.connected:
            raise Exception("Not connected")
        
        try:
            await self.client.write_gatt_char(uuid, data, response=with_response)
            print(f"✅ Wrote {data.hex()} to {uuid}")
            return True
        except BleakError as e:
            print(f"❌ Write failed: {e}")
            return False
    
    async def try_common_on_off_commands(self, char_uuid: str):
        """
        Try common on/off command patterns on a characteristic.
        
        Many BLE bulbs use simple byte patterns like:
        - 0x01 for ON, 0x00 for OFF
        - 0x7e0004010100ff00ef for ON patterns
        - Various proprietary formats
        
        Args:
            char_uuid: The characteristic UUID to test
        """
        print(f"\n🔬 Testing common commands on {char_uuid}")
        
        # Common ON patterns
        on_patterns = [
            bytes([0x01]),
            bytes([0x01, 0x01]),
            bytes([0x7e, 0x00, 0x04, 0x01, 0x01, 0x00, 0xff, 0x00, 0xef]),  # Common RGB format
            bytes([0x43, 0x01]),  # Another common format
        ]
        
        # Common OFF patterns
        off_patterns = [
            bytes([0x00]),
            bytes([0x01, 0x00]),
            bytes([0x7e, 0x00, 0x04, 0x00, 0x01, 0x00, 0xff, 0x00, 0xef]),
            bytes([0x43, 0x00]),
        ]
        
        print("Testing ON patterns...")
        for i, pattern in enumerate(on_patterns):
            print(f"  Pattern {i+1}: {pattern.hex()}")
            try:
                await self.write_to_characteristic(char_uuid, pattern, with_response=False)
                await asyncio.sleep(1.0)  # Wait to see effect
                response = input("  Did the light turn ON? (y/n): ")
                if response.lower() == 'y':
                    print(f"  ✅ Found ON pattern: {pattern.hex()}")
                    return {"on": pattern}
            except Exception as e:
                print(f"  Failed: {e}")
        
        return None
    
    async def interactive_test(self):
        """Interactive testing mode to discover control commands."""
        if not self.writable_chars:
            print("No writable characteristics found!")
            return
        
        print("\n" + "=" * 60)
        print("INTERACTIVE TESTING MODE")
        print("=" * 60)
        print("\nWritable characteristics:")
        for i, wc in enumerate(self.writable_chars):
            print(f"  {i+1}. {wc['uuid']}")
        
        while True:
            print("\nOptions:")
            print("  1. Write hex data to a characteristic")
            print("  2. Try common ON/OFF patterns")
            print("  3. List characteristics")
            print("  4. Read from a characteristic")
            print("  q. Quit")
            
            choice = input("\nChoice: ").strip()
            
            if choice == 'q':
                break
            elif choice == '1':
                idx = int(input("Characteristic number: ")) - 1
                if 0 <= idx < len(self.writable_chars):
                    hex_data = input("Hex data (e.g., 01ff00): ").strip()
                    try:
                        data = bytes.fromhex(hex_data)
                        await self.write_to_characteristic(
                            self.writable_chars[idx]['uuid'], 
                            data, 
                            with_response=False
                        )
                    except ValueError:
                        print("Invalid hex data")
            elif choice == '2':
                idx = int(input("Characteristic number: ")) - 1
                if 0 <= idx < len(self.writable_chars):
                    await self.try_common_on_off_commands(self.writable_chars[idx]['uuid'])
            elif choice == '3':
                for i, wc in enumerate(self.writable_chars):
                    print(f"  {i+1}. {wc['uuid']}: {', '.join(wc['properties'])}")
            elif choice == '4':
                # Find readable chars
                for service in self.client.services:
                    for char in service.characteristics:
                        if "read" in char.properties:
                            try:
                                value = await self.client.read_gatt_char(char.uuid)
                                print(f"  {char.uuid}: {value.hex()}")
                            except:
                                pass


async def main():
    if len(sys.argv) < 2:
        print("Usage: python cync_controller.py <MAC_ADDRESS>")
        print("Example: python cync_controller.py 34:13:43:46:CA:85")
        return
    
    address = sys.argv[1]
    controller = CyncLightController(address)
    
    try:
        await controller.connect()
        await controller.interactive_test()
    finally:
        await controller.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
