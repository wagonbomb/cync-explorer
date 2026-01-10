"""
Cync Provisioning Implementation
Based on reverse engineering analysis and HCI logs

This implements the provisioning protocol observed in the Android HCI logs
"""

import asyncio
from bleak import BleakClient, BleakScanner
import struct

# Known UUIDs from our testing
MESH_PROV_IN = "000102030405060708090a0b0c0d2b11"
MESH_PROV_OUT = "000102030405060708090a0b0c0d2b12"
MESH_PROXY_IN = "000102030405060708090a0b0c0d2b10"
MESH_PROXY_OUT = "000102030405060708090a0b0c0d2b13"
TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"
TELINK_STATUS = "00010203-0405-0607-0809-0a0b0c0d1914"

TARGET_MAC = "34:13:43:46:CA:84"

class CyncProvisioner:
    def __init__(self, mac_address):
        self.mac = mac_address
        self.client = None
        self.responses = []
       
    async def connect(self):
        """Connect to device"""
        print(f"Connecting to {self.mac}...")
        self.client = BleakClient(self.mac)
        await self.client.connect()
        print("Connected!")
        return True
       
    async def setup_notifications(self):
        """Subscribe to all notification characteristics"""
        print("Setting up notifications...")
       
        characteristics = {
            MESH_PROV_OUT: "Mesh Prov Out",
            MESH_PROXY_OUT: "Mesh Proxy Out",
            TELINK_STATUS: "Telink Status",
        }
       
        for uuid, name in characteristics.items():
            try:
                await self.client.start_notify(uuid, self._notification_handler)
                print(f"  ✓ Subscribed to {name}")
            except Exception as e:
                print(f"  ✗ Failed to subscribe to {name}: {e}")
               
    def _notification_handler(self, sender, data):
        """Handle incoming notifications"""
        hex_data = data.hex()
        print(f"<< NOTIFICATION: {hex_data}")
        self.responses.append(data)
       
    async def send_command(self, uuid, data_hex, wait_response=True):
        """Send command and optionally wait for response"""
        data = bytes.fromhex(data_hex)
        print(f">> SEND to {uuid[:8]}...: {data_hex}")
       
        await self.client.write_gatt_char(uuid, data, response=False)
       
        if wait_response:
            await asyncio.sleep(0.5)  # Wait for potential response
           
    async def provision_standard_telink(self):
        """Try standard Telink mesh provisioning"""
        print("\n=== STANDARD TELINK PROVISIONING ===\n")
       
        # Password: "123" encoded
        password = "313233".ljust(32, '0')  # Pad to 16 bytes
       
        # Telink provisioning commands
        commands = [
            (MESH_PROV_IN, "00" + password),  # Login with password
            (MESH_PROV_IN, "0c000000000000000000000000000000"),  # Set network key?
        ]
       
        for uuid, cmd in commands:
            await self.send_command(uuid, cmd)
            await asyncio.sleep(1)
           
    async def provision_from_hci_logs(self):
        """Attempt provisioning using exact sequence from HCI logs"""
        print("\n=== HCI LOG-BASED PROVISIONING ===\n")
       
        # These are the commands we saw in working Android session
        # They may be session-specific but worth trying
        hci_sequence = [
            # Initial handshake
            ("000501000000000000000000", "Handshake init"),
            ("00000100000000000000040000", "Session start?"),
            ("3100", "Key exchange 1"),
            ("3101", "Key exchange 2"),
            ("3102", "Key exchange 3"),
            ("3103", "Key exchange 4"),
            ("3104", "Key exchange 5"),
            ("320119000000", "Finalize"),
        ]
       
        for cmd_hex, description in hci_sequence:
            print(f"\n{description}:")
            await self.send_command(MESH_PROXY_IN, cmd_hex)
            await asyncio.sleep(1)
           
    async def provision_cync_specific(self):
        """Try Cync-specific provisioning sequences"""
        print("\n=== CYNC-SPECIFIC PROVISIONING ===\n")
       
        # Based on analysis, try common patterns
        cync_attempts = [
            # Attempt 1: Cync mesh init
            (MESH_PROV_IN, "0000000000000000000000000000"),
            # Attempt 2: Device ID based auth
            (MESH_PROV_IN, "34134346CA84" + "00" * 10),
            # Attempt 3: Default Cync password
            (MESH_PROV_IN, "63796e63" + "00" * 12),  # "cync" in hex
        ]
       
        for i, (uuid, cmd) in enumerate(cync_attempts, 1):
            print(f"\nAttempt {i}:")
            await self.send_command(uuid, cmd)
            await asyncio.sleep(1.5)
           
    async def test_control(self):
        """Test if we can control the light after provisioning"""
        print("\n=== TESTING CONTROL ===\n")
       
        test_commands = [
            ("Telink ON", TELINK_CMD, "7e0704100001010069"),
            ("Telink OFF", TELINK_CMD, "7e0704100001000068"),
            ("Mesh ON", MESH_PROXY_IN, "b0c001"),
            ("Mesh OFF", MESH_PROXY_IN, "b0c000"),
        ]
       
        for name, uuid, cmd in test_commands:
            print(f"\n{name}:")
            await self.send_command(uuid, cmd)
            await asyncio.sleep(2)
            print("  (Check if light changed physically)")
           
    async def run_full_provision_sequence(self):
        """Run complete provisioning attempt"""
        try:
            await self.connect()
            await self.setup_notifications()
           
            # Try all provisioning methods
            await self.provision_standard_telink()
            await asyncio.sleep(2)
           
            await self.provision_from_hci_logs()
            await asyncio.sleep(2)
           
            await self.provision_cync_specific()
            await asyncio.sleep(2)
           
            # Test if any worked
            await self.test_control()
           
        except Exception as e:
            print(f"\nError: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.client and self.client.is_connected:
                await self.client.disconnect()
                print("\nDisconnected")

async def main():
    print("="*80)
    print("CYNC PROVISIONING TEST")
    print("="*80)
    print(f"\nTarget: {TARGET_MAC}")
    print("\nThis will attempt multiple provisioning methods:")
    print("1. Standard Telink mesh provisioning")
    print("2. Commands from Android HCI logs")
    print("3. Cync-specific sequences")
    print("\nWatch the physical light for any changes!")
    print("="*80)
   
    provisioner = CyncProvisioner(TARGET_MAC)
    await provisioner.run_full_provision_sequence()
   
    print("\n" + "="*80)
    print("PROVISIONING TEST COMPLETE")
    print(f"Total responses received: {len(provisioner.responses)}")
    print("="*80)

if __name__ == "__main__":
    asyncio.run(main())
