#!/usr/bin/env python3
"""
PROOF OF CONCEPT: BLE Mesh Pairing Test
========================================

Purpose: Validate the Telink mesh pairing protocol with a factory-reset GE Cync bulb
Status: STANDALONE POC - Does NOT modify existing architecture
Author: Reverse-engineered from GE Cync APK decompilation

Prerequisites:
1. Factory reset bulb (power cycle 5x: ON 2s, OFF 2s)
2. Device name should show as "telink_mesh1"
3. MAC address: 34:13:43:46:CA:84

Expected Outcome:
- Device accepts pairing request
- Device responds with session key
- Device name changes from "telink_mesh1" to custom mesh name
- Control commands work after pairing

Test Strategy:
- Phase 1: Connect and verify device state
- Phase 2: Send pairing messages (opcodes 0x04, 0x05, 0x06, 0x07)
- Phase 3: Validate session key and pairing success
- Phase 4: Test simple control command

If successful, this will be promoted to src/protocol/mesh_pairing.py
"""

import asyncio
import struct
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES
import sys

# ============================================================================
# CONSTANTS (From APK Decompilation)
# ============================================================================

# Device Configuration
TARGET_MAC = "34:13:43:46:CA:84"
EXPECTED_UNPAIRED_NAME = "telink_mesh1"

# BLE GATT Characteristics (Standard BLE Mesh UUIDs)
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"   # Provisioning Data In
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"  # Provisioning Data Out
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"  # Proxy Data In
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb" # Proxy Data Out

# Pairing Opcodes (From Telink.java and Opcode.java)
PAIR_NETWORK_NAME = 0x04  # Set mesh network name
PAIR_PASSWORD = 0x05      # Set mesh password
PAIR_LTK = 0x06          # Set long-term key
PAIR_CONFIRM = 0x07      # Confirm pairing

# Default Mesh Credentials (From ppbbbdb.java)
DEFAULT_MESH_NAME = "out_of_mesh"
DEFAULT_MESH_PASSWORD = "123456"
DEFAULT_NETWORK_KEY = bytes.fromhex("D00710A0A601370854E32E177AFD1159")
DEFAULT_APP_KEY = bytes.fromhex("07D01433A954A460AD1689E6594F07DA")

# ============================================================================
# HELPER FUNCTIONS (Extracted from Telink.java)
# ============================================================================

def pad_to_length(data: bytes, target_length: int, pad_byte: int = 0x00) -> bytes:
    """
    Pad data to target length with specified byte.
    Implements Telink.m602d() from decompiled code.

    If data is shorter: pad with pad_byte
    If data is longer: truncate
    """
    if len(data) < target_length:
        return data + bytes([pad_byte] * (target_length - len(data)))
    elif len(data) > target_length:
        return data[:target_length]
    return data

def reverse_bytes(data: bytes) -> bytes:
    """Reverse byte array (Telink uses reversed byte order for encryption)"""
    return bytes(reversed(data))

def aes_encrypt_telink(data: bytes, key: bytes) -> bytes:
    """
    AES/ECB/NoPadding encryption with Telink byte reversal.
    Implements Telink.m600b() from decompiled code.

    Args:
        data: 16-byte data to encrypt
        key: 16-byte AES key

    Returns:
        16-byte encrypted data
    """
    if len(data) != 16 or len(key) != 16:
        raise ValueError("Data and key must be exactly 16 bytes")

    # Reverse bytes before encryption (Telink convention)
    reversed_data = reverse_bytes(data)

    # AES/ECB/NoPadding
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(reversed_data)

    # Reverse bytes after encryption
    return reverse_bytes(encrypted)

def build_pairing_message(opcode: int, encrypted_payload: bytes) -> bytes:
    """
    Build pairing message: [opcode] + [encrypted_payload]
    Total length: 17 bytes (1 opcode + 16 encrypted data)
    """
    if len(encrypted_payload) != 16:
        raise ValueError("Encrypted payload must be 16 bytes")

    return bytes([opcode]) + encrypted_payload

# ============================================================================
# PAIRING PROTOCOL IMPLEMENTATION
# ============================================================================

class MeshPairingPOC:
    """
    Proof of Concept implementation of Telink BLE Mesh pairing protocol.
    Based on TelinkDeviceBleManager$pairMesh$2.java decompilation.
    """

    def __init__(self, mac: str, mesh_name: str = DEFAULT_MESH_NAME,
                 mesh_password: str = DEFAULT_MESH_PASSWORD):
        self.mac = mac
        self.mesh_name = mesh_name
        self.mesh_password = mesh_password
        self.session_key = None
        self.notifications = []
        self.pairing_event = asyncio.Event()

    def notification_handler(self, sender, data: bytes):
        """Handle notifications from device"""
        print(f"[NOTIFY] {sender.uuid}: {data.hex()}")
        self.notifications.append((sender.uuid, data))

        # Check for pairing response
        if len(data) > 0:
            opcode = data[0]
            if opcode in [0x04, 0x05, 0x06, 0x07]:
                print(f"  -> Pairing response opcode: 0x{opcode:02X}")
                self.pairing_event.set()

    async def get_session_key(self, client: BleakClient) -> bytes:
        """
        Get session key from device.

        In the real implementation, this would:
        1. Send initial handshake
        2. Wait for session ID response
        3. Derive session key

        For POC, we'll try different approaches:
        - Approach 1: Use device MAC as seed
        - Approach 2: Use default key
        - Approach 3: Extract from initial notification
        """
        print("\n[PHASE 2A] Attempting to derive session key...")

        # Approach 1: Try using the initial notification data
        if self.notifications:
            initial_notify = self.notifications[0][1]
            print(f"  Initial notification: {initial_notify.hex()}")

            # The notification format from device:
            # 010100efbb755d239432fc0000000032bd9bc1d371a887
            # Let's try using the last 16 bytes as potential key material
            if len(initial_notify) >= 16:
                potential_key = initial_notify[-16:]
                print(f"  Extracted potential key material: {potential_key.hex()}")
                return potential_key

        # Approach 2: Default session key (all zeros for unprovisioned device)
        default_key = bytes([0x00] * 16)
        print(f"  Using default session key: {default_key.hex()}")
        return default_key

    async def send_pairing_sequence(self, client: BleakClient, session_key: bytes):
        """
        Send complete pairing sequence to device.
        Implements the protocol from TelinkDeviceBleManager$pairMesh$2.java
        """
        print("\n[PHASE 2B] Building pairing messages...")

        # Step 1: Prepare credentials (pad to 16 bytes)
        mesh_name_bytes = self.mesh_name.encode('utf-8')
        mesh_pass_bytes = self.mesh_password.encode('utf-8')

        mesh_name_padded = pad_to_length(mesh_name_bytes, 16)
        mesh_pass_padded = pad_to_length(mesh_pass_bytes, 16)
        ltk_padded = DEFAULT_NETWORK_KEY  # Already 16 bytes

        print(f"  Mesh Name: '{self.mesh_name}' -> {mesh_name_padded.hex()}")
        print(f"  Mesh Pass: '{self.mesh_password}' -> {mesh_pass_padded.hex()}")
        print(f"  LTK: {ltk_padded.hex()}")

        # Step 2: Encrypt with session key
        print(f"\n  Encrypting with session key: {session_key.hex()}")

        encrypted_name = aes_encrypt_telink(mesh_name_padded, session_key)
        encrypted_pass = aes_encrypt_telink(mesh_pass_padded, session_key)
        encrypted_ltk = aes_encrypt_telink(ltk_padded, session_key)

        print(f"  Encrypted Name: {encrypted_name.hex()}")
        print(f"  Encrypted Pass: {encrypted_pass.hex()}")
        print(f"  Encrypted LTK:  {encrypted_ltk.hex()}")

        # Step 3: Build pairing messages
        pair_name_msg = build_pairing_message(PAIR_NETWORK_NAME, encrypted_name)
        pair_pass_msg = build_pairing_message(PAIR_PASSWORD, encrypted_pass)
        pair_ltk_msg = build_pairing_message(PAIR_LTK, encrypted_ltk)
        pair_confirm_msg = bytes([PAIR_CONFIRM])

        print(f"\n  PAIR_NETWORK_NAME (0x04): {pair_name_msg.hex()}")
        print(f"  PAIR_PASSWORD (0x05):     {pair_pass_msg.hex()}")
        print(f"  PAIR_LTK (0x06):          {pair_ltk_msg.hex()}")
        print(f"  PAIR_CONFIRM (0x07):      {pair_confirm_msg.hex()}")

        # Step 4: Send pairing sequence
        print("\n[PHASE 2C] Sending pairing sequence...")

        messages = [
            (MESH_PROXY_IN, pair_name_msg, "Network Name"),
            (MESH_PROXY_IN, pair_pass_msg, "Password"),
            (MESH_PROXY_IN, pair_ltk_msg, "LTK"),
            (MESH_PROXY_IN, pair_confirm_msg, "Confirm")
        ]

        for uuid, msg, description in messages:
            print(f"\n  Sending {description} to {uuid}...")
            try:
                await client.write_gatt_char(uuid, msg, response=False)
                print(f"  [OK] Sent {len(msg)} bytes")

                # Wait for response
                self.pairing_event.clear()
                try:
                    await asyncio.wait_for(self.pairing_event.wait(), timeout=2.0)
                    print(f"  [OK] Received response")
                except asyncio.TimeoutError:
                    print(f"  [WARN] No response (timeout)")

                await asyncio.sleep(0.2)

            except Exception as e:
                print(f"  [FAIL] Failed: {e}")
                return False

        print("\n  [OK] Pairing sequence completed")
        return True

    async def test_pairing(self):
        """Main test function"""
        print("=" * 80)
        print("GE CYNC BLE MESH PAIRING - PROOF OF CONCEPT")
        print("=" * 80)
        print(f"Target Device: {self.mac}")
        print(f"Mesh Name: {self.mesh_name}")
        print(f"Mesh Password: {self.mesh_password}")
        print("=" * 80)

        # Phase 1: Connect to device
        print("\n[PHASE 1] Connecting to device...")

        try:
            client = BleakClient(self.mac, timeout=20.0)
            await client.connect()
            print(f"[OK] Connected to {self.mac}")

            # Check device name
            device_name = client._device_info.get('name', 'Unknown') if hasattr(client, '_device_info') else 'Unknown'
            print(f"  Device Name: {device_name}")

            if EXPECTED_UNPAIRED_NAME not in device_name.lower() and device_name != 'Unknown':
                print(f"\n[WARN] WARNING: Device name is '{device_name}', expected '{EXPECTED_UNPAIRED_NAME}'")
                print(f"  Device may already be paired. Factory reset recommended.")
                response = input("\nContinue anyway? (y/n): ")
                if response.lower() != 'y':
                    await client.disconnect()
                    return

            # Subscribe to notifications
            print("\n  Subscribing to notifications...")
            for service in client.services:
                for char in service.characteristics:
                    if "notify" in char.properties:
                        try:
                            await client.start_notify(char, self.notification_handler)
                            print(f"    [OK] Subscribed to {char.uuid}")
                        except Exception as e:
                            print(f"    [FAIL] Failed to subscribe to {char.uuid}: {e}")

            # Wait for initial notification
            print("\n  Waiting for initial notification...")
            await asyncio.sleep(1.0)

            if not self.notifications:
                print("  [WARN] No initial notification received")

            # Phase 2: Send pairing sequence
            print("\n[PHASE 2] Executing pairing protocol...")

            # Get session key
            session_key = await self.get_session_key(client)
            self.session_key = session_key

            # Send pairing messages
            success = await self.send_pairing_sequence(client, session_key)

            # Phase 3: Validate pairing
            print("\n[PHASE 3] Validating pairing result...")

            if success:
                print("  [OK] Pairing messages sent successfully")

                # Wait for device to process
                print("\n  Waiting 3 seconds for device to process...")
                await asyncio.sleep(3.0)

                # Check for pairing confirmation
                pairing_responses = [n for n in self.notifications if n[1][0] in [0x04, 0x05, 0x06, 0x07]]
                print(f"\n  Received {len(pairing_responses)} pairing-related notifications")

                if pairing_responses:
                    print("  [OK] Device responded to pairing messages!")
                else:
                    print("  [WARN] No pairing responses detected")

            else:
                print("  [FAIL] Pairing failed")

            # Phase 4: Summary
            print("\n[PHASE 4] Test Summary")
            print("=" * 80)
            print(f"Connection: [OK] Success")
            print(f"Notifications: {len(self.notifications)} received")
            print(f"Pairing Messages Sent: {4 if success else 0}/4")
            print(f"Session Key: {session_key.hex()}")

            if success:
                print("\nNEXT STEPS:")
                print("1. Scan for device again - name should have changed")
                print("2. Try sending control commands with this session key")
                print("3. If successful, promote to src/protocol/mesh_pairing.py")
            else:
                print("\nTROUBLESHOOTING:")
                print("1. Verify device is factory reset (name = 'telink_mesh1')")
                print("2. Check notification responses for error codes")
                print("3. Try different session key derivation methods")

            print("=" * 80)

            # Cleanup
            await client.disconnect()
            print("\n[OK] Disconnected")

        except Exception as e:
            print(f"\n[FAIL] Error: {e}")
            import traceback
            traceback.print_exc()

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def main():
    """Run POC test"""

    print("\n" + "=" * 80)
    print("PREREQUISITES CHECK")
    print("=" * 80)
    print("Before running this test, ensure:")
    print("1. [OK] Bulb is factory reset (power cycle 5x: ON 2s, OFF 2s)")
    print("2. [OK] Device name shows as 'telink_mesh1' when scanned")
    print("3. [OK] Device MAC is 34:13:43:46:CA:84")
    print("=" * 80)

    response = input("\nAre all prerequisites met? (y/n): ")
    if response.lower() != 'y':
        print("\nPlease complete prerequisites first.")
        print("\nFactory Reset Instructions:")
        print("1. Turn bulb ON for 2 seconds")
        print("2. Turn bulb OFF for 2 seconds")
        print("3. Repeat steps 1-2 four more times (5 cycles total)")
        print("4. Bulb should flash to confirm reset")
        print("5. Scan for device - name should be 'telink_mesh1'")
        return

    # Run test
    poc = MeshPairingPOC(TARGET_MAC)
    await poc.test_pairing()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(0)
