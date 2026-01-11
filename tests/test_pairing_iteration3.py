#!/usr/bin/env python3
"""
POC Iteration 3: Handshake THEN Pairing
Theory: Device needs handshake to "wake up" before accepting pairing messages
"""

import asyncio
from bleak import BleakClient
from Crypto.Cipher import AES

TARGET_MAC = "34:13:43:46:CA:84"
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

class PairingIteration3:
    def __init__(self):
        self.notifications = []

    def notification_handler(self, sender, data):
        print(f"[NOTIFY] {sender.uuid}: {data.hex()}")
        self.notifications.append((sender.uuid, data))

    def pad_to_length(self, data: bytes, target_length: int, pad_byte: int = 0x00) -> bytes:
        if len(data) < target_length:
            return data + bytes([pad_byte] * (target_length - len(data)))
        elif len(data) > target_length:
            return data[:target_length]
        return data

    def reverse_bytes(self, data: bytes) -> bytes:
        return bytes(reversed(data))

    def aes_encrypt_telink(self, data: bytes, key: bytes) -> bytes:
        if len(data) != 16 or len(key) != 16:
            raise ValueError("Data and key must be exactly 16 bytes")
        reversed_data = self.reverse_bytes(data)
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(reversed_data)
        return self.reverse_bytes(encrypted)

    async def step1_handshake_knock(self, client):
        """Send handshake sequence to wake up device notifications"""
        print("\n[STEP 1] Handshake Knock - Wake Up Device")
        print("  Theory: Device needs handshake before it responds")

        # From old working HCI logs (when device was paired)
        handshake_start = bytes.fromhex("000501000000000000000000")
        key_exchange = bytes.fromhex("000001000000000000040000")

        # Send to both UUIDs
        for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
            try:
                await client.write_gatt_char(uuid, handshake_start, response=False)
                print(f"  Sent handshake_start to {uuid[-4:]}: {handshake_start.hex()}")
            except Exception as e:
                print(f"  [FAIL] {e}")

        await asyncio.sleep(0.5)

        for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
            try:
                await client.write_gatt_char(uuid, key_exchange, response=False)
                print(f"  Sent key_exchange to {uuid[-4:]}: {key_exchange.hex()}")
            except Exception as e:
                print(f"  [FAIL] {e}")

        await asyncio.sleep(1.0)

        if len(self.notifications) > 0:
            print(f"  [SUCCESS] Got {len(self.notifications)} responses!")
            return True
        else:
            print(f"  [WARN] No responses (expected for unpaired device)")
            return False

    async def step2_send_pairing(self, client, session_key):
        """Send pairing messages with encryption"""
        print("\n[STEP 2] Send Pairing Messages")

        mesh_name = b"out_of_mesh"
        mesh_pass = b"123456"
        default_ltk = bytes.fromhex("D00710A0A601370854E32E177AFD1159")

        # Pad to 16 bytes
        mesh_name_padded = self.pad_to_length(mesh_name, 16)
        mesh_pass_padded = self.pad_to_length(mesh_pass, 16)
        ltk_padded = default_ltk

        print(f"  Mesh Name: {mesh_name_padded.hex()}")
        print(f"  Mesh Pass: {mesh_pass_padded.hex()}")
        print(f"  Session Key: {session_key.hex()}")

        # Encrypt
        encrypted_name = self.aes_encrypt_telink(mesh_name_padded, session_key)
        encrypted_pass = self.aes_encrypt_telink(mesh_pass_padded, session_key)
        encrypted_ltk = self.aes_encrypt_telink(ltk_padded, session_key)

        # Build messages
        pair_name_msg = bytes([0x04]) + encrypted_name
        pair_pass_msg = bytes([0x05]) + encrypted_pass
        pair_ltk_msg = bytes([0x06]) + encrypted_ltk
        pair_confirm_msg = bytes([0x07])

        messages = [
            (pair_name_msg, "Network Name"),
            (pair_pass_msg, "Password"),
            (pair_ltk_msg, "LTK"),
            (pair_confirm_msg, "Confirm")
        ]

        for msg, desc in messages:
            try:
                await client.write_gatt_char(MESH_PROXY_IN, msg, response=False)
                print(f"  Sent {desc}: {msg.hex()}")
                await asyncio.sleep(0.3)
            except Exception as e:
                print(f"  [FAIL] {desc}: {e}")

        await asyncio.sleep(1.0)

        new_notifications = [n for n in self.notifications if n[1][0] in [0x04, 0x05, 0x06, 0x07]]
        if new_notifications:
            print(f"  [SUCCESS] Got {len(new_notifications)} pairing responses!")
            return True
        else:
            print(f"  [WARN] No pairing responses")
            return False

    async def step3_try_control_command(self, client):
        """Try sending a simple control command to test if pairing worked"""
        print("\n[STEP 3] Test Control Command (Power ON)")

        # Simple unencrypted ON command (legacy format)
        legacy_on = bytes.fromhex("7e0004010100ff00ef")

        try:
            await client.write_gatt_char(MESH_PROXY_IN, legacy_on, response=False)
            print(f"  Sent legacy ON command: {legacy_on.hex()}")
            await asyncio.sleep(1.0)

            if len(self.notifications) > len([n for n in self.notifications if n[1][0] in [0x04, 0x05, 0x06, 0x07]]):
                print(f"  [SUCCESS] Device responded to control command!")
                return True
            else:
                print(f"  [WARN] No response to control command")
                return False
        except Exception as e:
            print(f"  [FAIL] {e}")
            return False

    async def run_test(self):
        print("=" * 80)
        print("PAIRING POC - ITERATION 3")
        print("Approach: Handshake THEN Pairing")
        print("=" * 80)

        try:
            client = BleakClient(TARGET_MAC, timeout=20.0)
            await client.connect()
            print(f"[OK] Connected to {TARGET_MAC}")

            # Subscribe to notifications
            print("\nSubscribing to notifications...")
            for service in client.services:
                for char in service.characteristics:
                    if "notify" in char.properties:
                        try:
                            await client.start_notify(char, self.notification_handler)
                            print(f"  [OK] {char.uuid}")
                        except: pass

            await asyncio.sleep(0.5)

            # Step 1: Handshake knock
            handshake_worked = await self.step1_handshake_knock(client)

            # Extract session key if we got a response
            session_key = bytes([0x00] * 16)  # Default
            if self.notifications:
                # Try to extract from response
                for uuid, data in self.notifications:
                    if len(data) >= 16:
                        session_key = data[-16:]
                        print(f"\n  [INFO] Extracted potential session key: {session_key.hex()}")
                        break

            # Step 2: Send pairing
            pairing_worked = await self.step2_send_pairing(client, session_key)

            # Step 3: Try control command
            control_worked = await self.step3_try_control_command(client)

            # Summary
            print("\n" + "=" * 80)
            print("TEST SUMMARY")
            print("=" * 80)
            print(f"Step 1 - Handshake: {'[OK]' if handshake_worked else '[WARN]'}")
            print(f"Step 2 - Pairing:   {'[OK]' if pairing_worked else '[WARN]'}")
            print(f"Step 3 - Control:   {'[OK]' if control_worked else '[WARN]'}")
            print(f"\nTotal Notifications: {len(self.notifications)}")

            if self.notifications:
                print("\nAll Notifications:")
                for i, (uuid, data) in enumerate(self.notifications, 1):
                    print(f"  {i}. {uuid}: {data.hex()}")

            if pairing_worked or control_worked:
                print("\n[SUCCESS] Device responded! Check if light changed state.")
            else:
                print("\n[CRITICAL] Device still not responding.")
                print("Next steps:")
                print("  1. Try using official GE Cync app to pair")
                print("  2. Capture HCI logs during app pairing")
                print("  3. Compare exact byte sequences")

            print("=" * 80)

            await client.disconnect()

        except Exception as e:
            print(f"\n[FAIL] Error: {e}")
            import traceback
            traceback.print_exc()

async def main():
    poc = PairingIteration3()
    await poc.run_test()

if __name__ == "__main__":
    asyncio.run(main())
