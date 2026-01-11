#!/usr/bin/env python3
"""
POC Iteration 2: Alternative Pairing Approaches
Based on first test results: device accepts writes but doesn't respond
"""

import asyncio
from bleak import BleakClient
from Crypto.Cipher import AES

TARGET_MAC = "34:13:43:46:CA:84"
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

class PairingIteration2:
    def __init__(self):
        self.notifications = []

    def notification_handler(self, sender, data):
        print(f"[NOTIFY] {sender.uuid}: {data.hex()}")
        self.notifications.append((sender.uuid, data))

    async def approach_1_provisioning_uuid(self, client):
        """Try sending pairing messages to MESH_PROV_IN instead of MESH_PROXY_IN"""
        print("\n[APPROACH 1] Send pairing to MESH_PROV_IN (Provisioning UUID)")
        print("  Theory: Unprovisioned devices may expect pairing on provisioning UUID")

        # Use session key from any initial notification, or default
        session_key = bytes([0x00] * 16)

        # Simple provisioning invite
        invite = bytes([0x00])  # BLE Mesh Provisioning Invite

        try:
            await client.write_gatt_char(MESH_PROV_IN, invite, response=False)
            print(f"  Sent provisioning invite to PROV_IN: {invite.hex()}")
            await asyncio.sleep(1.0)

            if self.notifications:
                print(f"  [OK] Received {len(self.notifications)} responses!")
                return True
            else:
                print("  [WARN] No response")
                return False
        except Exception as e:
            print(f"  [FAIL] Error: {e}")
            return False

    async def approach_2_unencrypted_pairing(self, client):
        """Try sending pairing credentials UNENCRYPTED"""
        print("\n[APPROACH 2] Send UNENCRYPTED pairing credentials")
        print("  Theory: Fresh devices may accept plaintext before encryption established")

        mesh_name = b"out_of_mesh" + bytes([0x00] * 5)  # Pad to 16 bytes
        mesh_pass = b"123456" + bytes([0x00] * 10)

        # Opcode + unencrypted data
        name_msg = bytes([0x04]) + mesh_name
        pass_msg = bytes([0x05]) + mesh_pass

        try:
            for msg, desc in [(name_msg, "name"), (pass_msg, "password")]:
                await client.write_gatt_char(MESH_PROXY_IN, msg, response=False)
                print(f"  Sent {desc}: {msg.hex()}")
                await asyncio.sleep(0.5)

            if len(self.notifications) > 0:
                print(f"  [OK] Received {len(self.notifications)} responses!")
                return True
            else:
                print("  [WARN] No responses")
                return False
        except Exception as e:
            print(f"  [FAIL] Error: {e}")
            return False

    async def approach_3_simple_commands(self, client):
        """Try simple mesh commands to see if device responds at all"""
        print("\n[APPROACH 3] Send simple test commands")
        print("  Theory: Check if device responds to ANY commands")

        test_commands = [
            (bytes([0x00, 0x00]), "Null command"),
            (bytes([0xD0, 0x01]), "Query status"),
            (bytes([0xE0, 0x00]), "Test ping"),
        ]

        for cmd, desc in test_commands:
            try:
                await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
                print(f"  Sent {desc}: {cmd.hex()}")
                await asyncio.sleep(0.3)
            except Exception as e:
                print(f"  [FAIL] {desc}: {e}")

        if len(self.notifications) > 0:
            print(f"  [OK] Received {len(self.notifications)} responses!")
            return True
        else:
            print("  [WARN] No responses to any test commands")
            return False

    async def approach_4_reconnect_check(self, client):
        """Disconnect and reconnect to see if device state changed"""
        print("\n[APPROACH 4] Reconnect to check device state")
        print("  Theory: Device may have processed pairing but needs reconnection")

        await client.disconnect()
        print("  Disconnected")
        await asyncio.sleep(2.0)

        await client.connect()
        print("  Reconnected")
        await asyncio.sleep(1.0)

        # Re-subscribe
        for service in client.services:
            for char in service.characteristics:
                if "notify" in char.properties:
                    try:
                        await client.start_notify(char, self.notification_handler)
                    except: pass

        await asyncio.sleep(1.0)

        if len(self.notifications) > 0:
            print(f"  [OK] Received {len(self.notifications)} notifications after reconnect!")
            return True
        else:
            print("  [WARN] Still no notifications")
            return False

    async def run_all_approaches(self):
        print("=" * 80)
        print("PAIRING POC - ITERATION 2")
        print("Testing alternative approaches based on Iteration 1 results")
        print("=" * 80)

        try:
            client = BleakClient(TARGET_MAC, timeout=20.0)
            await client.connect()
            print(f"[OK] Connected to {TARGET_MAC}\n")

            # Subscribe to notifications
            for service in client.services:
                for char in service.characteristics:
                    if "notify" in char.properties:
                        try:
                            await client.start_notify(char, self.notification_handler)
                            print(f"Subscribed to {char.uuid}")
                        except: pass

            await asyncio.sleep(1.0)
            print(f"\nInitial notifications: {len(self.notifications)}")

            # Try all approaches
            approaches = [
                self.approach_1_provisioning_uuid,
                self.approach_2_unencrypted_pairing,
                self.approach_3_simple_commands,
                self.approach_4_reconnect_check
            ]

            for approach in approaches:
                notification_count_before = len(self.notifications)
                await approach(client)
                new_notifications = len(self.notifications) - notification_count_before

                if new_notifications > 0:
                    print(f"\n[SUCCESS] This approach got {new_notifications} responses!")
                    print("  Notification details:")
                    for uuid, data in self.notifications[notification_count_before:]:
                        print(f"    {uuid}: {data.hex()}")

                await asyncio.sleep(1.0)

            # Summary
            print("\n" + "=" * 80)
            print("SUMMARY")
            print("=" * 80)
            print(f"Total notifications received: {len(self.notifications)}")

            if self.notifications:
                print("\nAll notifications:")
                for i, (uuid, data) in enumerate(self.notifications, 1):
                    print(f"  {i}. {uuid}: {data.hex()}")
            else:
                print("\n[CRITICAL] Device still not responding to any approach")
                print("This suggests:")
                print("  1. Device may not be in proper pairing mode")
                print("  2. May need specific provisioning sequence we haven't found")
                print("  3. GE Cync may use completely custom provisioning")

            print("=" * 80)

            await client.disconnect()

        except Exception as e:
            print(f"\n[FAIL] Error: {e}")
            import traceback
            traceback.print_exc()

async def main():
    poc = PairingIteration2()
    await poc.run_all_approaches()

if __name__ == "__main__":
    asyncio.run(main())
