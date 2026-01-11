#!/usr/bin/env python3
"""
GE Cync BLE Protocol Implementation

Based on reverse engineering of GE Cync APK and libBleLib.so:
- Uses BLE Mesh Proxy/Provisioning UUIDs
- Session ID received during handshake
- Commands use session-derived prefix + DP encoding

Protocol Flow:
1. Connect to bulb
2. Subscribe to notifications on all notify characteristics
3. Send handshake start (000501...) to Mesh Prov + Proxy In
4. Send key exchange (000001...040000) to Mesh Prov + Proxy In
5. Wait for session ID response (04 00 00 XX)
6. Send sync sequence (31 00 through 31 04) to Mesh Proxy In
7. Send auth finalize (320119000000) to Mesh Proxy In
8. Calculate prefix from session ID and send commands
"""

import asyncio
from bleak import BleakClient, BleakScanner
from collections import deque
from typing import Optional

# Target device
TARGET_MAC = "34:13:43:46:CA:84"

# BLE Mesh UUIDs (Standard Bluetooth SIG)
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"   # Mesh Provisioning In
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"  # Mesh Provisioning Out
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"  # Mesh Proxy In
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb" # Mesh Proxy Out

# Telink Custom UUIDs (fallback)
TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"
TELINK_STATUS = "00010203-0405-0607-0809-0a0b0c0d1911"

# Protocol Constants (from HCI log analysis)
HANDSHAKE_START = bytes([0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
KEY_EXCHANGE_04 = bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00])
KEY_EXCHANGE_16 = bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00])
AUTH_FINALIZE = bytes([0x32, 0x01, 0x19, 0x00, 0x00, 0x00])

class CyncProtocol:
    """GE Cync BLE Protocol Handler using Mesh Protocol"""

    def __init__(self, client: BleakClient):
        self.client = client
        self.session_id: Optional[int] = None
        self.cmd_prefix: Optional[int] = None
        self.handshake_event = asyncio.Event()
        self.handshake_data = None
        self.last_notifies = deque(maxlen=50)

    def _notification_handler(self, sender, data):
        """Handle notifications from device"""
        print(f"  [NOTIFY] {sender}: {data.hex()}")
        self.last_notifies.append((sender, data))
        # Look for session ID response pattern: 04 00 00 XX
        if b"\x04\x00\x00" in data:
            self.handshake_data = data
            self.handshake_event.set()

    async def start_notifications(self):
        """Subscribe to all notify characteristics"""
        for service in self.client.services:
            for char in service.characteristics:
                if "notify" in char.properties:
                    try:
                        await self.client.start_notify(char, self._notification_handler)
                        print(f"  [OK] Listening on {char.uuid}")
                    except Exception as e:
                        print(f"  [WARN] Could not subscribe to {char.uuid}: {e}")

    async def wait_for_response(self, timeout: float = 2.0) -> Optional[bytes]:
        """Wait for a notification response"""
        initial_count = len(self.last_notifies)
        try:
            for _ in range(int(timeout * 10)):  # Check every 0.1s
                await asyncio.sleep(0.1)
                if len(self.last_notifies) > initial_count:
                    # Get the latest notification
                    return self.last_notifies[-1][1]
        except:
            pass
        return None

    async def handshake(self) -> bool:
        """
        Perform mesh handshake following exact HCI sequence:
        TX: 000501000000000000000000 -> RX: 00060100000000000000000001
        TX: 00000100000000000000040000 -> RX: 00010100000000000000040000310001
        TX: 3100 -> RX: 3100d2b77b0a
        TX: 3101 -> RX: 3101000344
        TX: 3102 -> RX: 3102010202
        TX: 3103 -> RX: 3103300fac06df7eb4ce
        TX: 3104 -> RX: 31041e99e41b1991b80c380bd445585609da
        TX: 00000100000000000000160000 -> RX: 00010100000000000000160000320000
        TX: 320119000000 -> RX: 320200
        """
        print("\n[STEP 1] Sending Handshake Start...")

        try:
            await self.client.write_gatt_char(MESH_PROXY_IN, HANDSHAKE_START, response=False)
            print(f"  TX: {HANDSHAKE_START.hex()}")
        except Exception as e:
            print(f"  [ERROR] Failed: {e}")
            return False

        resp = await self.wait_for_response(1.0)
        if resp:
            print(f"  RX: {resp.hex()}")

        print("\n[STEP 2] Sending Key Exchange (04)...")
        try:
            await self.client.write_gatt_char(MESH_PROXY_IN, KEY_EXCHANGE_04, response=False)
            print(f"  TX: {KEY_EXCHANGE_04.hex()}")
        except Exception as e:
            print(f"  [ERROR] Failed: {e}")
            return False

        resp = await self.wait_for_response(1.0)
        if resp:
            print(f"  RX: {resp.hex()}")
            # Look for session ID in response (pattern: ...310001)
            if b"\x31" in resp:
                idx = resp.find(b"\x31")
                if len(resp) > idx + 2:
                    self.session_id = resp[idx + 2]
                    print(f"  [OK] Session ID from response: 0x{self.session_id:02X}")

        print("\n[STEP 3] Sending Sync Sequence...")
        for i in range(5):
            sync_pkt = bytes([0x31, i])
            try:
                await self.client.write_gatt_char(MESH_PROXY_IN, sync_pkt, response=False)
                print(f"  TX: {sync_pkt.hex()}", end="")
            except Exception as e:
                print(f"  [ERROR] Sync {i} failed: {e}")
                continue

            resp = await self.wait_for_response(0.5)
            if resp:
                print(f" -> RX: {resp.hex()}")
            else:
                print(" -> (no response)")

        print("\n[STEP 4] Sending Key Exchange (16)...")
        try:
            await self.client.write_gatt_char(MESH_PROXY_IN, KEY_EXCHANGE_16, response=False)
            print(f"  TX: {KEY_EXCHANGE_16.hex()}")
        except Exception as e:
            print(f"  [ERROR] Failed: {e}")
            return False

        resp = await self.wait_for_response(1.0)
        if resp:
            print(f"  RX: {resp.hex()}")

        print("\n[STEP 5] Sending Auth Finalize...")
        try:
            await self.client.write_gatt_char(MESH_PROXY_IN, AUTH_FINALIZE, response=False)
            print(f"  TX: {AUTH_FINALIZE.hex()}")
        except Exception as e:
            print(f"  [ERROR] Auth finalize failed: {e}")
            return False

        resp = await self.wait_for_response(1.0)
        if resp:
            print(f"  RX: {resp.hex()}")

        await asyncio.sleep(0.3)

        # Use default session ID if not captured
        if self.session_id is None:
            self.session_id = 0x01

        # Calculate command prefix: (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
        self.cmd_prefix = (((self.session_id & 0x0F) + 0x0A) << 4) & 0xFF
        print(f"\n[OK] Handshake Complete!")
        print(f"  Session ID: 0x{self.session_id:02X}")
        print(f"  Command Prefix: 0x{self.cmd_prefix:02X}")
        return True

    def build_dp_command(self, dp_id: int, dp_type: int, value: bytes) -> bytes:
        """
        Build a Data Point (DP) command with session prefix

        DP format: [prefix][0xC0][dp_id][dp_type][len][value...]
        """
        if self.cmd_prefix is None:
            raise ValueError("Handshake not completed")

        dp_packet = bytes([self.cmd_prefix, 0xC0, dp_id, dp_type, len(value)]) + value
        return dp_packet

    async def send_command(self, cmd: bytes) -> bool:
        """Send command via multiple paths for reliability"""
        print(f"  Sending: {cmd.hex()}")
        try:
            await self.client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
            await self.client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
            return True
        except Exception as e:
            print(f"  [ERROR] Send failed: {e}")
            return False

    async def turn_on(self) -> bool:
        """Turn light on"""
        print("\n[COMMAND] Turn ON")
        # DP1 (power) = True, Type BOOL (1), Value 1
        cmd = self.build_dp_command(1, 1, bytes([1]))
        return await self.send_command(cmd)

    async def turn_off(self) -> bool:
        """Turn light off"""
        print("\n[COMMAND] Turn OFF")
        # DP1 (power) = False, Type BOOL (1), Value 0
        cmd = self.build_dp_command(1, 1, bytes([0]))
        return await self.send_command(cmd)

    async def set_brightness(self, percent: int) -> bool:
        """Set brightness (0-100%)"""
        print(f"\n[COMMAND] Set brightness to {percent}%")
        # Convert 0-100% to 0-255
        level = int((percent / 100.0) * 255)
        # DP2 (brightness) = value, Type VALUE (2), 1 byte
        cmd = self.build_dp_command(2, 2, bytes([level]))
        return await self.send_command(cmd)


async def main():
    """Main test function"""
    print("="*80)
    print("GE CYNC BLE MESH PROTOCOL TEST")
    print("="*80)

    print(f"\nScanning for {TARGET_MAC}...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)

    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name} ({device.address})")

    async with BleakClient(device, timeout=20.0) as client:
        if not client.is_connected:
            print("[ERROR] Failed to connect")
            return

        print("[OK] Connected\n")

        # Initialize protocol
        protocol = CyncProtocol(client)

        # Subscribe to notifications
        print("[SETUP] Subscribing to notifications...")
        await protocol.start_notifications()
        await asyncio.sleep(0.5)

        # Perform mesh handshake
        print("\n" + "="*80)
        print("MESH HANDSHAKE")
        print("="*80)

        success = await protocol.handshake()

        if success:
            # Try sending commands
            print("\n" + "="*80)
            print("SENDING COMMANDS")
            print("="*80)
            print("Watch the bulb for changes!")

            # Turn off
            await protocol.turn_off()
            await asyncio.sleep(2)

            # Turn on
            await protocol.turn_on()
            await asyncio.sleep(2)

            # Brightness 50%
            await protocol.set_brightness(50)
            await asyncio.sleep(2)

            # Brightness 100%
            await protocol.set_brightness(100)

        else:
            print("\n[ERROR] Handshake failed")

        print("\n" + "="*80)
        print("TEST COMPLETE")
        print("="*80)


if __name__ == "__main__":
    asyncio.run(main())
