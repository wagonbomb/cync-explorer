#!/usr/bin/env python3
"""
Cync BLE - Try Mesh Provisioning path

The device advertises Mesh Provisioning service (0x1827) with data.
This might need to happen before Mesh Proxy commands work.

Mesh Provisioning flow (Bluetooth Mesh spec):
1. Send Provisioning Invite (0x00)
2. Receive Provisioning Capabilities (0x01)
3. Exchange public keys
4. Authentication
5. Provisioning Data

But Cync might use a simplified/proprietary flow.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bleak import BleakScanner, BleakClient

TARGET_MAC = "34:13:43:46:CA:84"

# Mesh Provisioning (standard Bluetooth Mesh)
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"   # Write (Provisioning PDU In)
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"  # Notify (Provisioning PDU Out)

# Mesh Proxy
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

# Telink
TELINK_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"
TELINK_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"

# Standard Mesh Provisioning PDU types
PROV_INVITE = 0x00
PROV_CAPABILITIES = 0x01
PROV_START = 0x02
PROV_PUBLIC_KEY = 0x03
PROV_INPUT_COMPLETE = 0x04
PROV_CONFIRMATION = 0x05
PROV_RANDOM = 0x06
PROV_DATA = 0x07
PROV_COMPLETE = 0x08
PROV_FAILED = 0x09

responses = []
response_event = asyncio.Event()

def make_handler(name):
    def handler(sender, data):
        hex_data = data.hex()
        print(f"  <- [{name}] {hex_data}")

        # Try to interpret as provisioning PDU
        if len(data) > 0:
            pdu_type = data[0] & 0x3f  # Lower 6 bits
            seg = (data[0] >> 6) & 0x03  # Upper 2 bits (segmentation)

            pdu_names = {
                0x00: "INVITE",
                0x01: "CAPABILITIES",
                0x02: "START",
                0x03: "PUBLIC_KEY",
                0x04: "INPUT_COMPLETE",
                0x05: "CONFIRMATION",
                0x06: "RANDOM",
                0x07: "DATA",
                0x08: "COMPLETE",
                0x09: "FAILED"
            }
            pdu_name = pdu_names.get(pdu_type, f"UNKNOWN({pdu_type:02x})")
            print(f"     PDU: seg={seg}, type={pdu_name}")

            if pdu_type == PROV_CAPABILITIES and len(data) >= 12:
                # Parse capabilities
                print(f"     Elements: {data[1]}")
                print(f"     Algorithms: {data[2]:02x}{data[3]:02x}")
                print(f"     Public Key Type: {data[4]}")
                print(f"     Static OOB Type: {data[5]}")
                print(f"     Output OOB Size: {data[6]}")
                print(f"     Output OOB Action: {data[7]:02x}{data[8]:02x}")
                print(f"     Input OOB Size: {data[9]}")
                print(f"     Input OOB Action: {data[10]:02x}{data[11]:02x}")

        responses.append((name, data))
        response_event.set()
    return handler

async def wait_response(timeout=3.0):
    global response_event
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.2)
        response_event.clear()
        return responses[-1] if responses else None
    except asyncio.TimeoutError:
        response_event.clear()
        return None

async def main():
    print("=" * 70)
    print("CYNC BLE - MESH PROVISIONING TEST")
    print("=" * 70)
    print()

    print("[1] Scanning...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=20.0)
    if not device:
        print("Device not found!")
        return
    print(f"Found: {device.name}")

    # Print advertisement data
    print(f"\nAdvertisement data:")
    try:
        devices = await BleakScanner.discover(timeout=5.0, return_adv=True)
        for addr, (dev, adv) in devices.items():
            if addr == TARGET_MAC:
                print(f"  Name: {adv.local_name}")
                print(f"  Service UUIDs: {adv.service_uuids}")
                print(f"  Service Data: {adv.service_data}")
                print(f"  Manufacturer Data: {adv.manufacturer_data}")
                break
    except Exception as e:
        print(f"  (could not get adv data: {e})")

    print()
    print("[2] Connecting...")
    async with BleakClient(device, timeout=30.0) as client:
        print(f"Connected! MTU: {client.mtu_size}")
        await asyncio.sleep(1.0)

        print()
        print("[3] Subscribing to notifications...")

        # Subscribe to provisioning out
        try:
            await client.start_notify(MESH_PROV_OUT, make_handler("PROV"))
            print(f"  [OK] Mesh Prov Out (2adc)")
        except Exception as e:
            print(f"  [FAIL] Mesh Prov Out: {e}")

        # Subscribe to proxy out
        try:
            await client.start_notify(MESH_PROXY_OUT, make_handler("PROXY"))
            print(f"  [OK] Mesh Proxy Out (2ade)")
        except Exception as e:
            print(f"  [FAIL] Mesh Proxy Out: {e}")

        await asyncio.sleep(0.5)

        print()
        print("=" * 70)
        print("TEST 1: MESH PROVISIONING INVITE")
        print("=" * 70)
        print("Sending Provisioning Invite PDU...")

        # Standard Mesh Provisioning Invite
        # Format: [PDU type (0x00)] [Attention Duration (seconds)]
        invite = bytes([0x00, 0x05])  # Invite with 5 second attention

        print(f"  -> {invite.hex()}")
        responses.clear()
        try:
            await client.write_gatt_char(MESH_PROV_IN, invite, response=False)
            result = await wait_response(timeout=5.0)
            if result:
                print("  Got response!")
            else:
                print("  (no response)")
        except Exception as e:
            print(f"  Error: {e}")

        print()
        print("=" * 70)
        print("TEST 2: PROVISIONING WITH SAR (SEGMENTATION)")
        print("=" * 70)
        print("Mesh PDUs use segmentation bits in first byte...")

        # Try with different segmentation markers
        # Bits 6-7: 00 = complete, 01 = first, 10 = continuation, 11 = last
        for seg_name, seg_bits in [("COMPLETE", 0x00), ("FIRST", 0x40), ("LAST", 0xC0)]:
            invite = bytes([seg_bits | 0x00, 0x05])  # Invite with seg bits
            print(f"\n  [{seg_name}] -> {invite.hex()}")
            responses.clear()
            try:
                await client.write_gatt_char(MESH_PROV_IN, invite, response=False)
                result = await wait_response(timeout=2.0)
                if result:
                    print("  Got response!")
                else:
                    print("  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 70)
        print("TEST 3: RAW HANDSHAKE VIA PROVISIONING")
        print("=" * 70)
        print("Try sending our handshake commands via provisioning characteristic...")

        commands = [
            ("START", "000501000000000000000000"),
            ("KEY_EXCHANGE", "00000100000000000000040000"),
        ]

        for name, cmd_hex in commands:
            cmd = bytes.fromhex(cmd_hex)
            print(f"\n  [{name}] -> {cmd_hex}")
            responses.clear()
            try:
                await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
                result = await wait_response(timeout=2.0)
                if result:
                    print("  Got response!")
                else:
                    print("  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 70)
        print("TEST 4: LINK OPEN (PROVISIONING BEARER)")
        print("=" * 70)
        print("Try PB-GATT Link Open...")

        # PB-GATT uses a different framing than PB-ADV
        # But let's try some common opcodes
        opcodes = [
            ("LINK_OPEN", bytes([0x03, 0x00])),  # Link open
            ("LINK_ACK", bytes([0x03, 0x01])),   # Link ack
            ("TRANS_START", bytes([0x03, 0x02])), # Transaction start
        ]

        for name, cmd in opcodes:
            print(f"\n  [{name}] -> {cmd.hex()}")
            responses.clear()
            try:
                await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
                result = await wait_response(timeout=2.0)
                if result:
                    print("  Got response!")
                else:
                    print("  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 70)
        print("TEST 5: PROXY CONFIGURATION")
        print("=" * 70)
        print("Try Mesh Proxy configuration messages...")

        # Mesh Proxy PDU types (first byte, bits 0-5)
        # 0x00 = Network PDU
        # 0x01 = Mesh Beacon
        # 0x02 = Proxy Configuration
        # 0x03 = Provisioning PDU

        proxy_msgs = [
            ("SET_FILTER_TYPE", bytes([0x02, 0x00, 0x00])),  # Proxy config, set filter to whitelist
            ("ADD_TO_FILTER", bytes([0x02, 0x01, 0x00, 0x00])),  # Add address to filter
            ("PROXY_BEACON", bytes([0x01, 0x00])),  # Request beacon
        ]

        for name, cmd in proxy_msgs:
            print(f"\n  [{name}] -> {cmd.hex()}")
            responses.clear()
            try:
                await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
                result = await wait_response(timeout=2.0)
                if result:
                    print("  Got response!")
                else:
                    print("  (no response)")
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 70)
        print("DONE")
        print("=" * 70)

if __name__ == "__main__":
    asyncio.run(main())
