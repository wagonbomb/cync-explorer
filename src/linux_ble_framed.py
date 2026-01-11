#!/usr/bin/env python3
"""
Cync BLE test using proper Telink framing from decompiled libBleLib.so

Key insight: Raw hex commands need to go through the framing encoder.
The device expects:
  [var_offset][var_total_len][type_seq][data...]

Where type_seq = (frame_type << 4) | (sequence & 0x0f)
"""

import asyncio
import sys
from pathlib import Path

# Add protocol module to path
sys.path.insert(0, str(Path(__file__).parent))

from bleak import BleakScanner, BleakClient
from protocol.telink_framing import TelinkFramer, KLVEncoder

TARGET_MAC = "34:13:43:46:CA:84"

# Characteristics
TELINK_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"  # Notify
TELINK_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"  # Write
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"   # Write
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"  # Notify

# Raw command payloads (before framing)
RAW_COMMANDS = {
    "START": bytes.fromhex("000501000000000000000000"),
    "KEY_EXCHANGE": bytes.fromhex("00000100000000000000040000"),
    "SYNC_0": bytes.fromhex("3100"),
    "SYNC_1": bytes.fromhex("3101"),
    "SYNC_2": bytes.fromhex("3102"),
    "SYNC_3": bytes.fromhex("3103"),
    "SYNC_4": bytes.fromhex("3104"),
    "AUTH": bytes.fromhex("320119000000"),
}

responses = []
response_event = asyncio.Event()

def make_handler(name):
    def handler(sender, data):
        hex_data = data.hex()
        print(f"  <- [{name}] {hex_data}")

        # Try to decode if it looks like a framed packet
        try:
            framer = TelinkFramer()
            decoded = framer.decode_packet(data)
            print(f"     Decoded: type={decoded['frame_type']}, seq={decoded['sequence']}, "
                  f"offset={decoded['offset']}, total={decoded['total_len']}")
            print(f"     Data: {decoded['data'].hex()}")
        except Exception as e:
            print(f"     (decode failed: {e})")

        responses.append((name, data))
        response_event.set()
    return handler

async def wait_response(timeout=2.0):
    global response_event
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.1)
        response_event.clear()
        return True
    except asyncio.TimeoutError:
        response_event.clear()
        return False

async def main():
    print("=" * 70)
    print("CYNC BLE - TELINK FRAMED PROTOCOL TEST")
    print("=" * 70)
    print()
    print("Based on libBleLib.so decompilation:")
    print("  - Packets use 7-bit variable-length encoding")
    print("  - Frame: [var_offset][var_total_len][type_seq][data]")
    print("  - type_seq: upper nibble = type, lower nibble = sequence (0-15)")
    print()

    # Create framer
    framer = TelinkFramer()

    # Show what the framed packets look like
    print("-" * 70)
    print("FRAMED PACKET PREVIEW")
    print("-" * 70)
    for name, raw_data in RAW_COMMANDS.items():
        framed = framer.encode_packet(0, raw_data)  # frame_type=0
        for i, pkt in enumerate(framed):
            print(f"  {name}: raw={raw_data.hex()}")
            print(f"         framed={pkt.hex()}")
    print()

    # Reset framer for actual test
    framer = TelinkFramer()

    print("-" * 70)
    print("CONNECTING TO DEVICE")
    print("-" * 70)

    print("[1] Scanning for device...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=20.0)
    if not device:
        print("Device not found!")
        return
    print(f"Found: {device.name}")

    print()
    print("[2] Connecting...")
    async with BleakClient(device, timeout=30.0) as client:
        print(f"Connected! MTU: {client.mtu_size}")
        await asyncio.sleep(1.0)

        print()
        print("[3] Subscribing to notifications...")

        # Try Mesh Proxy Out (this one works)
        try:
            await client.start_notify(MESH_PROXY_OUT, make_handler("PROXY"))
            print(f"  [OK] Mesh Proxy Out (2ade)")
        except Exception as e:
            print(f"  [FAIL] Mesh Proxy Out: {e}")

        # Try Telink 1911 (may fail with "Notify acquired")
        try:
            await client.start_notify(TELINK_1911, make_handler("TELINK"))
            print(f"  [OK] Telink 1911")
        except Exception as e:
            print(f"  [FAIL] Telink 1911: {e}")

        await asyncio.sleep(0.5)

        print()
        print("=" * 70)
        print("TEST 1: FRAMED HANDSHAKE VIA TELINK 1912")
        print("=" * 70)

        framer = TelinkFramer()  # Reset sequence

        for name in ["START", "KEY_EXCHANGE", "SYNC_0", "SYNC_1", "SYNC_2"]:
            raw_data = RAW_COMMANDS[name]
            framed_packets = framer.encode_packet(0, raw_data)

            for pkt in framed_packets:
                responses.clear()
                print(f"\n  [{name}]")
                print(f"    Raw:    {raw_data.hex()}")
                print(f"    Framed: {pkt.hex()}")

                try:
                    await client.write_gatt_char(TELINK_1912, pkt, response=False)
                    if await wait_response(timeout=2.0):
                        pass  # Already printed in handler
                    else:
                        print(f"    (no response)")
                except Exception as e:
                    print(f"    Error: {e}")

                await asyncio.sleep(0.3)

        print()
        print("=" * 70)
        print("TEST 2: FRAMED HANDSHAKE VIA MESH PROXY IN")
        print("=" * 70)

        framer = TelinkFramer()  # Reset sequence

        for name in ["START", "KEY_EXCHANGE", "SYNC_0", "SYNC_1"]:
            raw_data = RAW_COMMANDS[name]
            framed_packets = framer.encode_packet(0, raw_data)

            for pkt in framed_packets:
                responses.clear()
                print(f"\n  [{name}]")
                print(f"    Raw:    {raw_data.hex()}")
                print(f"    Framed: {pkt.hex()}")

                try:
                    await client.write_gatt_char(MESH_PROXY_IN, pkt, response=False)
                    if await wait_response(timeout=2.0):
                        pass
                    else:
                        print(f"    (no response)")
                except Exception as e:
                    print(f"    Error: {e}")

                await asyncio.sleep(0.3)

        print()
        print("=" * 70)
        print("TEST 3: RAW VS FRAMED COMPARISON")
        print("=" * 70)
        print("Sending same command both raw and framed to compare behavior")

        # Raw START
        print("\n  [RAW START]")
        raw = bytes.fromhex("000501000000000000000000")
        print(f"    Sending: {raw.hex()}")
        try:
            await client.write_gatt_char(TELINK_1912, raw, response=False)
            if await wait_response(timeout=1.5):
                pass
            else:
                print(f"    (no response)")
        except Exception as e:
            print(f"    Error: {e}")

        await asyncio.sleep(0.5)

        # Framed START
        print("\n  [FRAMED START]")
        framer = TelinkFramer()
        framed = framer.encode_packet(0, raw)[0]
        print(f"    Sending: {framed.hex()}")
        try:
            await client.write_gatt_char(TELINK_1912, framed, response=False)
            if await wait_response(timeout=1.5):
                pass
            else:
                print(f"    (no response)")
        except Exception as e:
            print(f"    Error: {e}")

        print()
        print("=" * 70)
        print("TEST 4: CONTROL COMMANDS (FRAMED)")
        print("=" * 70)

        # Try control commands with framing
        control_commands = [
            ("ON_FRAMED", bytes.fromhex("b0c00101")),
            ("OFF_FRAMED", bytes.fromhex("b0c00100")),
        ]

        for name, raw_data in control_commands:
            framer = TelinkFramer()
            framed = framer.encode_packet(0, raw_data)[0]

            print(f"\n  [{name}]")
            print(f"    Raw:    {raw_data.hex()}")
            print(f"    Framed: {framed.hex()}")
            print(f"    CHECK THE LIGHT!")

            try:
                await client.write_gatt_char(TELINK_1912, framed, response=False)
                await asyncio.sleep(3.0)
            except Exception as e:
                print(f"    Error: {e}")

        print()
        print("=" * 70)
        print("DONE")
        print("=" * 70)

if __name__ == "__main__":
    asyncio.run(main())
