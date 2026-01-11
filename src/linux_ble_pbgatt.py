#!/usr/bin/env python3
"""
Cync BLE - Proper PB-GATT (Provisioning Bearer over GATT) Protocol

Based on Bluetooth Mesh Specification v1.0.1, Section 5.2.2 (PB-GATT)

The device responded to bearer control commands (03xx) with error codes.
This suggests it expects proper Provisioning PDU format.

PB-GATT PDU Format:
  - Proxy PDU: [SAR:2 | MsgType:6] [PDU...]
  - SAR = 00 (complete), 01 (first), 10 (continuation), 11 (last)
  - MsgType = 0x03 for Provisioning PDU

Provisioning PDU Types:
  0x00 = Invite (1 byte: attention duration)
  0x01 = Capabilities (11 bytes response)
  0x02 = Start (5 bytes)
  0x03 = Public Key (64 bytes)
  0x04 = Input Complete
  0x05 = Confirmation (16 bytes)
  0x06 = Random (16 bytes)
  0x07 = Data (encrypted)
  0x08 = Complete
  0x09 = Failed (1 byte: error code)
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bleak import BleakScanner, BleakClient

TARGET_MAC = "34:13:43:46:CA:84"

# Mesh Provisioning characteristics
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

# Mesh Proxy characteristics (for after provisioning)
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

# Proxy PDU Message Types
MSG_NETWORK_PDU = 0x00
MSG_MESH_BEACON = 0x01
MSG_PROXY_CONFIG = 0x02
MSG_PROVISIONING = 0x03

# Provisioning PDU Types
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

PROV_NAMES = {
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

# Provisioning Failed Reasons
FAIL_PROHIBITED = 0x00
FAIL_INVALID_PDU = 0x01
FAIL_INVALID_FORMAT = 0x02
FAIL_UNEXPECTED_PDU = 0x03
FAIL_CONFIRMATION_FAILED = 0x04
FAIL_OUT_OF_RESOURCES = 0x05
FAIL_DECRYPTION_FAILED = 0x06
FAIL_UNEXPECTED_ERROR = 0x07
FAIL_CANNOT_ASSIGN_ADDR = 0x08

FAIL_NAMES = {
    0x00: "PROHIBITED",
    0x01: "INVALID_PDU",
    0x02: "INVALID_FORMAT",
    0x03: "UNEXPECTED_PDU",
    0x04: "CONFIRMATION_FAILED",
    0x05: "OUT_OF_RESOURCES",
    0x06: "DECRYPTION_FAILED",
    0x07: "UNEXPECTED_ERROR",
    0x08: "CANNOT_ASSIGN_ADDRESSES"
}

responses = []
response_event = asyncio.Event()

def build_proxy_pdu(msg_type: int, data: bytes, sar: int = 0) -> bytes:
    """Build a Proxy PDU with SAR and message type"""
    header = (sar << 6) | (msg_type & 0x3f)
    return bytes([header]) + data

def build_prov_invite(attention_duration: int = 5) -> bytes:
    """Build Provisioning Invite PDU"""
    # Proxy PDU header (SAR=complete, type=provisioning) + Prov PDU (type=invite, data)
    prov_pdu = bytes([PROV_INVITE, attention_duration])
    return build_proxy_pdu(MSG_PROVISIONING, prov_pdu)

def build_prov_start(algorithm: int = 0, pub_key: int = 0,
                      auth_method: int = 0, auth_action: int = 0,
                      auth_size: int = 0) -> bytes:
    """Build Provisioning Start PDU"""
    prov_pdu = bytes([
        PROV_START,
        algorithm,      # 0 = FIPS P-256 Elliptic Curve
        pub_key,        # 0 = No OOB Public Key
        auth_method,    # 0 = No OOB authentication
        auth_action,    # Action (depends on method)
        auth_size       # Size (depends on method)
    ])
    return build_proxy_pdu(MSG_PROVISIONING, prov_pdu)

def parse_response(data: bytes) -> dict:
    """Parse a Proxy PDU response"""
    if len(data) < 2:
        return {"error": "PDU too short"}

    header = data[0]
    sar = (header >> 6) & 0x03
    msg_type = header & 0x3f

    sar_names = {0: "COMPLETE", 1: "FIRST", 2: "CONTINUE", 3: "LAST"}
    msg_names = {0: "NETWORK", 1: "BEACON", 2: "PROXY_CONFIG", 3: "PROVISIONING"}

    result = {
        "sar": sar_names.get(sar, f"UNKNOWN({sar})"),
        "msg_type": msg_names.get(msg_type, f"UNKNOWN({msg_type})"),
        "raw": data.hex()
    }

    if msg_type == MSG_PROVISIONING and len(data) >= 2:
        prov_type = data[1]
        result["prov_type"] = PROV_NAMES.get(prov_type, f"UNKNOWN({prov_type:02x})")

        if prov_type == PROV_CAPABILITIES and len(data) >= 13:
            result["capabilities"] = {
                "elements": data[2],
                "algorithms": (data[3] << 8) | data[4],
                "pub_key_type": data[5],
                "static_oob_type": data[6],
                "output_oob_size": data[7],
                "output_oob_action": (data[8] << 8) | data[9],
                "input_oob_size": data[10],
                "input_oob_action": (data[11] << 8) | data[12]
            }
        elif prov_type == PROV_FAILED and len(data) >= 3:
            fail_code = data[2]
            result["fail_reason"] = FAIL_NAMES.get(fail_code, f"UNKNOWN({fail_code:02x})")

    return result

def make_handler(name):
    def handler(sender, data):
        hex_data = data.hex()
        print(f"  <- [{name}] {hex_data}")

        parsed = parse_response(data)
        print(f"     Parsed: {parsed}")

        responses.append((name, data, parsed))
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
    print("CYNC BLE - PB-GATT PROVISIONING TEST")
    print("=" * 70)
    print()
    print("Testing proper Bluetooth Mesh provisioning protocol...")
    print()

    print("[1] Scanning...")
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
        print("[3] Subscribing to Provisioning Out...")
        try:
            await client.start_notify(MESH_PROV_OUT, make_handler("PROV"))
            print(f"  [OK] Mesh Prov Out (2adc)")
        except Exception as e:
            print(f"  [FAIL] {e}")
            return

        await asyncio.sleep(0.5)

        print()
        print("=" * 70)
        print("TEST 1: PROVISIONING INVITE (Proper Format)")
        print("=" * 70)

        # Proper format: [Proxy Header: SAR=0, Type=3] [Prov Type=0] [Attention=5]
        invite = build_prov_invite(attention_duration=5)
        print(f"  Sending: {invite.hex()}")
        print(f"    Header: 0x{invite[0]:02x} (SAR=0, MsgType=PROVISIONING)")
        print(f"    ProvType: 0x{invite[1]:02x} (INVITE)")
        print(f"    Attention: {invite[2]} seconds")

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, invite, response=False)
        result = await wait_response(timeout=5.0)

        if not result:
            print("  (no response)")

        print()
        print("=" * 70)
        print("TEST 2: VARIOUS INVITE FORMATS")
        print("=" * 70)

        # Try different attention durations
        for attention in [0, 1, 5, 10, 255]:
            invite = build_prov_invite(attention_duration=attention)
            print(f"\n  [INVITE attention={attention}] -> {invite.hex()}")
            responses.clear()
            await client.write_gatt_char(MESH_PROV_IN, invite, response=False)
            result = await wait_response(timeout=2.0)
            if not result:
                print("    (no response)")

        print()
        print("=" * 70)
        print("TEST 3: RAW PROVISIONING PDU (No Proxy Header)")
        print("=" * 70)
        print("Try sending just the provisioning PDU without proxy header...")

        # Just the provisioning PDU: [Type=0] [Attention=5]
        raw_invite = bytes([PROV_INVITE, 0x05])
        print(f"\n  [RAW INVITE] -> {raw_invite.hex()}")
        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, raw_invite, response=False)
        result = await wait_response(timeout=2.0)
        if not result:
            print("    (no response)")

        print()
        print("=" * 70)
        print("TEST 4: PROVISIONING START (Skip Invite)")
        print("=" * 70)
        print("Maybe device is already waiting for Start...")

        start = build_prov_start(
            algorithm=0,     # FIPS P-256
            pub_key=0,       # No OOB Public Key
            auth_method=0,   # No OOB Authentication
            auth_action=0,
            auth_size=0
        )
        print(f"\n  [START] -> {start.hex()}")
        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, start, response=False)
        result = await wait_response(timeout=2.0)
        if not result:
            print("    (no response)")

        print()
        print("=" * 70)
        print("TEST 5: TELINK-SPECIFIC COMMANDS VIA PROV")
        print("=" * 70)
        print("Maybe Telink uses provisioning char for app-level commands...")

        # Wrap our handshake in proxy PDU format
        telink_cmds = [
            ("START wrapped", bytes([0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
            ("SYNC wrapped", bytes([0x03, 0x31, 0x00])),
        ]

        for name, cmd in telink_cmds:
            print(f"\n  [{name}] -> {cmd.hex()}")
            responses.clear()
            await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
            result = await wait_response(timeout=2.0)
            if not result:
                print("    (no response)")

        print()
        print("=" * 70)
        print("TEST 6: ATTENTION BLINK TEST")
        print("=" * 70)
        print("If device responds to invite, it should blink during attention timer...")

        # Send invite with 10 second attention
        invite = build_prov_invite(attention_duration=10)
        print(f"\n  Sending INVITE with 10 second attention timer...")
        print(f"  WATCH THE LIGHT - it should blink if provisioning works!")
        print(f"  -> {invite.hex()}")

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, invite, response=False)

        # Wait longer to observe
        print(f"\n  Waiting 12 seconds to observe light behavior...")
        for i in range(12):
            await asyncio.sleep(1.0)
            print(f"    {i+1}s...")
            if responses:
                print(f"    Got response during wait!")
                break

        print()
        print("=" * 70)
        print("DONE - Summary")
        print("=" * 70)
        print(f"Total responses received: {len(responses)}")
        for name, data, parsed in responses:
            print(f"  [{name}] {data.hex()}: {parsed.get('prov_type', 'N/A')} {parsed.get('fail_reason', '')}")

if __name__ == "__main__":
    asyncio.run(main())
