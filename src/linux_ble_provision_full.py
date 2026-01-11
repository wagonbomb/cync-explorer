#!/usr/bin/env python3
"""
Cync BLE - Full Provisioning Sequence

BREAKTHROUGH: Device responds to Provisioning Invite with Capabilities!

Capabilities:
- Elements: 4
- Algorithm: FIPS P-256 (ECDH)
- Static OOB: Available (need to find the value)
- No Output/Input OOB

This script attempts to complete provisioning.
"""

import asyncio
import hashlib
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bleak import BleakScanner, BleakClient

# Try to import cryptography for ECDH
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("Warning: cryptography not installed, using dummy keys")

TARGET_MAC = "34:13:43:46:CA:84"

MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

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

responses = []
response_event = asyncio.Event()

def build_proxy_pdu(msg_type: int, data: bytes, sar: int = 0) -> bytes:
    header = (sar << 6) | (msg_type & 0x3f)
    return bytes([header]) + data

def generate_keypair():
    """Generate P-256 keypair for ECDH"""
    if HAS_CRYPTO:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Get raw public key bytes (64 bytes: 32 for X, 32 for Y)
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # Remove the 0x04 prefix (uncompressed point indicator)
        return private_key, pub_bytes[1:]
    else:
        # Dummy 64-byte public key for testing
        return None, bytes(64)

def parse_public_key(data: bytes) -> tuple:
    """Parse 64-byte public key into X, Y coordinates"""
    if len(data) != 64:
        return None, None
    x = data[:32]
    y = data[32:]
    return x, y

def make_handler(name):
    def handler(sender, data):
        hex_data = data.hex()
        print(f"  <- [{name}] {hex_data}")
        responses.append((name, data))
        response_event.set()
    return handler

async def wait_response(timeout=5.0):
    global response_event
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.2)
        response_event.clear()
        return responses[-1][1] if responses else None
    except asyncio.TimeoutError:
        response_event.clear()
        return None

async def main():
    print("=" * 70)
    print("CYNC BLE - FULL PROVISIONING SEQUENCE")
    print("=" * 70)
    print()

    if not HAS_CRYPTO:
        print("Installing cryptography for ECDH...")
        # Will use dummy keys

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
        print("[3] Subscribing...")
        await client.start_notify(MESH_PROV_OUT, make_handler("PROV"))
        print("  Subscribed to Provisioning Out")

        await asyncio.sleep(0.5)

        # ========================================
        # STEP 1: Send Invite
        # ========================================
        print()
        print("=" * 70)
        print("STEP 1: PROVISIONING INVITE")
        print("=" * 70)

        invite = build_proxy_pdu(0x03, bytes([PROV_INVITE, 0x00]))  # 0 second attention
        print(f"  -> {invite.hex()}")
        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, invite, response=False)

        response = await wait_response(timeout=5.0)
        if not response:
            print("  No response to invite!")
            return

        if len(response) < 2 or response[1] != PROV_CAPABILITIES:
            print(f"  Unexpected response: {response.hex()}")
            return

        # Parse capabilities
        print(f"  Got CAPABILITIES: {response.hex()}")
        elements = response[2]
        algorithms = (response[3] << 8) | response[4]
        pub_key_type = response[5]
        static_oob = response[6]
        print(f"    Elements: {elements}")
        print(f"    Algorithms: {algorithms:#06x}")
        print(f"    Public Key Type: {pub_key_type}")
        print(f"    Static OOB Available: {static_oob}")

        # ========================================
        # STEP 2: Send Start
        # ========================================
        print()
        print("=" * 70)
        print("STEP 2: PROVISIONING START")
        print("=" * 70)

        # Provisioning Start parameters:
        # - Algorithm: 0 (FIPS P-256)
        # - Public Key: 0 (No OOB)
        # - Auth Method: 0 (No OOB), 1 (Static OOB), 2 (Output OOB), 3 (Input OOB)
        # - Auth Action: depends on method
        # - Auth Size: depends on method

        # Try with No OOB first (method 0)
        start_pdu = bytes([
            PROV_START,
            0x00,  # Algorithm: FIPS P-256
            0x00,  # Public Key: No OOB
            0x00,  # Auth Method: No OOB (try 0x01 for Static OOB)
            0x00,  # Auth Action
            0x00   # Auth Size
        ])
        start = build_proxy_pdu(0x03, start_pdu)
        print(f"  -> {start.hex()} (No OOB auth)")

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, start, response=False)
        response = await wait_response(timeout=5.0)

        if response:
            print(f"  <- {response.hex()}")
            if len(response) >= 2 and response[1] == PROV_FAILED:
                fail_reason = response[2] if len(response) > 2 else 0
                print(f"    FAILED: reason {fail_reason}")

                # Try with Static OOB
                print()
                print("  Trying with Static OOB auth...")
                start_pdu = bytes([
                    PROV_START,
                    0x00,  # Algorithm
                    0x00,  # Public Key: No OOB
                    0x01,  # Auth Method: Static OOB
                    0x00,  # Auth Action
                    0x00   # Auth Size
                ])
                start = build_proxy_pdu(0x03, start_pdu)
                print(f"  -> {start.hex()} (Static OOB)")

                # Need to send invite again first
                responses.clear()
                await client.write_gatt_char(MESH_PROV_IN, invite, response=False)
                response = await wait_response(timeout=3.0)
                if response:
                    print(f"  <- {response.hex()} (capabilities)")

                responses.clear()
                await client.write_gatt_char(MESH_PROV_IN, start, response=False)
                response = await wait_response(timeout=5.0)

                if response:
                    print(f"  <- {response.hex()}")
        else:
            print("  No response to start")

        # ========================================
        # STEP 3: Public Key Exchange
        # ========================================
        print()
        print("=" * 70)
        print("STEP 3: PUBLIC KEY EXCHANGE")
        print("=" * 70)

        # Generate our keypair
        private_key, our_public_key = generate_keypair()
        print(f"  Our public key (64 bytes): {our_public_key.hex()[:32]}...")

        # Build Public Key PDU
        # Note: This is 65 bytes total, may need to segment
        pk_pdu = bytes([PROV_PUBLIC_KEY]) + our_public_key

        # Check if we need segmentation (MTU is typically 23 bytes for BLE)
        # Max payload per packet is MTU - 3 = 20 bytes
        # Public key PDU is 65 bytes, so we need segmentation

        print(f"  Public key PDU size: {len(pk_pdu)} bytes (needs segmentation)")

        # For now, try sending first segment
        # SAR: 01 = first segment
        first_seg = build_proxy_pdu(0x03, pk_pdu[:19], sar=1)  # First 19 bytes
        print(f"  -> First segment: {first_seg.hex()}")

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, first_seg, response=False)
        response = await wait_response(timeout=3.0)
        if response:
            print(f"  <- {response.hex()}")

        # Continue with more segments
        offset = 19
        while offset < len(pk_pdu):
            remaining = len(pk_pdu) - offset
            seg_len = min(19, remaining)
            is_last = (offset + seg_len >= len(pk_pdu))
            sar = 3 if is_last else 2  # 3=last, 2=continuation

            seg = build_proxy_pdu(0x03, pk_pdu[offset:offset+seg_len], sar=sar)
            print(f"  -> Segment (SAR={sar}): {seg.hex()}")

            await client.write_gatt_char(MESH_PROV_IN, seg, response=False)
            offset += seg_len
            await asyncio.sleep(0.1)

        # Wait for device's public key
        response = await wait_response(timeout=5.0)
        if response:
            print(f"  <- Device response: {response.hex()}")

        # ========================================
        # Summary
        # ========================================
        print()
        print("=" * 70)
        print("PROVISIONING ATTEMPT SUMMARY")
        print("=" * 70)
        print()
        print("The device responded to Provisioning Invite with Capabilities!")
        print("This confirms the device is unprovisioned and ready to join a mesh.")
        print()
        print("To complete provisioning, we need:")
        print("1. Static OOB value (16 bytes) - likely from device label or documentation")
        print("2. Network Key (16 bytes) - we generate this")
        print("3. Device Key (16 bytes) - we generate this")
        print("4. Unicast Address (2 bytes) - we assign this")
        print()
        print("The Static OOB might be:")
        print(f"  - Based on MAC: {TARGET_MAC}")
        print(f"  - A fixed value for Cync devices")
        print(f"  - Printed on the device packaging")
        print()
        print("Next: Find the Static OOB value or try common values")

if __name__ == "__main__":
    asyncio.run(main())
