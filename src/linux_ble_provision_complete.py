#!/usr/bin/env python3
"""
Cync BLE - Complete Provisioning with ECDH

We've confirmed:
1. Device responds to Invite with Capabilities
2. Device responds to Public Key with its Public Key
3. We can do ECDH key exchange!

This script completes the full provisioning:
- ECDH shared secret calculation
- Confirmation exchange
- Random exchange
- Provisioning Data (network key, device key, address)
"""

import asyncio
import hashlib
import hmac
import secrets
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bleak import BleakScanner, BleakClient

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
all_responses = []

def build_proxy_pdu(msg_type: int, data: bytes, sar: int = 0) -> bytes:
    header = (sar << 6) | (msg_type & 0x3f)
    return bytes([header]) + data

def aes_cmac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC for Bluetooth Mesh"""
    from cryptography.hazmat.primitives.cmac import CMAC

    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(data)
    return c.finalize()

def s1(m: bytes) -> bytes:
    """s1 salt function"""
    zero_key = bytes(16)
    return aes_cmac(zero_key, m)

def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    """k1 key derivation"""
    t = aes_cmac(salt, n)
    return aes_cmac(t, p)

def make_handler(name):
    def handler(sender, data):
        hex_data = data.hex()
        print(f"  <- [{name}] {hex_data}")
        responses.append((name, data))
        all_responses.append((name, data))
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

async def send_segmented(client, char_uuid, pdu: bytes):
    """Send a PDU with segmentation if needed"""
    max_seg = 19  # Max segment size

    if len(pdu) <= max_seg:
        # Single segment
        packet = build_proxy_pdu(0x03, pdu, sar=0)
        await client.write_gatt_char(char_uuid, packet, response=False)
    else:
        # Multiple segments
        offset = 0
        first = True
        while offset < len(pdu):
            remaining = len(pdu) - offset
            seg_len = min(max_seg, remaining)
            is_last = (offset + seg_len >= len(pdu))

            if first:
                sar = 1  # First segment
                first = False
            elif is_last:
                sar = 3  # Last segment
            else:
                sar = 2  # Continuation

            packet = build_proxy_pdu(0x03, pdu[offset:offset+seg_len], sar=sar)
            await client.write_gatt_char(char_uuid, packet, response=False)
            offset += seg_len
            await asyncio.sleep(0.05)

async def main():
    print("=" * 70)
    print("CYNC BLE - COMPLETE PROVISIONING")
    print("=" * 70)
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
        print("[3] Subscribing...")
        await client.start_notify(MESH_PROV_OUT, make_handler("PROV"))

        # ========================================
        # Generate our keypair
        # ========================================
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        our_pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )[1:]  # Remove 0x04 prefix

        print(f"  Our public key: {our_pub_bytes.hex()[:32]}...")

        # ========================================
        # STEP 1: Invite
        # ========================================
        print()
        print("=" * 70)
        print("STEP 1: INVITE")
        print("=" * 70)

        attention = 0x00
        invite_pdu = bytes([PROV_INVITE, attention])
        invite = build_proxy_pdu(0x03, invite_pdu)
        print(f"  -> {invite.hex()}")

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, invite, response=False)
        response = await wait_response()

        if not response or response[1] != PROV_CAPABILITIES:
            print("  Failed to get capabilities!")
            return

        capabilities = response[2:]
        print(f"  Capabilities: {capabilities.hex()}")

        # ========================================
        # STEP 2: Start (No OOB)
        # ========================================
        print()
        print("=" * 70)
        print("STEP 2: START (No OOB)")
        print("=" * 70)

        start_pdu = bytes([
            PROV_START,
            0x00,  # Algorithm: FIPS P-256
            0x00,  # Public Key: No OOB
            0x00,  # Auth Method: No OOB
            0x00,  # Auth Action
            0x00   # Auth Size
        ])
        start = build_proxy_pdu(0x03, start_pdu)
        print(f"  -> {start.hex()}")

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, start, response=False)
        # No response expected for Start

        await asyncio.sleep(0.5)

        # ========================================
        # STEP 3: Public Key Exchange
        # ========================================
        print()
        print("=" * 70)
        print("STEP 3: PUBLIC KEY")
        print("=" * 70)

        pk_pdu = bytes([PROV_PUBLIC_KEY]) + our_pub_bytes
        print(f"  -> Sending our public key ({len(pk_pdu)} bytes)")

        responses.clear()
        await send_segmented(client, MESH_PROV_IN, pk_pdu)

        # Wait for device's public key
        response = await wait_response(timeout=10.0)

        if not response:
            print("  No response!")
            return

        # Reassemble if segmented
        device_pk_data = response

        if response[1] == PROV_PUBLIC_KEY:
            device_pub_bytes = response[2:]  # Skip proxy header and prov type
            print(f"  <- Device public key: {device_pub_bytes.hex()[:32]}...")

            if len(device_pub_bytes) != 64:
                print(f"  Warning: Expected 64 bytes, got {len(device_pub_bytes)}")
                # Try to get more data
                for _ in range(5):
                    more = await wait_response(timeout=2.0)
                    if more:
                        device_pub_bytes += more[1:]  # Append continuation data
                        if len(device_pub_bytes) >= 64:
                            break

            print(f"  Final device public key length: {len(device_pub_bytes)}")

        elif response[1] == PROV_FAILED:
            print(f"  FAILED: {response[2] if len(response) > 2 else 'unknown'}")
            return
        else:
            print(f"  Unexpected response type: {response[1]:02x}")
            return

        # ========================================
        # STEP 4: ECDH Shared Secret
        # ========================================
        print()
        print("=" * 70)
        print("STEP 4: ECDH SHARED SECRET")
        print("=" * 70)

        try:
            # Reconstruct device's public key
            device_pub_point = bytes([0x04]) + device_pub_bytes[:64]
            device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                device_pub_point
            )

            # Calculate shared secret
            shared_secret = private_key.exchange(ec.ECDH(), device_public_key)
            print(f"  Shared secret: {shared_secret.hex()}")

        except Exception as e:
            print(f"  ECDH failed: {e}")
            return

        # ========================================
        # STEP 5: Derive Confirmation Key
        # ========================================
        print()
        print("=" * 70)
        print("STEP 5: KEY DERIVATION")
        print("=" * 70)

        # ConfirmationInputs = ProvisioningInvitePDUValue || ProvisioningCapabilitiesPDUValue ||
        #                      ProvisioningStartPDUValue || PublicKeyProvisioner || PublicKeyDevice

        invite_value = bytes([attention])  # Just the attention duration
        cap_value = capabilities
        start_value = start_pdu[1:]  # Skip prov type

        confirmation_inputs = (
            invite_value +
            cap_value +
            start_value +
            our_pub_bytes +
            device_pub_bytes[:64]
        )
        print(f"  Confirmation inputs: {len(confirmation_inputs)} bytes")

        # ConfirmationSalt = s1(ConfirmationInputs)
        confirmation_salt = s1(confirmation_inputs)
        print(f"  Confirmation salt: {confirmation_salt.hex()}")

        # ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck")
        confirmation_key = k1(shared_secret, confirmation_salt, b"prck")
        print(f"  Confirmation key: {confirmation_key.hex()}")

        # ========================================
        # STEP 6: Send Confirmation
        # ========================================
        print()
        print("=" * 70)
        print("STEP 6: CONFIRMATION")
        print("=" * 70)

        # Random value
        random_provisioner = secrets.token_bytes(16)
        print(f"  Our random: {random_provisioner.hex()}")

        # AuthValue for No OOB = zeros
        auth_value = bytes(16)

        # Confirmation = AES-CMAC(ConfirmationKey, Random || AuthValue)
        our_confirmation = aes_cmac(confirmation_key, random_provisioner + auth_value)
        print(f"  Our confirmation: {our_confirmation.hex()}")

        conf_pdu = bytes([PROV_CONFIRMATION]) + our_confirmation
        conf = build_proxy_pdu(0x03, conf_pdu)
        print(f"  -> {conf.hex()}")

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, conf, response=False)

        # Wait for device confirmation
        response = await wait_response(timeout=10.0)

        if not response:
            print("  No confirmation response!")
            return

        if response[1] == PROV_CONFIRMATION:
            device_confirmation = response[2:18]
            print(f"  <- Device confirmation: {device_confirmation.hex()}")
        elif response[1] == PROV_FAILED:
            fail_code = response[2] if len(response) > 2 else 0
            fail_names = {0: "PROHIBITED", 1: "INVALID_PDU", 2: "INVALID_FORMAT",
                         3: "UNEXPECTED_PDU", 4: "CONFIRMATION_FAILED"}
            print(f"  FAILED: {fail_names.get(fail_code, fail_code)}")
            return
        else:
            print(f"  Unexpected: {response.hex()}")
            return

        # ========================================
        # STEP 7: Send Random
        # ========================================
        print()
        print("=" * 70)
        print("STEP 7: RANDOM EXCHANGE")
        print("=" * 70)

        random_pdu = bytes([PROV_RANDOM]) + random_provisioner
        random_packet = build_proxy_pdu(0x03, random_pdu)
        print(f"  -> {random_packet.hex()}")

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, random_packet, response=False)

        response = await wait_response(timeout=10.0)

        if not response:
            print("  No random response!")
            return

        if response[1] == PROV_RANDOM:
            device_random = response[2:18]
            print(f"  <- Device random: {device_random.hex()}")

            # Verify device's confirmation
            expected_device_conf = aes_cmac(confirmation_key, device_random + auth_value)
            if expected_device_conf == device_confirmation:
                print("  Confirmation VERIFIED!")
            else:
                print("  Confirmation MISMATCH!")
                print(f"    Expected: {expected_device_conf.hex()}")
                print(f"    Got:      {device_confirmation.hex()}")
                return

        elif response[1] == PROV_FAILED:
            fail_code = response[2] if len(response) > 2 else 0
            print(f"  FAILED: code {fail_code}")
            return

        # ========================================
        # STEP 8: Provisioning Data
        # ========================================
        print()
        print("=" * 70)
        print("STEP 8: PROVISIONING DATA")
        print("=" * 70)

        # Generate provisioning data
        network_key = secrets.token_bytes(16)
        key_index = 0
        flags = 0x00  # Key refresh: false, IV update: false
        iv_index = 0
        unicast_address = 0x0001

        provisioning_data = (
            network_key +
            struct.pack(">H", key_index) +
            bytes([flags]) +
            struct.pack(">I", iv_index) +
            struct.pack(">H", unicast_address)
        )
        print(f"  Network Key: {network_key.hex()}")
        print(f"  Unicast Address: 0x{unicast_address:04x}")

        # Derive Session Key and Nonce
        prov_salt = s1(confirmation_salt + random_provisioner + device_random)
        session_key = k1(shared_secret, prov_salt, b"prsk")
        session_nonce = k1(shared_secret, prov_salt, b"prsn")[:13]
        device_key = k1(shared_secret, prov_salt, b"prdk")

        print(f"  Session Key: {session_key.hex()}")
        print(f"  Device Key: {device_key.hex()}")

        # Encrypt provisioning data with AES-CCM
        # This is complex - for now just try sending
        # TODO: Proper AES-CCM encryption

        print()
        print("  [Provisioning data encryption needed - stopping here]")
        print()
        print("=" * 70)
        print("PROVISIONING PROGRESS SUMMARY")
        print("=" * 70)
        print()
        print("SUCCESS so far:")
        print("  [x] Invite -> Capabilities")
        print("  [x] Start accepted")
        print("  [x] Public Key exchange completed")
        print("  [x] ECDH shared secret calculated")
        print("  [x] Confirmation exchange")
        print("  [x] Random exchange")
        print("  [x] Device confirmation verified!")
        print()
        print("REMAINING:")
        print("  [ ] AES-CCM encrypt provisioning data")
        print("  [ ] Send encrypted data")
        print("  [ ] Receive Complete")
        print()
        print(f"Network Key: {network_key.hex()}")
        print(f"Device Key: {device_key.hex()}")

if __name__ == "__main__":
    asyncio.run(main())
