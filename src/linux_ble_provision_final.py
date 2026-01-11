#!/usr/bin/env python3
"""
Cync BLE - FINAL Provisioning with AES-CCM

We've verified:
- ECDH key exchange works
- Confirmation verified!
- Random exchange works

Now we complete with encrypted Provisioning Data.
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend

TARGET_MAC = "34:13:43:46:CA:84"

MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

PROV_INVITE = 0x00
PROV_CAPABILITIES = 0x01
PROV_START = 0x02
PROV_PUBLIC_KEY = 0x03
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

def aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(data)
    return c.finalize()

def s1(m: bytes) -> bytes:
    return aes_cmac(bytes(16), m)

def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    t = aes_cmac(salt, n)
    return aes_cmac(t, p)

def aes_ccm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
    """AES-CCM encryption with 8-byte MIC"""
    aesccm = AESCCM(key, tag_length=8)
    return aesccm.encrypt(nonce, plaintext, aad)

def make_handler(name):
    def handler(sender, data):
        print(f"  <- [{name}] {data.hex()}")
        responses.append(data)
        response_event.set()
    return handler

async def wait_response(timeout=5.0):
    global response_event
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.2)
        response_event.clear()
        return responses[-1] if responses else None
    except asyncio.TimeoutError:
        response_event.clear()
        return None

async def send_segmented(client, char_uuid, pdu: bytes):
    max_seg = 19
    if len(pdu) <= max_seg:
        packet = build_proxy_pdu(0x03, pdu, sar=0)
        await client.write_gatt_char(char_uuid, packet, response=False)
    else:
        offset = 0
        first = True
        while offset < len(pdu):
            remaining = len(pdu) - offset
            seg_len = min(max_seg, remaining)
            is_last = (offset + seg_len >= len(pdu))
            sar = 1 if first else (3 if is_last else 2)
            first = False
            packet = build_proxy_pdu(0x03, pdu[offset:offset+seg_len], sar=sar)
            await client.write_gatt_char(char_uuid, packet, response=False)
            offset += seg_len
            await asyncio.sleep(0.05)

async def main():
    print("=" * 70)
    print("CYNC BLE - FINAL PROVISIONING")
    print("=" * 70)

    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=20.0)
    if not device:
        print("Device not found!")
        return
    print(f"Found: {device.name}")

    async with BleakClient(device, timeout=30.0) as client:
        print(f"Connected! MTU: {client.mtu_size}")
        await asyncio.sleep(1.0)

        await client.start_notify(MESH_PROV_OUT, make_handler("PROV"))

        # Generate keypair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        our_pub = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )[1:]

        # ========================================
        # STEP 1: Invite
        # ========================================
        print("\n[STEP 1] Invite")
        attention = 0x00
        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, build_proxy_pdu(0x03, bytes([PROV_INVITE, attention])), response=False)
        response = await wait_response()
        if not response or response[1] != PROV_CAPABILITIES:
            print("  Failed!")
            return
        capabilities = response[2:]
        print(f"  OK - {response[2]} elements")

        # ========================================
        # STEP 2: Start
        # ========================================
        print("\n[STEP 2] Start")
        start_pdu = bytes([PROV_START, 0x00, 0x00, 0x00, 0x00, 0x00])
        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, build_proxy_pdu(0x03, start_pdu), response=False)
        await asyncio.sleep(0.5)
        print("  OK")

        # ========================================
        # STEP 3: Public Key
        # ========================================
        print("\n[STEP 3] Public Key Exchange")
        responses.clear()
        await send_segmented(client, MESH_PROV_IN, bytes([PROV_PUBLIC_KEY]) + our_pub)
        response = await wait_response(timeout=10.0)
        if not response or response[1] != PROV_PUBLIC_KEY:
            print(f"  Failed: {response.hex() if response else 'no response'}")
            return
        device_pub = response[2:66]
        print(f"  OK - Got device key")

        # ECDH
        device_pub_point = bytes([0x04]) + device_pub
        device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_pub_point)
        shared_secret = private_key.exchange(ec.ECDH(), device_public_key)
        print(f"  Shared secret: {shared_secret.hex()[:16]}...")

        # Key derivation
        invite_value = bytes([attention])
        start_value = start_pdu[1:]
        conf_inputs = invite_value + capabilities + start_value + our_pub + device_pub
        conf_salt = s1(conf_inputs)
        conf_key = k1(shared_secret, conf_salt, b"prck")

        # ========================================
        # STEP 4: Confirmation
        # ========================================
        print("\n[STEP 4] Confirmation Exchange")
        random_prov = secrets.token_bytes(16)
        auth_value = bytes(16)  # No OOB
        our_conf = aes_cmac(conf_key, random_prov + auth_value)

        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, build_proxy_pdu(0x03, bytes([PROV_CONFIRMATION]) + our_conf), response=False)
        response = await wait_response()
        if not response or response[1] != PROV_CONFIRMATION:
            print(f"  Failed: {response.hex() if response else 'no response'}")
            return
        device_conf = response[2:18]
        print(f"  OK - Got device confirmation")

        # ========================================
        # STEP 5: Random
        # ========================================
        print("\n[STEP 5] Random Exchange")
        responses.clear()
        await client.write_gatt_char(MESH_PROV_IN, build_proxy_pdu(0x03, bytes([PROV_RANDOM]) + random_prov), response=False)
        response = await wait_response()
        if not response or response[1] != PROV_RANDOM:
            print(f"  Failed: {response.hex() if response else 'no response'}")
            return
        device_random = response[2:18]

        # Verify
        expected_conf = aes_cmac(conf_key, device_random + auth_value)
        if expected_conf != device_conf:
            print("  Confirmation mismatch!")
            return
        print("  OK - Confirmation VERIFIED!")

        # ========================================
        # STEP 6: Provisioning Data
        # ========================================
        print("\n[STEP 6] Provisioning Data")

        # Generate keys
        network_key = secrets.token_bytes(16)
        key_index = 0
        flags = 0x00
        iv_index = 0
        unicast_address = 0x0001

        # Provisioning data (25 bytes) - Big Endian per Mesh spec
        prov_data = (
            network_key +                      # 16 bytes
            struct.pack(">H", key_index) +     # 2 bytes (big endian)
            bytes([flags]) +                   # 1 byte
            struct.pack(">I", iv_index) +      # 4 bytes (big endian)
            struct.pack(">H", unicast_address) # 2 bytes (big endian)
        )
        print(f"  Provisioning data: {len(prov_data)} bytes")
        print(f"  Prov data hex: {prov_data.hex()}")

        # Derive session keys (Mesh spec section 5.4.2.5)
        prov_salt = s1(conf_salt + random_prov + device_random)
        session_key = k1(shared_secret, prov_salt, b"prsk")
        # Session nonce is first 13 bytes of k1 with "prsn"
        session_nonce_full = k1(shared_secret, prov_salt, b"prsn")
        session_nonce = session_nonce_full[:13]
        device_key = k1(shared_secret, prov_salt, b"prdk")

        print(f"  Prov salt: {prov_salt.hex()}")
        print(f"  Session nonce full: {session_nonce_full.hex()}")

        print(f"  Session key: {session_key.hex()}")
        print(f"  Session nonce: {session_nonce.hex()}")
        print(f"  Device key: {device_key.hex()}")
        print(f"  Network key: {network_key.hex()}")

        # Encrypt with AES-CCM (8-byte MIC)
        # Try with empty AAD first
        encrypted_data = aes_ccm_encrypt(session_key, session_nonce, prov_data, b'')
        print(f"  Encrypted data (no AAD): {len(encrypted_data)} bytes")
        print(f"  Encrypted: {encrypted_data.hex()}")

        # Also compute what it would be with PDU type as AAD
        encrypted_with_aad = aes_ccm_encrypt(session_key, session_nonce, prov_data, bytes([PROV_DATA]))
        print(f"  Encrypted (with AAD=0x07): {encrypted_with_aad.hex()}")

        # Try both versions - with and without AAD
        print("\n  Trying with no AAD first...")
        data_pdu = bytes([PROV_DATA]) + encrypted_data
        print(f"  Sending: {data_pdu.hex()}")

        responses.clear()
        await send_segmented(client, MESH_PROV_IN, data_pdu)

        response = await wait_response(timeout=10.0)

        if response:
            prov_type = response[1] if len(response) > 1 else 0
            if prov_type == PROV_COMPLETE:
                print()
                print("=" * 70)
                print("PROVISIONING COMPLETE!")
                print("=" * 70)
                print()
                print(f"Network Key: {network_key.hex()}")
                print(f"Device Key:  {device_key.hex()}")
                print(f"Address:     0x{unicast_address:04x}")
                print()
                print("The device is now provisioned and should respond to mesh commands!")

            elif prov_type == PROV_FAILED:
                fail_code = response[2] if len(response) > 2 else 0
                fail_names = {
                    0: "PROHIBITED", 1: "INVALID_PDU", 2: "INVALID_FORMAT",
                    3: "UNEXPECTED_PDU", 4: "CONFIRMATION_FAILED",
                    5: "OUT_OF_RESOURCES", 6: "DECRYPTION_FAILED",
                    7: "UNEXPECTED_ERROR", 8: "CANNOT_ASSIGN_ADDRESSES"
                }
                print(f"  FAILED: {fail_names.get(fail_code, fail_code)}")

                # If decryption failed, we need to restart provisioning
                if fail_code == 6:
                    print("\n  Note: AES-CCM encryption parameters may need adjustment.")
                    print("  This could be due to:")
                    print("    - Nonce format differences")
                    print("    - CCM M/L parameter mismatch")
                    print("    - Endianness issues in key derivation")
                    print("\n  Keys generated (save for debugging):")
                    print(f"    Network Key: {network_key.hex()}")
                    print(f"    Device Key:  {device_key.hex()}")
                    print(f"    Session Key: {session_key.hex()}")
                    print(f"    Session Nonce: {session_nonce.hex()}")
                    print(f"    Prov Data: {prov_data.hex()}")
            else:
                print(f"  Unexpected response: {response.hex()}")
        else:
            print("  No response to provisioning data")

        # Wait a bit and check for any more responses
        print("\n[Waiting for additional responses...]")
        for _ in range(5):
            await asyncio.sleep(1.0)
            if responses:
                print(f"  Got: {responses[-1].hex()}")

if __name__ == "__main__":
    asyncio.run(main())
