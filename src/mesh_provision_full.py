#!/usr/bin/env python3
"""
Complete BLE Mesh Provisioning Implementation
=============================================

Follows Bluetooth Mesh Profile Specification v1.0.
Implements full ECDH key exchange and encrypted provisioning.

Target: Factory-reset GE Cync bulb (telink_mesh1)
"""

import asyncio
import os
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

TARGET_MAC = "34:13:43:46:CA:84"

# UUIDs
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

# Network credentials to provision
NET_KEY = bytes.fromhex("D00710A0A601370854E32E177AFD1159")
KEY_INDEX = bytes([0x00, 0x00])
FLAGS = bytes([0x00])
IV_INDEX = bytes([0x00, 0x00, 0x00, 0x00])
UNICAST_ADDR = bytes([0x00, 0x01])

# State
responses = []
response_event = asyncio.Event()

def notification_handler(sender, data):
    hex_data = data.hex()
    print(f"  <- {hex_data}")
    responses.append(data)
    response_event.set()

async def send_pdu(client, pdu: bytes, timeout=5.0):
    global responses, response_event
    responses.clear()
    response_event.clear()

    print(f"  -> {pdu.hex()}")
    await client.write_gatt_char(MESH_PROV_IN, pdu, response=False)

    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.1)
        return responses[-1] if responses else None
    except asyncio.TimeoutError:
        print(f"     (timeout)")
        return None

# ============================================================================
# BLE Mesh Crypto Functions
# ============================================================================

def aes_cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg)
    return c.digest()

def s1(m: bytes) -> bytes:
    return aes_cmac(bytes(16), m)

def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    t = aes_cmac(salt, n)
    return aes_cmac(t, p)

def reverse_bytes(data: bytes) -> bytes:
    return data[::-1]

def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    pub_x = numbers.x.to_bytes(32, 'big')
    pub_y = numbers.y.to_bytes(32, 'big')
    return private_key, pub_x + pub_y

def compute_ecdh_secret(private_key, peer_public_bytes: bytes) -> bytes:
    peer_x = int.from_bytes(peer_public_bytes[:32], 'big')
    peer_y = int.from_bytes(peer_public_bytes[32:], 'big')
    peer_public_numbers = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1())
    peer_public_key = peer_public_numbers.public_key(default_backend())
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

def ccm_encrypt(key, nonce, plaintext, mac_len=8):
    """Standard AES-CCM encryption"""
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mac_len)
    return cipher.encrypt_and_digest(plaintext)

def ccm_encrypt_telink(key, nonce, plaintext, mac_len=8):
    """Telink-style CCM with byte reversal"""
    # Reverse inputs
    rev_key = reverse_bytes(key)
    rev_nonce = reverse_bytes(nonce)
    rev_pt = reverse_bytes(plaintext)

    cipher = AES.new(rev_key, AES.MODE_CCM, nonce=rev_nonce, mac_len=mac_len)
    enc, mic = cipher.encrypt_and_digest(rev_pt)

    # Reverse outputs
    return reverse_bytes(enc), reverse_bytes(mic)

# ============================================================================
# Provisioning Protocol
# ============================================================================

async def provision_device(client: BleakClient):
    """Execute full provisioning protocol with multiple strategy variations"""

    print("\n" + "=" * 70)
    print("STEP 1: Provisioning Invite")
    print("=" * 70)

    invite_pdu = bytes([0x00, 0x00])  # Invite with 0s attention
    resp = await send_pdu(client, invite_pdu)

    if not resp or resp[0] != 0x01:
        print("[ERROR] No Capabilities response")
        return False

    caps = resp
    print(f"\nCapabilities ({len(caps)} bytes): {caps.hex()}")
    print(f"  NumElements: {caps[1]}")
    print(f"  Algorithms: {caps[2]:02x}{caps[3]:02x}")
    print(f"  PublicKeyType: {caps[4]}")
    print(f"  StaticOOBType: {caps[5]}")
    print(f"  OutputOOBSize: {caps[6]}")
    print(f"  OutputOOBAction: {caps[7]:02x}{caps[8]:02x}")
    print(f"  InputOOBSize: {caps[9]}")
    print(f"  InputOOBAction: {caps[10]:02x}{caps[11]:02x}")

    print("\n" + "=" * 70)
    print("STEP 2: Provisioning Start")
    print("=" * 70)

    start_pdu = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
    await send_pdu(client, start_pdu, timeout=2.0)
    await asyncio.sleep(0.3)

    print("\n" + "=" * 70)
    print("STEP 3: Public Key Exchange")
    print("=" * 70)

    priv_key, pub_key = generate_ecdh_keypair()
    print(f"ProvPubKey: {pub_key.hex()}")

    pubkey_pdu = bytes([0x03]) + pub_key
    resp = await send_pdu(client, pubkey_pdu, timeout=5.0)

    if not resp or resp[0] != 0x03:
        print("[ERROR] No Public Key response")
        return False

    dev_pub = resp[1:65]
    print(f"DevPubKey: {dev_pub.hex()}")

    ecdh_secret = compute_ecdh_secret(priv_key, dev_pub)
    print(f"ECDH Secret: {ecdh_secret.hex()}")

    print("\n" + "=" * 70)
    print("STEP 4: Confirmation")
    print("=" * 70)

    # Try both ConfirmationInputs formats
    # Format A: Parameters only (per spec section 5.4.2.4)
    invite_params = invite_pdu[1:2]  # 1 byte
    caps_params = caps[1:12]  # 11 bytes
    start_params = start_pdu[1:6]  # 5 bytes
    conf_inputs_a = invite_params + caps_params + start_params + pub_key + dev_pub
    print(f"ConfInputs Format A ({len(conf_inputs_a)} bytes): params only")

    # Format B: Full PDUs with type bytes
    conf_inputs_b = invite_pdu + caps + start_pdu + bytes([0x03]) + pub_key + bytes([0x03]) + dev_pub
    print(f"ConfInputs Format B ({len(conf_inputs_b)} bytes): full PDUs")

    # Use Format A (spec compliant)
    conf_inputs = conf_inputs_a
    print(f"\nUsing Format A: {conf_inputs[:30].hex()}...")

    conf_salt = s1(conf_inputs)
    print(f"ConfirmationSalt: {conf_salt.hex()}")

    conf_key = k1(ecdh_secret, conf_salt, b"prck")
    print(f"ConfirmationKey: {conf_key.hex()}")

    prov_random = os.urandom(16)
    auth_value = bytes(16)  # No OOB
    print(f"ProvRandom: {prov_random.hex()}")
    print(f"AuthValue: {auth_value.hex()}")

    prov_conf = aes_cmac(conf_key, prov_random + auth_value)
    print(f"ProvConfirmation: {prov_conf.hex()}")

    conf_pdu = bytes([0x05]) + prov_conf
    resp = await send_pdu(client, conf_pdu, timeout=5.0)

    if not resp or resp[0] != 0x05:
        print("[ERROR] No Confirmation response")
        return False

    dev_conf = resp[1:17]
    print(f"DevConfirmation: {dev_conf.hex()}")

    print("\n" + "=" * 70)
    print("STEP 5: Random Exchange")
    print("=" * 70)

    random_pdu = bytes([0x06]) + prov_random
    resp = await send_pdu(client, random_pdu, timeout=5.0)

    if not resp or resp[0] != 0x06:
        print("[ERROR] No Random response")
        return False

    dev_random = resp[1:17]
    print(f"DevRandom: {dev_random.hex()}")

    # Verify device confirmation
    expected_dev_conf = aes_cmac(conf_key, dev_random + auth_value)
    print(f"Expected DevConf: {expected_dev_conf.hex()}")

    if dev_conf != expected_dev_conf:
        print("[ERROR] Device confirmation mismatch!")
        print("Trying Format B for ConfirmationInputs...")

        # Try Format B
        conf_salt = s1(conf_inputs_b)
        conf_key = k1(ecdh_secret, conf_salt, b"prck")
        expected_dev_conf = aes_cmac(conf_key, dev_random + auth_value)
        print(f"Format B Expected: {expected_dev_conf.hex()}")

        if dev_conf != expected_dev_conf:
            print("[ERROR] Format B also failed")
            return False
        else:
            print("[OK] Format B works! Using that...")
            conf_inputs = conf_inputs_b

    print("[OK] Device confirmation verified!")

    print("\n" + "=" * 70)
    print("STEP 6: Provisioning Data (Multiple Strategies)")
    print("=" * 70)

    prov_salt = s1(conf_salt + prov_random + dev_random)
    print(f"ProvisioningSalt: {prov_salt.hex()}")

    sess_key = k1(ecdh_secret, prov_salt, b"prsk")
    print(f"SessionKey: {sess_key.hex()}")

    nonce_full = k1(ecdh_secret, prov_salt, b"prsn")
    print(f"NonceRaw (16 bytes): {nonce_full.hex()}")

    prov_data = NET_KEY + KEY_INDEX + FLAGS + IV_INDEX + UNICAST_ADDR
    print(f"ProvData ({len(prov_data)} bytes): {prov_data.hex()}")

    # Try multiple encryption strategies
    strategies = [
        ("Standard CCM, nonce[0:13]", sess_key, nonce_full[:13], ccm_encrypt, prov_data),
        ("Standard CCM, nonce[3:16]", sess_key, nonce_full[3:16], ccm_encrypt, prov_data),
        ("Telink CCM, nonce[0:13]", sess_key, nonce_full[:13], ccm_encrypt_telink, prov_data),
        ("Standard CCM reversed key", reverse_bytes(sess_key), nonce_full[:13], ccm_encrypt, prov_data),
        ("Standard CCM reversed nonce", sess_key, reverse_bytes(nonce_full[:13]), ccm_encrypt, prov_data),
    ]

    for name, key, nonce, encrypt_fn, data in strategies:
        print(f"\n--- Strategy: {name} ---")
        print(f"  Key: {key.hex()}")
        print(f"  Nonce: {nonce.hex()}")

        try:
            encrypted, mic = encrypt_fn(key, nonce, data)
            print(f"  Encrypted: {encrypted.hex()}")
            print(f"  MIC: {mic.hex()}")

            data_pdu = bytes([0x07]) + encrypted + mic
            print(f"  PDU: {data_pdu.hex()}")

            resp = await send_pdu(client, data_pdu, timeout=5.0)

            if resp:
                print(f"  Response: {resp.hex()}")
                if resp[0] == 0x08:
                    print(f"\n[SUCCESS] Provisioning Complete with: {name}")
                    return True
                elif resp[0] == 0x09:
                    error = resp[1] if len(resp) > 1 else 0
                    error_name = {
                        0x01: "InvalidPDU", 0x02: "InvalidFormat", 0x03: "UnexpectedPDU",
                        0x04: "ConfirmationFailed", 0x05: "OutOfResources",
                        0x06: "DecryptionFailed", 0x07: "UnexpectedError",
                        0x08: "CannotAssign"
                    }.get(error, f"Unknown({error})")
                    print(f"  Error: {error_name}")

                    # If DecryptionFailed, need to reconnect
                    if error == 0x06:
                        print("  Device rejected - need to reconnect for retry")
            else:
                print("  No response")

        except Exception as e:
            print(f"  Exception: {e}")

    print("\n[ERROR] All strategies failed")
    return False

async def test_control(client: BleakClient):
    """Test light control after provisioning"""
    print("\n" + "=" * 70)
    print("TESTING LIGHT CONTROL")
    print("=" * 70)

    MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"

    commands = [
        ("ON", "b0c00101"),
        ("OFF", "b0c00100"),
    ]

    for name, cmd_hex in commands:
        print(f"\n{name}: {cmd_hex}")
        try:
            await client.write_gatt_char(MESH_PROXY_IN, bytes.fromhex(cmd_hex), response=False)
            await asyncio.sleep(2.0)
        except Exception as e:
            print(f"  Error: {e}")

async def main():
    print("=" * 70)
    print("BLE MESH PROVISIONING - COMPLETE IMPLEMENTATION")
    print("=" * 70)
    print(f"Target: {TARGET_MAC}")
    print(f"NetKey: {NET_KEY.hex()}")
    print("=" * 70)

    print("\nScanning for device...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)

    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name} ({device.address})")

    async with BleakClient(device, timeout=20.0) as client:
        print(f"[OK] Connected (MTU: {client.mtu_size})")

        await client.start_notify(MESH_PROV_OUT, notification_handler)
        await asyncio.sleep(0.5)

        success = await provision_device(client)

        if success:
            await test_control(client)

        print("\n" + "=" * 70)
        print("DONE")
        print("=" * 70)

if __name__ == "__main__":
    asyncio.run(main())
