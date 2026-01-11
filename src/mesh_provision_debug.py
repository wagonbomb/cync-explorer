#!/usr/bin/env python3
"""
BLE Mesh Provisioning Debug Script
==================================

Runs through the provisioning sequence and dumps all intermediate values
for debugging the DecryptionFailed error.

Usage: Factory reset the bulb first (power cycle 5x), then run this script.
"""

import asyncio
import os
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

TARGET_MAC = "34:13:43:46:CA:84"
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

NET_KEY = bytes.fromhex("D00710A0A601370854E32E177AFD1159")

responses = []
response_event = asyncio.Event()

def notification_handler(sender, data):
    print(f"  <- {data.hex()}")
    responses.append(data)
    response_event.set()

async def send_and_wait(client, pdu, timeout=5.0):
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
        print("     (timeout)")
        return None

# Crypto functions
def aes_cmac(key, msg):
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg)
    return c.digest()

def s1(m):
    result = aes_cmac(bytes(16), m)
    return result

def k1(n, salt, p):
    t = aes_cmac(salt, n)
    result = aes_cmac(t, p)
    return result

def generate_keypair():
    pk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    nums = pk.public_key().public_numbers()
    return pk, nums.x.to_bytes(32, 'big') + nums.y.to_bytes(32, 'big')

def ecdh_shared(priv, peer):
    px = int.from_bytes(peer[:32], 'big')
    py = int.from_bytes(peer[32:], 'big')
    peer_key = ec.EllipticCurvePublicNumbers(px, py, ec.SECP256R1()).public_key(default_backend())
    return priv.exchange(ec.ECDH(), peer_key)

async def main():
    print("=" * 80)
    print("BLE MESH PROVISIONING DEBUG")
    print("=" * 80)
    print(f"Target: {TARGET_MAC}")
    print()
    print("NOTE: Factory reset the bulb first! (power cycle 5x)")
    print("      Device should advertise as 'telink_mesh1'")
    print("=" * 80)

    # Scan
    print("\n[SCAN] Looking for device...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print("[ERROR] Device not found!")
        return

    print(f"Found: {device.name} ({device.address})")
    if device.name and "telink" in device.name.lower():
        print("[OK] Device appears to be in factory reset mode")
    else:
        print("[WARN] Device name is not 'telink_mesh1' - may not be in reset mode")

    async with BleakClient(device, timeout=20.0) as client:
        print(f"\n[CONNECT] Connected (MTU: {client.mtu_size})")
        await client.start_notify(MESH_PROV_OUT, notification_handler)
        await asyncio.sleep(0.5)

        # =================== STEP 1: INVITE ===================
        print("\n" + "=" * 80)
        print("STEP 1: PROVISIONING INVITE")
        print("=" * 80)
        invite_pdu = bytes([0x00, 0x00])  # Type 0x00, Attention 0x00
        resp = await send_and_wait(client, invite_pdu)

        if not resp or resp[0] != 0x01:
            print("[ERROR] No capabilities response - device not in provisioning mode")
            return

        caps = resp
        print(f"\nCapabilities PDU ({len(caps)} bytes): {caps.hex()}")
        print(f"  Type: 0x{caps[0]:02x} (should be 0x01)")
        print(f"  NumElements: {caps[1]}")
        print(f"  Algorithms: 0x{(caps[2] << 8 | caps[3]):04x}")
        print(f"  PublicKeyType: {caps[4]}")
        print(f"  StaticOOBType: {caps[5]}")
        print(f"  OutputOOBSize: {caps[6]}")
        print(f"  OutputOOBAction: 0x{(caps[7] << 8 | caps[8]):04x}")
        print(f"  InputOOBSize: {caps[9]}")
        print(f"  InputOOBAction: 0x{(caps[10] << 8 | caps[11]):04x}")

        # =================== STEP 2: START ===================
        print("\n" + "=" * 80)
        print("STEP 2: PROVISIONING START")
        print("=" * 80)
        # Algorithm=0 (FIPS P-256), PubKey=0 (No OOB), Auth=0 (No OOB)
        start_pdu = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
        await send_and_wait(client, start_pdu, timeout=2.0)
        await asyncio.sleep(0.3)

        # =================== STEP 3: PUBLIC KEY ===================
        print("\n" + "=" * 80)
        print("STEP 3: PUBLIC KEY EXCHANGE")
        print("=" * 80)
        priv_key, prov_pub = generate_keypair()
        print(f"Provisioner Public Key ({len(prov_pub)} bytes):")
        print(f"  X: {prov_pub[:32].hex()}")
        print(f"  Y: {prov_pub[32:].hex()}")

        pubkey_pdu = bytes([0x03]) + prov_pub
        resp = await send_and_wait(client, pubkey_pdu, timeout=5.0)

        if not resp or resp[0] != 0x03:
            print("[ERROR] No public key response")
            return

        dev_pub = resp[1:65]
        print(f"\nDevice Public Key ({len(dev_pub)} bytes):")
        print(f"  X: {dev_pub[:32].hex()}")
        print(f"  Y: {dev_pub[32:].hex()}")

        ecdh_secret = ecdh_shared(priv_key, dev_pub)
        print(f"\nECDH Shared Secret ({len(ecdh_secret)} bytes): {ecdh_secret.hex()}")

        # =================== STEP 4: CONFIRMATION ===================
        print("\n" + "=" * 80)
        print("STEP 4: CONFIRMATION")
        print("=" * 80)

        # ConfirmationInputs per BLE Mesh spec:
        # InviteAttnDuration(1) + CapabilitiesParams(11) + StartParams(5) +
        # ProvPubKey(64) + DevPubKey(64) = 145 bytes
        invite_params = invite_pdu[1:2]  # 1 byte
        caps_params = caps[1:12]  # 11 bytes (skip type)
        start_params = start_pdu[1:6]  # 5 bytes (skip type)

        conf_inputs = invite_params + caps_params + start_params + prov_pub + dev_pub
        print(f"\nConfirmationInputs ({len(conf_inputs)} bytes):")
        print(f"  InviteAttnDuration: {invite_params.hex()}")
        print(f"  CapabilitiesParams: {caps_params.hex()}")
        print(f"  StartParams: {start_params.hex()}")
        print(f"  ProvPubKey: {prov_pub[:16].hex()}...")
        print(f"  DevPubKey: {dev_pub[:16].hex()}...")
        print(f"  Full SHA256: (for reference)")

        conf_salt = s1(conf_inputs)
        print(f"\nConfirmationSalt = s1(ConfInputs)")
        print(f"  = {conf_salt.hex()}")

        conf_key = k1(ecdh_secret, conf_salt, b"prck")
        print(f"\nConfirmationKey = k1(ECDH, ConfSalt, 'prck')")
        print(f"  = {conf_key.hex()}")

        prov_random = os.urandom(16)
        auth_value = bytes(16)  # No OOB = all zeros
        print(f"\nProvisionerRandom: {prov_random.hex()}")
        print(f"AuthValue (No OOB): {auth_value.hex()}")

        prov_conf = aes_cmac(conf_key, prov_random + auth_value)
        print(f"\nProvisionerConfirmation = CMAC(ConfKey, ProvRand || Auth)")
        print(f"  = {prov_conf.hex()}")

        conf_pdu = bytes([0x05]) + prov_conf
        resp = await send_and_wait(client, conf_pdu, timeout=5.0)

        if not resp or resp[0] != 0x05:
            print("[ERROR] No confirmation response")
            return

        dev_conf = resp[1:17]
        print(f"\nDeviceConfirmation: {dev_conf.hex()}")

        # =================== STEP 5: RANDOM ===================
        print("\n" + "=" * 80)
        print("STEP 5: RANDOM EXCHANGE")
        print("=" * 80)

        random_pdu = bytes([0x06]) + prov_random
        resp = await send_and_wait(client, random_pdu, timeout=5.0)

        if not resp or resp[0] != 0x06:
            print("[ERROR] No random response")
            return

        dev_random = resp[1:17]
        print(f"DeviceRandom: {dev_random.hex()}")

        expected_dev_conf = aes_cmac(conf_key, dev_random + auth_value)
        print(f"\nExpected DevConf = CMAC(ConfKey, DevRand || Auth)")
        print(f"  = {expected_dev_conf.hex()}")

        if dev_conf != expected_dev_conf:
            print("[ERROR] Device confirmation MISMATCH!")
            print("  This means our ConfirmationInputs format is wrong.")
            return

        print("[OK] Device confirmation VERIFIED!")

        # =================== STEP 6: PROVISIONING DATA ===================
        print("\n" + "=" * 80)
        print("STEP 6: PROVISIONING DATA")
        print("=" * 80)

        prov_salt = s1(conf_salt + prov_random + dev_random)
        print(f"\nProvisioningSalt = s1(ConfSalt || ProvRand || DevRand)")
        print(f"  Input: {conf_salt.hex()} || {prov_random.hex()} || {dev_random.hex()}")
        print(f"  = {prov_salt.hex()}")

        sess_key = k1(ecdh_secret, prov_salt, b"prsk")
        print(f"\nSessionKey = k1(ECDH, ProvSalt, 'prsk')")
        print(f"  = {sess_key.hex()}")

        nonce_full = k1(ecdh_secret, prov_salt, b"prsn")
        print(f"\nSessionNonce = k1(ECDH, ProvSalt, 'prsn')")
        print(f"  Full (16 bytes): {nonce_full.hex()}")
        print(f"  [0:13]: {nonce_full[:13].hex()}")
        print(f"  [3:16]: {nonce_full[3:16].hex()}")

        # Build provisioning data
        key_index = bytes([0x00, 0x00])
        flags = bytes([0x00])
        iv_index = bytes([0x00, 0x00, 0x00, 0x00])
        unicast = bytes([0x00, 0x01])

        prov_data = NET_KEY + key_index + flags + iv_index + unicast
        print(f"\nProvisioningData ({len(prov_data)} bytes):")
        print(f"  NetKey: {NET_KEY.hex()}")
        print(f"  KeyIndex: {key_index.hex()}")
        print(f"  Flags: {flags.hex()}")
        print(f"  IVIndex: {iv_index.hex()}")
        print(f"  UnicastAddr: {unicast.hex()}")
        print(f"  Combined: {prov_data.hex()}")

        # Try encryption
        nonce = nonce_full[:13]
        print(f"\nAES-CCM Encryption:")
        print(f"  Key: {sess_key.hex()}")
        print(f"  Nonce: {nonce.hex()}")
        print(f"  Plaintext: {prov_data.hex()}")
        print(f"  MIC Length: 8 bytes")

        cipher = AES.new(sess_key, AES.MODE_CCM, nonce=nonce, mac_len=8)
        encrypted, mic = cipher.encrypt_and_digest(prov_data)
        print(f"  Encrypted: {encrypted.hex()}")
        print(f"  MIC: {mic.hex()}")

        # Verify self-decryption
        cipher_v = AES.new(sess_key, AES.MODE_CCM, nonce=nonce, mac_len=8)
        try:
            decrypted = cipher_v.decrypt_and_verify(encrypted, mic)
            print(f"  Self-verify: OK")
        except Exception as e:
            print(f"  Self-verify: FAILED ({e})")

        data_pdu = bytes([0x07]) + encrypted + mic
        print(f"\nProvisioning Data PDU ({len(data_pdu)} bytes): {data_pdu.hex()}")

        print("\n[SENDING] Provisioning Data PDU...")
        resp = await send_and_wait(client, data_pdu, timeout=5.0)

        if resp:
            print(f"\nResponse ({len(resp)} bytes): {resp.hex()}")
            if resp[0] == 0x08:
                print("\n" + "=" * 80)
                print("[SUCCESS] PROVISIONING COMPLETE!")
                print("=" * 80)
                print("Device is now provisioned with your NetKey.")
                print("Next: Use Mesh Proxy protocol to control the light.")
            elif resp[0] == 0x09:
                print("\n" + "=" * 80)
                print("[FAILED] PROVISIONING ERROR")
                print("=" * 80)
                error = resp[1] if len(resp) > 1 else 0
                errors = {
                    0x01: "Invalid PDU",
                    0x02: "Invalid Format",
                    0x03: "Unexpected PDU",
                    0x04: "Confirmation Failed",
                    0x05: "Out of Resources",
                    0x06: "Decryption Failed",
                    0x07: "Unexpected Error",
                    0x08: "Cannot Assign Addresses"
                }
                print(f"Error Code: 0x{error:02x} - {errors.get(error, 'Unknown')}")

                if error == 0x06:
                    print("\nAnalysis: DecryptionFailed means the device couldn't decrypt")
                    print("our Provisioning Data using the session key we derived.")
                    print("\nPossible causes:")
                    print("1. Nonce extraction wrong (bytes 0:13 vs 3:16 vs reversed)")
                    print("2. Session key derivation differs from spec")
                    print("3. Telink uses proprietary encryption layer")
                    print("4. CCM parameters differ (AAD, MIC length)")
        else:
            print("\n[ERROR] No response to Provisioning Data")

        print("\n" + "=" * 80)
        print("DEBUG DUMP COMPLETE")
        print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main())
