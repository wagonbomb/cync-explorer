#!/usr/bin/env python3
"""
BLE Mesh Provisioning with Automatic Retry
==========================================

After each failed attempt, reconnects and tries a different strategy.
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
KEY_INDEX = bytes([0x00, 0x00])
FLAGS = bytes([0x00])
IV_INDEX = bytes([0x00, 0x00, 0x00, 0x00])
UNICAST_ADDR = bytes([0x00, 0x01])

responses = []
response_event = asyncio.Event()

def handler(sender, data):
    print(f"  <- {data.hex()}")
    responses.append(data)
    response_event.set()

async def send_pdu(client, pdu, timeout=5.0):
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
        return None

def aes_cmac(key, msg):
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg)
    return c.digest()

def s1(m): return aes_cmac(bytes(16), m)
def k1(n, salt, p): return aes_cmac(aes_cmac(salt, n), p)

def generate_keypair():
    pk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    nums = pk.public_key().public_numbers()
    return pk, nums.x.to_bytes(32, 'big') + nums.y.to_bytes(32, 'big')

def ecdh_secret(priv, peer):
    px, py = int.from_bytes(peer[:32], 'big'), int.from_bytes(peer[32:], 'big')
    peer_key = ec.EllipticCurvePublicNumbers(px, py, ec.SECP256R1()).public_key(default_backend())
    return priv.exchange(ec.ECDH(), peer_key)

def ccm_enc(key, nonce, pt):
    return AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8).encrypt_and_digest(pt)

# Different strategies to try
STRATEGIES = [
    {"name": "Standard (nonce 0:13)", "nonce_slice": (0, 13), "reverse": False},
    {"name": "Nonce 3:16", "nonce_slice": (3, 16), "reverse": False},
    {"name": "Reversed nonce", "nonce_slice": (0, 13), "reverse": True},
]

async def try_provision(strategy_idx):
    """Run one provisioning attempt with a specific strategy"""
    strat = STRATEGIES[strategy_idx]
    print(f"\n{'='*70}")
    print(f"ATTEMPT {strategy_idx + 1}: {strat['name']}")
    print(f"{'='*70}")

    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print("Device not found")
        return False

    print(f"Found: {device.name}")

    async with BleakClient(device, timeout=20.0) as client:
        print(f"Connected (MTU: {client.mtu_size})")
        await client.start_notify(MESH_PROV_OUT, handler)
        await asyncio.sleep(0.5)

        # Step 1: Invite
        print("\n[1] Invite")
        invite = bytes([0x00, 0x00])
        resp = await send_pdu(client, invite)
        if not resp or resp[0] != 0x01:
            print("No capabilities")
            return False
        caps = resp
        print(f"Capabilities: {caps.hex()}")

        # Step 2: Start
        print("\n[2] Start")
        start = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
        await send_pdu(client, start, timeout=2.0)
        await asyncio.sleep(0.3)

        # Step 3: Public Key
        print("\n[3] Public Key")
        priv, pub = generate_keypair()
        resp = await send_pdu(client, bytes([0x03]) + pub, timeout=5.0)
        if not resp or resp[0] != 0x03:
            print("No device public key")
            return False
        dev_pub = resp[1:65]
        ecdh = ecdh_secret(priv, dev_pub)
        print(f"ECDH: {ecdh.hex()}")

        # Step 4: Confirmation
        print("\n[4] Confirmation")
        # Use params-only format (145 bytes total)
        conf_inputs = invite[1:2] + caps[1:12] + start[1:6] + pub + dev_pub
        conf_salt = s1(conf_inputs)
        conf_key = k1(ecdh, conf_salt, b"prck")
        prov_rand = os.urandom(16)
        auth = bytes(16)
        prov_conf = aes_cmac(conf_key, prov_rand + auth)
        print(f"ProvConf: {prov_conf.hex()}")

        resp = await send_pdu(client, bytes([0x05]) + prov_conf, timeout=5.0)
        if not resp or resp[0] != 0x05:
            print("No confirmation response")
            return False
        dev_conf = resp[1:17]

        # Step 5: Random
        print("\n[5] Random")
        resp = await send_pdu(client, bytes([0x06]) + prov_rand, timeout=5.0)
        if not resp or resp[0] != 0x06:
            print("No random response")
            return False
        dev_rand = resp[1:17]

        # Verify
        expected = aes_cmac(conf_key, dev_rand + auth)
        if dev_conf != expected:
            print(f"Confirmation mismatch!")
            print(f"  Got:      {dev_conf.hex()}")
            print(f"  Expected: {expected.hex()}")
            return False
        print("Confirmation OK!")

        # Step 6: Provisioning Data
        print("\n[6] Provisioning Data")
        prov_salt = s1(conf_salt + prov_rand + dev_rand)
        sess_key = k1(ecdh, prov_salt, b"prsk")
        nonce_full = k1(ecdh, prov_salt, b"prsn")

        # Apply strategy
        a, b = strat["nonce_slice"]
        nonce = nonce_full[a:b]
        if strat["reverse"]:
            nonce = nonce[::-1]

        print(f"SessionKey: {sess_key.hex()}")
        print(f"Nonce: {nonce.hex()}")

        prov_data = NET_KEY + KEY_INDEX + FLAGS + IV_INDEX + UNICAST_ADDR
        print(f"ProvData: {prov_data.hex()}")

        enc, mic = ccm_enc(sess_key, nonce, prov_data)
        pdu = bytes([0x07]) + enc + mic
        print(f"PDU: {pdu.hex()}")

        resp = await send_pdu(client, pdu, timeout=5.0)
        if resp:
            print(f"Response: {resp.hex()}")
            if resp[0] == 0x08:
                print("\n*** PROVISIONING SUCCESS! ***")
                return True
            elif resp[0] == 0x09:
                err = resp[1] if len(resp) > 1 else 0
                errs = {1:"InvalidPDU", 2:"InvalidFormat", 3:"UnexpectedPDU",
                        4:"ConfirmationFailed", 5:"OutOfResources",
                        6:"DecryptionFailed", 7:"UnexpectedError", 8:"CannotAssign"}
                print(f"Error: {errs.get(err, err)}")
        else:
            print("No response")

        return False

async def main():
    print("="*70)
    print("BLE MESH PROVISIONING - RETRY MODE")
    print("="*70)
    print(f"Target: {TARGET_MAC}")
    print(f"NetKey: {NET_KEY.hex()}")
    print(f"Strategies to try: {len(STRATEGIES)}")

    for i in range(len(STRATEGIES)):
        success = await try_provision(i)
        if success:
            print("\n" + "="*70)
            print("PROVISIONING COMPLETE!")
            print("="*70)
            return

        print(f"\nStrategy {i+1} failed. Waiting 3s before reconnect...")
        await asyncio.sleep(3.0)

    print("\n" + "="*70)
    print("ALL STRATEGIES FAILED")
    print("="*70)
    print("\nPossible issues:")
    print("1. Telink uses non-standard key derivation in libBleLib.so")
    print("2. Need to capture actual provisioning with HCI log")
    print("3. Device may require Static OOB authentication")

if __name__ == "__main__":
    asyncio.run(main())
