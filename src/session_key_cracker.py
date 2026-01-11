#!/usr/bin/env python3
"""
Session Key Cracker - Derive session key using discovered algorithm

Based on reverse engineering findings:
- Session key = MD5(deviceRandom + loginKey)
- Commands encrypted with AES-128-ECB
- Telink uses byte reversal before/after AES
"""

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Known from HCI capture - encrypted pairing data
ENCRYPTED_NETWORK_NAME = bytes.fromhex("5b7eab67f223368e4a7bc65139b4d9f5")
ENCRYPTED_PASSWORD = bytes.fromhex("74cc2e38baf1ef4484139556e9c4746e")
ENCRYPTED_LTK = bytes.fromhex("1061bdc9e752c21621b2a1eb0cb1968f")

# Known plaintexts
PLAINTEXT_NETWORK_NAME = pad(b"out_of_mesh", 16)  # Padded to 16 bytes
PLAINTEXT_PASSWORD = pad(b"123456", 16)
PLAINTEXT_LTK = bytes.fromhex("D00710A0A601370854E32E177AFD1159")

# Known default login key (password)
DEFAULT_LOGIN_KEY = "123456"

def reverse_bytes(data: bytes) -> bytes:
    """Reverse byte order (Telink implementation)"""
    return data[::-1]

def md5_hash(data: bytes) -> bytes:
    """MD5 hash - same as Java bbqbbdq.bdpdqbp()"""
    return hashlib.md5(data).digest()

def derive_session_key_md5(device_random: bytes, login_key: str) -> bytes:
    """Derive session key using MD5(deviceRandom + loginKey)"""
    combined = device_random + login_key.encode('utf-8')
    return md5_hash(combined)

def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128-ECB encryption"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-128-ECB decryption"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def aes_telink_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES encryption with Telink byte reversal"""
    reversed_pt = reverse_bytes(plaintext)
    encrypted = aes_ecb_encrypt(reversed_pt, key)
    return reverse_bytes(encrypted)

def aes_telink_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES decryption with Telink byte reversal"""
    reversed_ct = reverse_bytes(ciphertext)
    decrypted = aes_ecb_decrypt(reversed_ct, key)
    return reverse_bytes(decrypted)

def try_decrypt(ciphertext: bytes, key: bytes, plaintext: bytes, name: str):
    """Try to decrypt ciphertext and compare with known plaintext"""
    print(f"\n{name}:")
    print(f"  Ciphertext: {ciphertext.hex()}")
    print(f"  Expected:   {plaintext.hex()}")

    # Try different decryption methods
    methods = [
        ("AES-ECB direct", aes_ecb_decrypt(ciphertext, key)),
        ("AES-Telink", aes_telink_decrypt(ciphertext, key)),
    ]

    for method_name, result in methods:
        if result == plaintext:
            print(f"  >>> MATCH with {method_name}!")
            return True
        else:
            # Check partial match
            matches = sum(1 for a, b in zip(result, plaintext) if a == b)
            print(f"  {method_name}: {result.hex()} ({matches}/16 bytes match)")

    return False

def brute_force_device_random():
    """
    Try to find device random by testing common values.
    In real usage, device random is received during connection handshake.
    """
    print("="*80)
    print("SESSION KEY CRACKING - Brute Force Device Random")
    print("="*80)

    # Try known patterns from HCI log
    # The early commands to 0x001b might contain the device random
    possible_randoms = [
        # From HCI capture - early writes
        bytes.fromhex("a0a1a2a3a4a5a6a78db674711b855a79")[:12],
        bytes.fromhex("a0a1a2a3a4a5a6a7c0c0d4abef0d15c3")[:12],

        # Common test patterns
        bytes(12),  # All zeros
        bytes([0xa0 + i for i in range(12)]),  # Sequential

        # 12 bytes of known sequence
        bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]),
    ]

    for device_random in possible_randoms:
        print(f"\nTrying device random: {device_random.hex()}")

        # Derive session key using MD5
        session_key = derive_session_key_md5(device_random, DEFAULT_LOGIN_KEY)
        print(f"  Session key (MD5): {session_key.hex()}")

        # Try to decrypt known ciphertext
        match = try_decrypt(
            ENCRYPTED_NETWORK_NAME,
            session_key,
            PLAINTEXT_NETWORK_NAME,
            "Network Name"
        )

        if match:
            print("\n" + "="*80)
            print("SUCCESS! Session key found!")
            print(f"  Device Random: {device_random.hex()}")
            print(f"  Login Key: {DEFAULT_LOGIN_KEY}")
            print(f"  Session Key: {session_key.hex()}")
            print("="*80)
            return session_key, device_random

    return None, None

def test_known_session_keys():
    """Test with some guessed session keys"""
    print("\n" + "="*80)
    print("TESTING KNOWN/GUESSED SESSION KEYS")
    print("="*80)

    guessed_keys = [
        ("Network key as session", bytes.fromhex("D00710A0A601370854E32E177AFD1159")),
        ("MD5 of 'out_of_mesh'", md5_hash(b"out_of_mesh")),
        ("MD5 of '123456'", md5_hash(b"123456")),
        ("MD5 of 'out_of_mesh123456'", md5_hash(b"out_of_mesh123456")),
        ("MD5 of '123456out_of_mesh'", md5_hash(b"123456out_of_mesh")),
    ]

    for name, key in guessed_keys:
        print(f"\n{name}: {key.hex()}")
        try_decrypt(ENCRYPTED_NETWORK_NAME, key, PLAINTEXT_NETWORK_NAME, "  Network Name")

if __name__ == "__main__":
    # First try brute force with common device random values
    session_key, device_random = brute_force_device_random()

    if not session_key:
        # Try some guessed keys
        test_known_session_keys()

        print("\n" + "="*80)
        print("CONCLUSION")
        print("="*80)
        print("Could not find session key with simple brute force.")
        print("The device random is likely unique per session and")
        print("must be captured during the actual handshake.")
        print("\nNext step: Implement full handshake to receive device random.")
        print("="*80)
