#!/usr/bin/env python3
"""
Comprehensive Session Key Cracker

Try all possible key derivations from:
1. Initial notification data
2. Known device values
3. Various hash/combine methods
"""

import hashlib
from Crypto.Cipher import AES

# Known plaintext-ciphertext pairs from HCI log
PAIRS = [
    {
        "name": "Network Name",
        "ciphertext": bytes.fromhex("5b7eab67f223368e4a7bc65139b4d9f5"),
        "plaintext": b"out_of_mesh\x05\x05\x05\x05\x05",  # PKCS7 padded to 16 bytes
    },
    {
        "name": "Password",
        "ciphertext": bytes.fromhex("74cc2e38baf1ef4484139556e9c4746e"),
        "plaintext": b"123456\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a",  # PKCS7 padded
    },
    {
        "name": "LTK",
        "ciphertext": bytes.fromhex("1061bdc9e752c21621b2a1eb0cb1968f"),
        "plaintext": bytes.fromhex("D00710A0A601370854E32E177AFD1159"),
    },
]

# Initial notification data - might contain device random
INITIAL_NOTIFY = bytes.fromhex("010100efbb755d239432fc0000000032bd9bc1d371a887")

# Known values
NETWORK_NAME = b"out_of_mesh"
PASSWORD = b"123456"
NETWORK_KEY = bytes.fromhex("D00710A0A601370854E32E177AFD1159")

def reverse_bytes(data: bytes) -> bytes:
    return data[::-1]

def try_key(key: bytes, name: str):
    """Try a key against all known pairs"""
    if len(key) != 16:
        return False

    cipher = AES.new(key, AES.MODE_ECB)

    for pair in PAIRS:
        ct = pair["ciphertext"]
        pt = pair["plaintext"]

        # Try different decryption modes
        modes = [
            ("ECB", cipher.decrypt(ct)),
            ("ECB-Rev", reverse_bytes(cipher.decrypt(reverse_bytes(ct)))),
        ]

        for mode_name, result in modes:
            if result == pt:
                print(f"[SUCCESS!] Key found: {key.hex()}")
                print(f"  Method: {name}")
                print(f"  Mode: {mode_name}")
                print(f"  Matched: {pair['name']}")
                return True

    return False

def extract_randoms_from_notify(data: bytes) -> list:
    """Extract potential random values from notification"""
    randoms = []

    # Try various offsets and lengths
    for start in range(len(data) - 5):
        for length in [6, 8, 12, 16]:
            if start + length <= len(data):
                randoms.append(data[start:start+length])

    return randoms

def main():
    print("="*80)
    print("COMPREHENSIVE SESSION KEY CRACKER")
    print("="*80)

    attempts = 0

    # 1. Try key derivations from initial notification
    print("\n[1] Trying keys from initial notification...")
    randoms = extract_randoms_from_notify(INITIAL_NOTIFY)

    for random in randoms:
        # MD5(random)
        key = hashlib.md5(random).digest()
        if try_key(key, f"MD5({random.hex()})"):
            return
        attempts += 1

        # MD5(random + password)
        key = hashlib.md5(random + PASSWORD).digest()
        if try_key(key, f"MD5({random.hex()} + password)"):
            return
        attempts += 1

        # MD5(password + random)
        key = hashlib.md5(PASSWORD + random).digest()
        if try_key(key, f"MD5(password + {random.hex()})"):
            return
        attempts += 1

    # 2. Try static keys
    print(f"\n[2] Trying static keys...")
    static_keys = [
        ("Network Key", NETWORK_KEY),
        ("MD5(password)", hashlib.md5(PASSWORD).digest()),
        ("MD5(network_name)", hashlib.md5(NETWORK_NAME).digest()),
        ("MD5(network_key)", hashlib.md5(NETWORK_KEY).digest()),
        ("MD5(password+network_name)", hashlib.md5(PASSWORD + NETWORK_NAME).digest()),
        ("MD5(network_name+password)", hashlib.md5(NETWORK_NAME + PASSWORD).digest()),
        ("All zeros", bytes(16)),
        ("All 0xFF", bytes([0xFF] * 16)),
        # Telink default keys
        ("Telink default 1", bytes.fromhex("00000000000000000000000000000000")),
        ("Telink default 2", bytes.fromhex("01020304050607080102030405060708")),
    ]

    for name, key in static_keys:
        if try_key(key, name):
            return
        attempts += 1

    # 3. Try XOR-based key derivation
    print(f"\n[3] Trying XOR-based derivations...")
    # XOR network name with password (zero-padded)
    name_padded = NETWORK_NAME.ljust(16, b'\x00')
    pass_padded = PASSWORD.ljust(16, b'\x00')
    xor_key = bytes(a ^ b for a, b in zip(name_padded, pass_padded))
    if try_key(xor_key, "XOR(network_name, password)"):
        return
    attempts += 1

    # 4. Try reversed keys
    print(f"\n[4] Trying reversed keys...")
    for name, key in static_keys:
        rev_key = reverse_bytes(key)
        if try_key(rev_key, f"Reversed {name}"):
            return
        attempts += 1

    # 5. Try key=plaintext approach (for self-encrypted data)
    print(f"\n[5] Trying plaintext-as-key approach...")
    for pair in PAIRS:
        pt = pair["plaintext"]
        if len(pt) == 16:
            if try_key(pt, f"Plaintext as key ({pair['name']})"):
                return
        attempts += 1

    # 6. Brute force common patterns
    print(f"\n[6] Trying common patterns...")
    patterns = [
        bytes([i] * 16) for i in range(256)  # Single byte repeated
    ]
    for key in patterns[:50]:  # Limit to first 50
        if try_key(key, f"Pattern {key[0]:02x}"):
            return
        attempts += 1

    print(f"\n{'='*80}")
    print(f"RESULT: No key found after {attempts} attempts")
    print(f"{'='*80}")

    # Analysis
    print("\n[ANALYSIS]")
    print("The encryption key is likely derived from:")
    print("1. A unique device identifier not in the notification")
    print("2. A cloud-provisioned key from the Cync server")
    print("3. A combination we haven't discovered yet")
    print("\nNext steps:")
    print("- Capture fresh pairing with HCI log enabled BEFORE pairing")
    print("- Extract keys from phone app storage (requires root)")
    print("- Analyze native library more deeply with Ghidra")

if __name__ == "__main__":
    main()
