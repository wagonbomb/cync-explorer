#!/usr/bin/env python3
"""
Extract session key from known plaintext-ciphertext pairs
Uses AES-128-ECB with Telink byte reversal (from DEX analysis)
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def reverse_bytes(data: bytes) -> bytes:
    """Reverse byte order (Telink implementation)"""
    return data[::-1]

def decrypt_with_key(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt using AES/ECB with Telink byte reversal"""
    # Reverse ciphertext
    reversed_ct = reverse_bytes(ciphertext)

    # Decrypt
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(reversed_ct)

    # Reverse result
    return reverse_bytes(decrypted)

def try_brute_force_key(known_pairs):
    """
    Try to find the session key by brute force
    Since we don't know the key, we'll try known keys from DEX analysis
    """
    # Known keys from DEX analysis
    possible_keys = [
        bytes.fromhex("D00710A0A601370854E32E177AFD1159"),  # DEFAULT_NETWORK_KEY
        bytes.fromhex("a4c137686c1d8701287090ad3453e89c"),  # Example from bppbqbb
        b"out_of_mesh\x00\x00\x00\x00\x00",  # Padded mesh name
        b"123456\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # Padded password
    ]

    print("="*80)
    print("SESSION KEY EXTRACTION - Known Plaintext Attack")
    print("="*80)

    for plaintext, ciphertext, name in known_pairs:
        print(f"\n{name}:")
        print(f"  Plaintext:  {plaintext.hex()}")
        print(f"  Ciphertext: {ciphertext.hex()}")

        for i, key in enumerate(possible_keys, 1):
            decrypted = decrypt_with_key(ciphertext, key)
            print(f"\n  Try key {i}: {key.hex()}")
            print(f"    Decrypted: {decrypted.hex()}")

            if decrypted == plaintext:
                print(f"    >>> MATCH! Session key found: {key.hex()}")
                return key
            elif decrypted.startswith(plaintext[:4]):
                print(f"    >>> PARTIAL MATCH (first 4 bytes)")

    print("\n" + "="*80)
    print("No matching key found in known keys")
    print("="*80)
    return None

def analyze_encryption_pattern():
    """
    Analyze the encryption pattern without knowing the key
    Try to find relationships between plaintext/ciphertext
    """
    # Known plaintexts (padded to 16 bytes with 0x00)
    mesh_name_plain = pad(b"out_of_mesh", 16)
    password_plain = pad(b"123456", 16)
    ltk_plain = bytes.fromhex("D00710A0A601370854E32E177AFD1159")

    # Captured ciphertexts
    mesh_name_cipher = bytes.fromhex("5b7eab67f223368e4a7bc65139b4d9f5")
    password_cipher = bytes.fromhex("74cc2e38baf1ef4484139556e9c4746e")
    ltk_cipher = bytes.fromhex("1061bdc9e752c21621b2a1eb0cb1968f")

    known_pairs = [
        (mesh_name_plain, mesh_name_cipher, "Network Name"),
        (password_plain, password_cipher, "Password"),
        (ltk_plain, ltk_cipher, "LTK"),
    ]

    # Try to find the session key
    session_key = try_brute_force_key(known_pairs)

    if not session_key:
        print("\n" + "="*80)
        print("ALTERNATIVE APPROACH: XOR Analysis")
        print("="*80)

        for plaintext, ciphertext, name in known_pairs:
            print(f"\n{name}:")
            xor_result = bytes(p ^ c for p, c in zip(plaintext, ciphertext))
            print(f"  PT XOR CT: {xor_result.hex()}")

if __name__ == "__main__":
    analyze_encryption_pattern()
