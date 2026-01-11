#!/usr/bin/env python3
"""
Direct analysis of libBleLib.so - Extract functions, strings, and patterns
"""

import struct
from pathlib import Path

def extract_strings(data, min_length=4):
    """Extract printable ASCII strings from binary"""
    strings = []
    current = []
    start = 0

    for i, b in enumerate(data):
        if 32 <= b <= 126:  # Printable ASCII
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_length:
                strings.append((start, ''.join(current)))
            current = []

    if len(current) >= min_length:
        strings.append((start, ''.join(current)))

    return strings

def analyze_elf(filepath):
    """Analyze ELF file for symbols and strings"""
    with open(filepath, 'rb') as f:
        data = f.read()

    print("="*80)
    print(f"ANALYZING: {filepath}")
    print("="*80)
    print(f"Size: {len(data)} bytes")

    # Check ELF magic
    if data[:4] != b'\x7fELF':
        print("[ERROR] Not an ELF file")
        return

    # ELF class (32 or 64 bit)
    elf_class = data[4]
    print(f"ELF Class: {'64-bit' if elf_class == 2 else '32-bit'}")

    # Extract strings
    print("\n" + "="*80)
    print("STRINGS (potential function names, debug messages)")
    print("="*80)

    strings = extract_strings(data, min_length=6)

    # Filter interesting strings
    interesting_keywords = [
        'session', 'key', 'encrypt', 'decrypt', 'aes', 'crc',
        'send', 'recv', 'pkg', 'frame', 'klv', 'parse', 'made',
        'trsmitr', 'command', 'data', 'normal', 'request'
    ]

    for offset, s in strings:
        s_lower = s.lower()
        if any(kw in s_lower for kw in interesting_keywords):
            print(f"  [0x{offset:06x}] {s}")

    # Look for specific patterns
    print("\n" + "="*80)
    print("KEY FUNCTION PATTERNS")
    print("="*80)

    # Search for known function names in symbol table
    function_patterns = [
        b'made_session_key',
        b'trsmitr_send_pkg_encode',
        b'trsmitr_recv_pkg_decode',
        b'parseKLVData',
        b'parseDataRecived',
        b'getCommandRequestData',
        b'getNormalRequestData',
        b'init_crc8',
        b'Thing_OTACalcCRC',
        b'data_2_klvlist',
        b'klvlist_2_data',
    ]

    for pattern in function_patterns:
        idx = data.find(pattern)
        if idx >= 0:
            print(f"  FOUND: {pattern.decode()} at offset 0x{idx:06x}")

    # Look for AES S-box (common in crypto)
    aes_sbox_start = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
    sbox_idx = data.find(aes_sbox_start)
    if sbox_idx >= 0:
        print(f"  FOUND: AES S-Box at offset 0x{sbox_idx:06x} (confirms AES usage)")

    # Look for constant patterns we know from protocol
    print("\n" + "="*80)
    print("KNOWN PROTOCOL CONSTANTS")
    print("="*80)

    constants = [
        (b'\x00\x05\x01', "Handshake start (000501)"),
        (b'\x31\x00', "Sync packet base (3100)"),
        (b'\x32\x01\x19', "Auth finalize (320119)"),
        (b'\xc0', "Command marker (0xc0)"),
    ]

    for pattern, name in constants:
        idx = data.find(pattern)
        if idx >= 0:
            # Show context around the match
            context_start = max(0, idx - 4)
            context_end = min(len(data), idx + len(pattern) + 8)
            context = data[context_start:context_end]
            print(f"  FOUND: {name}")
            print(f"    Offset: 0x{idx:06x}")
            print(f"    Context: {context.hex()}")

    # Extract all debug messages
    print("\n" + "="*80)
    print("DEBUG STRINGS (format strings)")
    print("="*80)

    for offset, s in strings:
        if '%' in s or 'call' in s.lower() or 'error' in s.lower():
            print(f"  [0x{offset:06x}] {s}")

    # Analyze dynamic symbol table for JNI exports
    print("\n" + "="*80)
    print("SEARCHING FOR JNI EXPORTS")
    print("="*80)

    jni_patterns = [
        b'Java_com_',
        b'JNI_OnLoad',
        b'madeSessionKey',
        b'crc4otaPackage',
    ]

    for pattern in jni_patterns:
        idx = data.find(pattern)
        if idx >= 0:
            # Extract full string
            end = idx
            while end < len(data) and data[end] != 0:
                end += 1
            full_name = data[idx:end].decode('latin-1')
            print(f"  FOUND: {full_name} at 0x{idx:06x}")

if __name__ == "__main__":
    lib_path = Path("artifacts/apk_extracted/lib/arm64-v8a/libBleLib.so")
    if lib_path.exists():
        analyze_elf(lib_path)
    else:
        print(f"[ERROR] File not found: {lib_path}")
