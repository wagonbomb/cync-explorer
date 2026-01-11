#!/usr/bin/env python3
"""
Direct analysis of libBleLib.so using Python
Extract function names, strings, and basic structure without Ghidra
"""
import struct
from pathlib import Path

def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract ASCII strings from binary data"""
    strings = []
    current = bytearray()

    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode('ascii', errors='ignore'))
            current = bytearray()

    if len(current) >= min_length:
        strings.append(current.decode('ascii', errors='ignore'))

    return strings

def analyze_elf_basic(filepath: Path):
    """Basic ELF analysis without external dependencies"""
    data = filepath.read_bytes()

    # Check ELF magic
    if data[:4] != b'\x7fELF':
        return "Not an ELF file"

    results = {
        'size': len(data),
        'strings': extract_strings(data, min_length=4),
        'functions_found': []
    }

    # Look for function names in strings
    for s in results['strings']:
        if any(keyword in s.lower() for keyword in ['trsmitr', 'session', 'parse', 'klv', 'encode', 'decode', 'send', 'recv']):
            results['functions_found'].append(s)

    return results

if __name__ == "__main__":
    lib_path = Path(__file__).parents[1] / "artifacts" / "ghidra_analysis" / "libraries" / "libBleLib.so"

    if not lib_path.exists():
        print(f"Library not found: {lib_path}")
        exit(1)

    print("=" * 70)
    print("libBleLib.so Analysis")
    print("=" * 70)
    print()

    results = analyze_elf_basic(lib_path)

    if isinstance(results, str):
        print(results)
    else:
        print(f"File size: {results['size']:,} bytes")
        print()

        print("Potential function names found in strings:")
        for func in results['functions_found']:
            print(f"  - {func}")
        print()

        print(f"All strings ({len(results['strings'])} total):")
        for i, s in enumerate(results['strings'], 1):
            print(f"  {i:3d}. {s}")
