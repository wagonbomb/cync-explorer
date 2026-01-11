#!/usr/bin/env python3
"""
btsnooz Decompressor - Convert Android's compressed btsnooz format to btsnoop
Based on: https://android.googlesource.com/platform/packages/modules/Bluetooth/+/refs/heads/master/system/tools/scripts/btsnooz.py
"""

import sys
import struct
import zlib
from pathlib import Path

def decompress_btsnooz(input_path, output_path):
    """Decompress btsnooz format to btsnoop format"""
    print(f"Reading btsnooz file: {input_path}")

    with open(input_path, 'rb') as f:
        data = f.read()

    print(f"Input file size: {len(data)} bytes")

    if len(data) < 9:
        print("[ERROR] File too small to be valid btsnooz format")
        return False

    # Parse 9-byte header
    # Byte 0: version (should be 1 or 2)
    # Bytes 1-8: last timestamp (uint64, little-endian)
    version, last_timestamp = struct.unpack('=bQ', data[0:9])

    print(f"btsnooz version: {version}")
    print(f"Last timestamp: {last_timestamp}")

    # Decompress the data after the 9-byte header
    compressed_data = data[9:]
    print(f"Compressed data size: {len(compressed_data)} bytes")

    try:
        print("Decompressing...")
        decompressed_data = zlib.decompress(compressed_data)
        print(f"Decompressed size: {len(decompressed_data)} bytes")
    except zlib.error as e:
        print(f"[ERROR] Decompression failed: {e}")
        return False

    # The decompressed data should be in btsnoop format
    # Verify it has the btsnoop magic header
    if len(decompressed_data) < 16:
        print("[ERROR] Decompressed data too small")
        return False

    if decompressed_data[0:8] == b'btsnoop\x00':
        print("[OK] Valid btsnoop format detected")
    else:
        print("[WARNING] btsnoop magic header not found")
        magic = decompressed_data[0:8]
        print(f"  Found: {magic.hex()}")

    # Write to output file
    print(f"Writing btsnoop file: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(decompressed_data)

    print(f"[SUCCESS] Decompression complete: {output_path}")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/btsnooz_decompress.py <input.log> [output.log]")
        print("\nExample:")
        print("  python src/btsnooz_decompress.py artifacts/hci_logs/btsnooz_hci.log artifacts/hci_logs/btsnoop_hci.log")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}")
        sys.exit(1)

    # Determine output path
    if len(sys.argv) >= 3:
        output_path = Path(sys.argv[2])
    else:
        # Default: replace btsnooz with btsnoop in filename
        output_path = input_path.with_name(input_path.name.replace('btsnooz', 'btsnoop'))

    success = decompress_btsnooz(input_path, output_path)
    sys.exit(0 if success else 1)
