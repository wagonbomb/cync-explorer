#!/usr/bin/env python3
"""
Analyze btsnoop packet flags to understand direction encoding
"""

import sys
import struct
from pathlib import Path

def parse_btsnoop_header(data):
    if len(data) < 16 or data[0:8] != b'btsnoop\x00':
        return None
    version, datalink = struct.unpack('>II', data[8:16])
    return {'version': version, 'datalink': datalink}

def parse_btsnoop_packet(data, offset):
    if offset + 24 > len(data):
        return None, offset
    orig_len, incl_len, flags, drops, timestamp = struct.unpack('>IIIIQ', data[offset:offset+24])
    packet_data = data[offset+24:offset+24+incl_len]
    return {
        'flags': flags,
        'data': packet_data,
    }, offset + 24 + incl_len

def analyze_flags(log_path):
    with open(log_path, 'rb') as f:
        data = f.read()

    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file")
        return

    print(f"Datalink type: {header['datalink']}")
    print("\nFlag analysis for first 100 packets:\n")

    offset = 16
    packet_count = 0
    flag_counts = {}

    while offset < len(data) and packet_count < 100:
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        flags = packet['flags']
        pdata = packet['data']

        # Count flag patterns
        flag_counts[flags] = flag_counts.get(flags, 0) + 1

        # Show details for first 10
        if packet_count <= 10:
            pkt_type = pdata[0] if len(pdata) >= 1 else 0
            type_names = {0x01: "CMD", 0x02: "ACL", 0x03: "SCO", 0x04: "EVT"}
            type_name = type_names.get(pkt_type, f"0x{pkt_type:02x}")

            print(f"Packet {packet_count}: flags=0x{flags:08x} ({flags:032b})")
            print(f"  Type: {type_name}")
            print(f"  Bit 0 (sent flag): {flags & 0x01}")
            print(f"  Bit 1: {(flags >> 1) & 0x01}")
            print(f"  Bit 2: {(flags >> 2) & 0x01}")
            print(f"  First 16 bytes: {pdata[:16].hex()}")
            print()

    print("\nFlag distribution:")
    for flags, count in sorted(flag_counts.items()):
        print(f"  0x{flags:08x}: {count} packets")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/analyze_packet_flags.py <path_to_btsnoop_hci.log>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    analyze_flags(log_path)
