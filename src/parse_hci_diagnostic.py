#!/usr/bin/env python3
"""
Diagnostic HCI Log Parser - Show raw packet structure
"""

import sys
import struct
from pathlib import Path

def parse_btsnoop_header(data):
    """Parse btsnoop file header"""
    if len(data) < 16 or data[0:8] != b'btsnoop\x00':
        return None
    version, datalink = struct.unpack('>II', data[8:16])
    return {'version': version, 'datalink': datalink}

def parse_btsnoop_packet(data, offset):
    """Parse a single btsnoop packet record"""
    if offset + 24 > len(data):
        return None, offset

    orig_len, incl_len, flags, drops, timestamp = struct.unpack('>IIIIQ', data[offset:offset+24])
    packet_data = data[offset+24:offset+24+incl_len]

    return {
        'orig_len': orig_len,
        'incl_len': incl_len,
        'flags': flags,
        'timestamp': timestamp,
        'data': packet_data,
        'direction': 'sent' if (flags & 0x01) else 'received'
    }, offset + 24 + incl_len

def analyze_packet_structure(log_path):
    """Show first few packets with hex dumps"""
    with open(log_path, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes")

    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file format")
        return

    print(f"btsnoop version: {header['version']}")
    print(f"Datalink type: {header['datalink']}")
    print("\n" + "="*80)
    print("FIRST 10 PACKETS - RAW STRUCTURE")
    print("="*80)

    offset = 16
    packet_count = 0

    while offset < len(data) and packet_count < 10:
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        pdata = packet['data']

        print(f"\n[Packet {packet_count}] {packet['direction'].upper()}")
        print(f"  Length: {len(pdata)} bytes")
        print(f"  Flags: 0x{packet['flags']:08x}")

        # Show first 32 bytes in hex
        hex_preview = pdata[:32].hex()
        print(f"  First 32 bytes: {hex_preview}")

        # Try to identify packet type
        if len(pdata) >= 1:
            pkt_type = pdata[0]
            type_names = {
                0x01: "HCI Command",
                0x02: "HCI ACL Data",
                0x03: "HCI SCO Data",
                0x04: "HCI Event"
            }
            print(f"  Type byte: 0x{pkt_type:02x} ({type_names.get(pkt_type, 'Unknown')})")

            # If ACL data, show more details
            if pkt_type == 0x02 and len(pdata) >= 5:
                handle_flags = struct.unpack('<H', pdata[1:3])[0]
                handle = handle_flags & 0x0FFF
                data_len = struct.unpack('<H', pdata[3:5])[0]
                print(f"  ACL Handle: 0x{handle:03x}")
                print(f"  ACL Data Length: {data_len}")

                # Show L2CAP if present
                if len(pdata) >= 9:
                    l2cap_len = struct.unpack('<H', pdata[5:7])[0]
                    l2cap_cid = struct.unpack('<H', pdata[7:9])[0]
                    print(f"  L2CAP Length: {l2cap_len}")
                    print(f"  L2CAP CID: 0x{l2cap_cid:04x}")

                    # Show ATT if CID = 0x0004
                    if l2cap_cid == 0x0004 and len(pdata) >= 10:
                        att_opcode = pdata[9]
                        print(f"  ATT Opcode: 0x{att_opcode:02x}")

                        # If write command/request, show handle
                        if att_opcode in [0x12, 0x52] and len(pdata) >= 12:
                            att_handle = struct.unpack('<H', pdata[10:12])[0]
                            print(f"  ATT Handle: 0x{att_handle:04x}")
                            value_preview = pdata[12:28].hex() if len(pdata) > 12 else ""
                            print(f"  ATT Value: {value_preview}...")

    print("\n" + "="*80)
    print(f"Total packets analyzed: {packet_count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/parse_hci_diagnostic.py <path_to_btsnoop_hci.log>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    analyze_packet_structure(log_path)
