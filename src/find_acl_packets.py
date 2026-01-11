#!/usr/bin/env python3
"""
Find ACL Data packets in btsnoop log
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
        'orig_len': orig_len,
        'incl_len': incl_len,
        'flags': flags,
        'timestamp': timestamp,
        'data': packet_data,
        'direction': 'sent' if (flags & 0x01) else 'received'
    }, offset + 24 + incl_len

def find_acl_packets(log_path):
    with open(log_path, 'rb') as f:
        data = f.read()

    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file format")
        return

    print(f"File size: {len(data)} bytes")
    print(f"Searching for ACL Data packets (type 0x02)...")

    offset = 16
    packet_count = 0
    packet_types = {}
    acl_packets = []

    while offset < len(data):
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        pdata = packet['data']
        if len(pdata) >= 1:
            pkt_type = pdata[0]
            packet_types[pkt_type] = packet_types.get(pkt_type, 0) + 1

            # Collect ACL packets
            if pkt_type == 0x02:
                acl_packets.append({
                    'num': packet_count,
                    'data': pdata,
                    'direction': packet['direction']
                })

    print(f"\nTotal packets: {packet_count}")
    print("\nPacket type distribution:")
    type_names = {
        0x01: "HCI Command",
        0x02: "HCI ACL Data",
        0x03: "HCI SCO Data",
        0x04: "HCI Event"
    }
    for pkt_type, count in sorted(packet_types.items()):
        name = type_names.get(pkt_type, f"Unknown (0x{pkt_type:02x})")
        print(f"  {name}: {count}")

    print(f"\nFound {len(acl_packets)} ACL Data packets")

    if acl_packets:
        print("\nFirst 5 ACL packets:")
        for i, pkt in enumerate(acl_packets[:5], 1):
            pdata = pkt['data']
            print(f"\n[{i}] Packet {pkt['num']} - {pkt['direction']}")
            print(f"  Length: {len(pdata)} bytes")

            if len(pdata) >= 5:
                handle_flags = struct.unpack('<H', pdata[1:3])[0]
                handle = handle_flags & 0x0FFF
                data_len = struct.unpack('<H', pdata[3:5])[0]
                print(f"  Handle: 0x{handle:03x}")
                print(f"  Data Length: {data_len}")

                # Show L2CAP if present
                if len(pdata) >= 9:
                    l2cap_len = struct.unpack('<H', pdata[5:7])[0]
                    l2cap_cid = struct.unpack('<H', pdata[7:9])[0]
                    print(f"  L2CAP CID: 0x{l2cap_cid:04x}")

                    # Show ATT if CID = 0x0004
                    if l2cap_cid == 0x0004 and len(pdata) >= 10:
                        att_opcode = pdata[9]
                        print(f"  ATT Opcode: 0x{att_opcode:02x}")

                        # If write, show handle and value
                        if att_opcode in [0x12, 0x52] and len(pdata) >= 12:
                            att_handle = struct.unpack('<H', pdata[10:12])[0]
                            value = pdata[12:]
                            print(f"  ATT Handle: 0x{att_handle:04x}")
                            print(f"  ATT Value ({len(value)} bytes): {value.hex()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/find_acl_packets.py <path_to_btsnoop_hci.log>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    find_acl_packets(log_path)
