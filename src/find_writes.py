#!/usr/bin/env python3
"""
Find all ATT Write operations in HCI log
"""

import sys
import struct
from pathlib import Path

CHAR_HANDLES = {
    0x0011: "Telink Command",
    0x0014: "Mesh Prov In (2adb)",
    0x0016: "Mesh Prov Out (2adc)",
    0x0019: "Mesh Proxy In (2add)",
    0x001b: "Mesh Proxy Out (2ade)",
}

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

    # For datalink 1002: bit 0 clear = sent FROM phone
    direction = 'received' if (flags & 0x01) else 'sent'

    return {
        'flags': flags,
        'timestamp': timestamp,
        'data': packet_data,
        'direction': direction
    }, offset + 24 + incl_len

def find_writes(log_path):
    with open(log_path, 'rb') as f:
        data = f.read()

    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file")
        return

    print("="*80)
    print("SEARCHING FOR ATT WRITE OPERATIONS")
    print("="*80)
    print(f"File: {log_path}")
    print(f"Size: {len(data)} bytes")
    print("="*80)

    offset = 16
    packet_count = 0
    writes_found = []

    while offset < len(data):
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        pdata = packet['data']

        # Look for ACL Data packets (type 0x02)
        if len(pdata) < 10 or pdata[0] != 0x02:
            continue

        # Parse ACL header
        handle_flags = struct.unpack('<H', pdata[1:3])[0]
        handle = handle_flags & 0x0FFF
        acl_len = struct.unpack('<H', pdata[3:5])[0]

        if len(pdata) < 5 + acl_len:
            continue

        # Parse L2CAP header
        l2cap_len = struct.unpack('<H', pdata[5:7])[0]
        l2cap_cid = struct.unpack('<H', pdata[7:9])[0]

        # Only look at ATT channel (CID 0x0004)
        if l2cap_cid != 0x0004 or len(pdata) < 10:
            continue

        # Get ATT opcode
        att_opcode = pdata[9]

        # Check for Write Request (0x12) or Write Command (0x52)
        if att_opcode in [0x12, 0x52]:
            if len(pdata) >= 12:
                att_handle = struct.unpack('<H', pdata[10:12])[0]
                att_value = pdata[12:]

                writes_found.append({
                    'packet_num': packet_count,
                    'direction': packet['direction'],
                    'timestamp': packet['timestamp'],
                    'opcode': att_opcode,
                    'handle': att_handle,
                    'value': att_value
                })

    print(f"\nTotal packets analyzed: {packet_count}")
    print(f"Write operations found: {len(writes_found)}")

    # Separate by direction
    writes_sent = [w for w in writes_found if w['direction'] == 'sent']
    writes_recv = [w for w in writes_found if w['direction'] == 'received']

    print(f"  Sent (phone -> bulb): {len(writes_sent)}")
    print(f"  Received (bulb -> phone): {len(writes_recv)}")

    # Show all writes SENT
    print("\n" + "="*80)
    print(f"WRITES SENT FROM PHONE TO BULB ({len(writes_sent)} total)")
    print("="*80)

    for i, w in enumerate(writes_sent, 1):
        opcode_name = "Write Request" if w['opcode'] == 0x12 else "Write Command"
        handle_name = CHAR_HANDLES.get(w['handle'], f"Unknown (0x{w['handle']:04x})")

        print(f"\n[{i}] Packet {w['packet_num']}")
        print(f"    Opcode: 0x{w['opcode']:02x} ({opcode_name})")
        print(f"    Handle: 0x{w['handle']:04x} ({handle_name})")
        print(f"    Value ({len(w['value'])} bytes): {w['value'].hex()}")

        # Try to identify command type
        if len(w['value']) >= 1:
            first_byte = w['value'][0]
            if first_byte == 0x00 and len(w['value']) >= 2:
                second_byte = w['value'][1]
                if second_byte == 0x05:
                    print(f"    >>> Handshake Start (000501...)")
                elif second_byte == 0x00 and len(w['value']) >= 10:
                    if w['value'][9] == 0x04:
                        print(f"    >>> Key Exchange (000001...040000)")
            elif first_byte in [0x31, 0x32]:
                print(f"    >>> Sync/Auth packet (0x{first_byte:02x})")
            elif first_byte == 0x04 and len(w['value']) == 17:
                print(f"    >>> Pairing Network Name (encrypted)")
            elif first_byte == 0x05 and len(w['value']) == 17:
                print(f"    >>> Pairing Password (encrypted)")
            elif first_byte == 0x06 and len(w['value']) == 17:
                print(f"    >>> Pairing LTK (encrypted)")
            elif first_byte == 0x07:
                print(f"    >>> Pairing Confirm")
            elif len(w['value']) >= 2 and w['value'][1] == 0xc0:
                print(f"    >>> CONTROL COMMAND (prefix 0x{first_byte:02x})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/find_writes.py <path_to_btsnoop_hci.log>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    find_writes(log_path)
