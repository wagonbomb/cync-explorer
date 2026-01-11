#!/usr/bin/env python3
"""
Parse HCI Events for embedded GATT data
Some Android implementations embed ATT operations in HCI Event parameters
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
    return {
        'orig_len': orig_len,
        'incl_len': incl_len,
        'flags': flags,
        'timestamp': timestamp,
        'data': packet_data,
        'direction': 'sent' if (flags & 0x01) else 'received'
    }, offset + 24 + incl_len

def search_for_att_patterns(data):
    """Search for ATT opcodes and characteristic handles in event data"""
    findings = []

    # Look for ATT opcodes
    att_opcodes = {
        0x12: "Write Request",
        0x13: "Write Response",
        0x52: "Write Command",
        0x1b: "Handle Value Notification",
        0x04: "Pairing Network Name (?)",
        0x05: "Pairing Password (?)",
        0x06: "Pairing LTK (?)",
        0x07: "Pairing Confirm (?)"
    }

    for i in range(len(data)):
        byte = data[i]

        # Check for ATT opcodes
        if byte in att_opcodes:
            # Try to parse as write operation
            if byte in [0x12, 0x52] and i + 2 < len(data):
                try:
                    handle = struct.unpack('<H', data[i+1:i+3])[0]
                    if handle in CHAR_HANDLES or 0x0010 <= handle <= 0x0020:
                        value = data[i+3:i+19] if i+19 <= len(data) else data[i+3:]
                        findings.append({
                            'type': 'att_write',
                            'offset': i,
                            'opcode': byte,
                            'opcode_name': att_opcodes[byte],
                            'handle': handle,
                            'handle_name': CHAR_HANDLES.get(handle, f"0x{handle:04x}"),
                            'value': value
                        })
                except:
                    pass

            # Check for pairing opcodes
            elif byte in [0x04, 0x05, 0x06, 0x07]:
                value = data[i+1:i+17] if i+17 <= len(data) else data[i+1:]
                if len(value) >= 16:
                    findings.append({
                        'type': 'pairing',
                        'offset': i,
                        'opcode': byte,
                        'opcode_name': att_opcodes[byte],
                        'value': value
                    })

        # Check for characteristic handles
        if i + 1 < len(data):
            try:
                handle = struct.unpack('<H', data[i:i+2])[0]
                if handle in CHAR_HANDLES:
                    findings.append({
                        'type': 'char_handle',
                        'offset': i,
                        'handle': handle,
                        'handle_name': CHAR_HANDLES[handle]
                    })
            except:
                pass

    return findings

def analyze_events(log_path):
    with open(log_path, 'rb') as f:
        data = f.read()

    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file format")
        return

    print("="*80)
    print("HCI EVENT ANALYZER - Search for embedded GATT data")
    print("="*80)
    print(f"File: {log_path}")
    print(f"Size: {len(data)} bytes")
    print("="*80)

    offset = 16
    packet_count = 0
    interesting_packets = []

    while offset < len(data):
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        pdata = packet['data']

        # Only analyze HCI Events (0x04)
        if len(pdata) >= 3 and pdata[0] == 0x04:
            event_code = pdata[1]
            param_len = pdata[2]
            params = pdata[3:3+param_len] if len(pdata) >= 3+param_len else pdata[3:]

            # Search for ATT patterns in event parameters
            findings = search_for_att_patterns(params)

            if findings:
                interesting_packets.append({
                    'num': packet_count,
                    'direction': packet['direction'],
                    'event_code': event_code,
                    'findings': findings,
                    'data': pdata
                })

    print(f"\nTotal packets: {packet_count}")
    print(f"Packets with interesting data: {len(interesting_packets)}")

    if interesting_packets:
        print("\n" + "="*80)
        print("INTERESTING PACKETS")
        print("="*80)

        for i, pkt in enumerate(interesting_packets[:50], 1):  # Show first 50
            print(f"\n[{i}] Packet {pkt['num']} - {pkt['direction']}")
            print(f"  Event Code: 0x{pkt['event_code']:02x}")

            for finding in pkt['findings']:
                if finding['type'] == 'att_write':
                    print(f"  [ATT Write] Offset {finding['offset']}: {finding['opcode_name']}")
                    print(f"    Handle: 0x{finding['handle']:04x} ({finding['handle_name']})")
                    print(f"    Value ({len(finding['value'])} bytes): {finding['value'].hex()}")

                elif finding['type'] == 'pairing':
                    print(f"  [Pairing] Offset {finding['offset']}: {finding['opcode_name']}")
                    print(f"    Value ({len(finding['value'])} bytes): {finding['value'].hex()}")

                elif finding['type'] == 'char_handle':
                    print(f"  [Handle] Offset {finding['offset']}: 0x{finding['handle']:04x} ({finding['handle_name']})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/parse_hci_events.py <path_to_btsnoop_hci.log>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    analyze_events(log_path)
