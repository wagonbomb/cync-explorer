#!/usr/bin/env python3
"""
Complete HCI Log Parser - Show ALL ATT operations with directions
"""

import sys
import struct
from pathlib import Path

TARGET_MAC = "34:13:43:46:CA:84"

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

def parse_hci_acl_packet(data):
    if len(data) < 5 or data[0] != 0x02:
        return None
    handle_flags = struct.unpack('<H', data[1:3])[0]
    handle = handle_flags & 0x0FFF
    data_len = struct.unpack('<H', data[3:5])[0]
    if len(data) < 5 + data_len:
        return None
    payload = data[5:5+data_len]
    return {'handle': handle, 'payload': payload}

def parse_l2cap_packet(data):
    if len(data) < 4:
        return None
    length = struct.unpack('<H', data[0:2])[0]
    cid = struct.unpack('<H', data[2:4])[0]
    if len(data) < 4 + length:
        return None
    payload = data[4:4+length]
    return {'length': length, 'cid': cid, 'payload': payload}

def parse_att_packet(data):
    if len(data) < 1:
        return None
    opcode = data[0]
    att_data = data[1:]

    att_info = {'opcode': opcode, 'opcode_name': get_att_opcode_name(opcode), 'data': att_data}

    if opcode in [0x12, 0x52] and len(att_data) >= 2:
        handle = struct.unpack('<H', att_data[0:2])[0]
        value = att_data[2:]
        att_info['handle'] = handle
        att_info['handle_name'] = CHAR_HANDLES.get(handle, f"Unknown (0x{handle:04x})")
        att_info['value'] = value
    elif opcode == 0x1b and len(att_data) >= 2:
        handle = struct.unpack('<H', att_data[0:2])[0]
        value = att_data[2:]
        att_info['handle'] = handle
        att_info['handle_name'] = CHAR_HANDLES.get(handle, f"Unknown (0x{handle:04x})")
        att_info['value'] = value

    return att_info

def get_att_opcode_name(opcode):
    opcodes = {
        0x01: 'Error Response',
        0x02: 'Exchange MTU Request',
        0x03: 'Exchange MTU Response',
        0x08: 'Read By Type Request',
        0x09: 'Read By Type Response',
        0x0a: 'Read Request',
        0x0b: 'Read Response',
        0x12: 'Write Request',
        0x13: 'Write Response',
        0x1b: 'Handle Value Notification',
        0x52: 'Write Command',
    }
    return opcodes.get(opcode, f'Unknown (0x{opcode:02x})')

def analyze_hci_log(log_path):
    print("="*80)
    print("COMPLETE HCI LOG ANALYZER - ALL ATT OPERATIONS")
    print("="*80)
    print(f"Log file: {log_path}")
    print("="*80)

    with open(log_path, 'rb') as f:
        data = f.read()

    print(f"\nFile size: {len(data)} bytes")

    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file format")
        return

    print(f"btsnoop version: {header['version']}")
    print(f"Datalink type: {header['datalink']}")

    offset = 16
    packet_count = 0
    all_att_writes = []
    all_att_notifications = []

    while offset < len(data):
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        hci_acl = parse_hci_acl_packet(packet['data'])
        if not hci_acl:
            continue

        l2cap = parse_l2cap_packet(hci_acl['payload'])
        if not l2cap or l2cap['cid'] != 0x0004:
            continue

        att = parse_att_packet(l2cap['payload'])
        if not att:
            continue

        # Collect ALL writes
        if att['opcode'] in [0x12, 0x52] and 'value' in att:
            all_att_writes.append({
                'packet_num': packet_count,
                'direction': packet['direction'],
                'timestamp': packet['timestamp'],
                'handle': att.get('handle'),
                'handle_name': att.get('handle_name'),
                'value': att['value'],
                'opcode_name': att['opcode_name']
            })

        # Collect ALL notifications
        if att['opcode'] == 0x1b and 'value' in att:
            all_att_notifications.append({
                'packet_num': packet_count,
                'direction': packet['direction'],
                'timestamp': packet['timestamp'],
                'handle': att.get('handle'),
                'handle_name': att.get('handle_name'),
                'value': att['value']
            })

    print(f"\nTotal packets: {packet_count}")
    print(f"ATT Write operations: {len(all_att_writes)}")
    print(f"ATT Notifications: {len(all_att_notifications)}")

    # Separate by direction
    writes_sent = [w for w in all_att_writes if w['direction'] == 'sent']
    writes_received = [w for w in all_att_writes if w['direction'] == 'received']

    print(f"\n  Writes SENT (phone -> bulb): {len(writes_sent)}")
    print(f"  Writes RECEIVED (bulb -> phone): {len(writes_received)}")

    # Show ALL writes sent to bulb
    print("\n" + "="*80)
    print("ALL WRITES SENT TO BULB (Phone -> Bulb)")
    print("="*80)

    for i, write in enumerate(writes_sent, 1):
        print(f"\n[{i}] Packet {write['packet_num']}")
        print(f"    Handle: 0x{write['handle']:04x} ({write['handle_name']})")
        print(f"    Value: {write['value'].hex()}")
        print(f"    Length: {len(write['value'])} bytes")

        # Try to identify command type
        if len(write['value']) >= 1:
            first_byte = write['value'][0]
            if first_byte == 0x00:
                print(f"    Type: Handshake packet (starts with 0x00)")
            elif first_byte in [0x31, 0x32]:
                print(f"    Type: Sync/Auth packet (0x{first_byte:02x})")
            elif first_byte == 0x04:
                print(f"    Type: Pairing Network Name")
            elif first_byte == 0x05:
                print(f"    Type: Pairing Password")
            elif first_byte == 0x06:
                print(f"    Type: Pairing LTK")
            elif first_byte == 0x07:
                print(f"    Type: Pairing Confirm")
            elif len(write['value']) >= 2 and write['value'][1] == 0xc0:
                print(f"    Type: Control command (prefix 0x{first_byte:02x})")

    # Show ALL notifications from bulb
    print("\n" + "="*80)
    print("ALL NOTIFICATIONS FROM BULB (Bulb -> Phone)")
    print("="*80)

    notifs_sent = [n for n in all_att_notifications if n['direction'] == 'sent']
    print(f"\nFound {len(notifs_sent)} notifications:")

    for i, notif in enumerate(notifs_sent[:30], 1):
        print(f"\n[{i}] Packet {notif['packet_num']}")
        print(f"    Handle: 0x{notif['handle']:04x} ({notif['handle_name']})")
        print(f"    Value: {notif['value'].hex()}")
        print(f"    Length: {len(notif['value'])} bytes")

        # Try to identify response type
        if len(notif['value']) >= 1:
            first_byte = notif['value'][0]
            if first_byte == 0x04:
                print(f"    Type: Session ID response")

    return {'writes_sent': writes_sent, 'notifications': notifs_sent}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/parse_hci_complete.py <path_to_btsnoop_hci.log>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    analyze_hci_log(log_path)
