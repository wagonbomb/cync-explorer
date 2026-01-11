#!/usr/bin/env python3
"""
Find session ID response in HCI log
Look for notifications from bulb around early connection time
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
    direction = 'received' if (flags & 0x01) else 'sent'
    return {
        'flags': flags,
        'timestamp': timestamp,
        'data': packet_data,
        'direction': direction
    }, offset + 24 + incl_len

def find_notifications(log_path):
    with open(log_path, 'rb') as f:
        data = f.read()

    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file")
        return

    print("="*80)
    print("SEARCHING FOR SESSION ID RESPONSE")
    print("="*80)
    print(f"File: {log_path}")
    print("="*80)

    offset = 16
    packet_count = 0
    all_notifications = []

    while offset < len(data):
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        pdata = packet['data']

        # Look for ACL Data packets (type 0x02) received from bulb
        if len(pdata) < 10 or pdata[0] != 0x02 or packet['direction'] != 'received':
            continue

        # Parse ACL header
        handle_flags = struct.unpack('<H', pdata[1:3])[0]
        handle = handle_flags & 0x0FFF
        acl_len = struct.unpack('<H', pdata[3:5])[0]

        if len(pdata) < 5 + acl_len:
            continue

        # Parse L2CAP header
        if len(pdata) < 9:
            continue

        l2cap_len = struct.unpack('<H', pdata[5:7])[0]
        l2cap_cid = struct.unpack('<H', pdata[7:9])[0]

        # Only look at ATT channel (CID 0x0004)
        if l2cap_cid != 0x0004 or len(pdata) < 10:
            continue

        # Get ATT opcode
        att_opcode = pdata[9]

        # Check for Notification (0x1b)
        if att_opcode == 0x1b and len(pdata) >= 12:
            att_handle = struct.unpack('<H', pdata[10:12])[0]
            att_value = pdata[12:]

            all_notifications.append({
                'packet_num': packet_count,
                'timestamp': packet['timestamp'],
                'handle': att_handle,
                'value': att_value
            })

    print(f"\nTotal packets: {packet_count}")
    print(f"Notifications from bulb: {len(all_notifications)}")

    # Show all notifications (looking for session ID)
    print("\n" + "="*80)
    print(f"ALL NOTIFICATIONS FROM BULB")
    print("="*80)

    for i, notif in enumerate(all_notifications, 1):
        print(f"\n[{i}] Packet {notif['packet_num']}")
        print(f"    Handle: 0x{notif['handle']:04x}")
        print(f"    Value ({len(notif['value'])} bytes): {notif['value'].hex()}")

        # Check for session ID response pattern (04 00 00 [session_id])
        if len(notif['value']) >= 4:
            if notif['value'][0] == 0x04 and notif['value'][1] == 0x00 and notif['value'][2] == 0x00:
                session_id = notif['value'][3]
                print(f"    >>> POSSIBLE SESSION ID RESPONSE: session_id = 0x{session_id:02x}")

        # Check for other interesting patterns
        if len(notif['value']) >= 1:
            first_byte = notif['value'][0]
            if first_byte in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]:
                if len(notif['value']) == 3 or len(notif['value']) == 4:
                    print(f"    >>> Short response (potential handshake/status)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/find_session_response.py <path_to_btsnoop_hci.log>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    find_notifications(log_path)
