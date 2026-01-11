#!/usr/bin/env python3
"""
Advanced HCI Log Parser - Properly decode BLE ATT packets
Extracts GATT Write operations for GE Cync bulb control
"""

import sys
import struct
from pathlib import Path

TARGET_MAC = "34:13:43:46:CA:84"

# Known characteristic handles for GE Cync (from our testing)
CHAR_HANDLES = {
    0x0011: "Telink Command",
    0x0014: "Mesh Prov In (2adb)",
    0x0016: "Mesh Prov Out (2adc)",
    0x0019: "Mesh Proxy In (2add)",
    0x001b: "Mesh Proxy Out (2ade)",
}

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

def parse_hci_acl_packet(data):
    """Parse HCI ACL Data packet"""
    if len(data) < 5:
        return None

    # HCI packet type (1 byte) - should be 0x02 for ACL data
    if data[0] != 0x02:
        return None

    # Connection handle and flags (2 bytes)
    handle_flags = struct.unpack('<H', data[1:3])[0]
    handle = handle_flags & 0x0FFF
    pb_flag = (handle_flags >> 12) & 0x03
    bc_flag = (handle_flags >> 14) & 0x03

    # Data length (2 bytes)
    data_len = struct.unpack('<H', data[3:5])[0]

    if len(data) < 5 + data_len:
        return None

    payload = data[5:5+data_len]

    return {
        'handle': handle,
        'pb_flag': pb_flag,
        'bc_flag': bc_flag,
        'payload': payload
    }

def parse_l2cap_packet(data):
    """Parse L2CAP packet"""
    if len(data) < 4:
        return None

    length = struct.unpack('<H', data[0:2])[0]
    cid = struct.unpack('<H', data[2:4])[0]

    if len(data) < 4 + length:
        return None

    payload = data[4:4+length]

    return {
        'length': length,
        'cid': cid,  # Channel ID (0x0004 = ATT)
        'payload': payload
    }

def parse_att_packet(data):
    """Parse ATT (Attribute Protocol) packet"""
    if len(data) < 1:
        return None

    opcode = data[0]
    att_data = data[1:]

    att_info = {
        'opcode': opcode,
        'opcode_name': get_att_opcode_name(opcode),
        'data': att_data
    }

    # Parse ATT Write Request (0x12) or Write Command (0x52)
    if opcode in [0x12, 0x52] and len(att_data) >= 2:
        handle = struct.unpack('<H', att_data[0:2])[0]
        value = att_data[2:]
        att_info['handle'] = handle
        att_info['handle_name'] = CHAR_HANDLES.get(handle, f"Unknown (0x{handle:04x})")
        att_info['value'] = value

    # Parse ATT Write Response (0x13)
    elif opcode == 0x13:
        att_info['response'] = 'Write successful'

    # Parse ATT Notification (0x1b)
    elif opcode == 0x1b and len(att_data) >= 2:
        handle = struct.unpack('<H', att_data[0:2])[0]
        value = att_data[2:]
        att_info['handle'] = handle
        att_info['handle_name'] = CHAR_HANDLES.get(handle, f"Unknown (0x{handle:04x})")
        att_info['value'] = value

    return att_info

def get_att_opcode_name(opcode):
    """Get ATT opcode name"""
    opcodes = {
        0x01: 'Error Response',
        0x02: 'Exchange MTU Request',
        0x03: 'Exchange MTU Response',
        0x08: 'Read By Type Request',
        0x09: 'Read By Type Response',
        0x12: 'Write Request',
        0x13: 'Write Response',
        0x1b: 'Handle Value Notification',
        0x52: 'Write Command',
    }
    return opcodes.get(opcode, f'Unknown (0x{opcode:02x})')

def analyze_hci_log(log_path):
    """Main analysis function"""
    print("=" * 80)
    print("ADVANCED HCI LOG ANALYZER - GE CYNC BLE PROTOCOL")
    print("=" * 80)
    print(f"Log file: {log_path}")
    print(f"Target device: {TARGET_MAC}")
    print("=" * 80)

    with open(log_path, 'rb') as f:
        data = f.read()

    print(f"\nFile size: {len(data)} bytes")

    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file format")
        return

    print(f"btsnoop version: {header['version']}")
    print(f"Datalink type: {header['datalink']}")

    # Parse packets
    print("\nParsing HCI packets...")
    offset = 16
    packet_count = 0
    att_writes = []
    att_notifications = []

    while offset < len(data):
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        # Parse HCI ACL packet
        hci_acl = parse_hci_acl_packet(packet['data'])
        if not hci_acl:
            continue

        # Parse L2CAP packet
        l2cap = parse_l2cap_packet(hci_acl['payload'])
        if not l2cap or l2cap['cid'] != 0x0004:  # CID 0x0004 = ATT
            continue

        # Parse ATT packet
        att = parse_att_packet(l2cap['payload'])
        if not att:
            continue

        # Collect ATT Write operations
        if att['opcode'] in [0x12, 0x52] and 'value' in att:
            att_writes.append({
                'packet_num': packet_count,
                'direction': packet['direction'],
                'timestamp': packet['timestamp'],
                'handle': att.get('handle'),
                'handle_name': att.get('handle_name'),
                'value': att['value'],
                'opcode_name': att['opcode_name']
            })

        # Collect ATT Notifications
        if att['opcode'] == 0x1b and 'value' in att:
            att_notifications.append({
                'packet_num': packet_count,
                'timestamp': packet['timestamp'],
                'handle': att.get('handle'),
                'handle_name': att.get('handle_name'),
                'value': att['value']
            })

    print(f"Total packets: {packet_count}")
    print(f"ATT Write operations: {len(att_writes)}")
    print(f"ATT Notifications: {len(att_notifications)}")

    # Display writes to GE Cync characteristics
    print("\n" + "=" * 80)
    print("GATT WRITE OPERATIONS (to Cync bulb)")
    print("=" * 80)

    cync_writes = [w for w in att_writes if w['handle'] in CHAR_HANDLES]
    print(f"\nFound {len(cync_writes)} writes to known Cync characteristics:")

    for i, write in enumerate(cync_writes, 1):
        print(f"\n[{i}] Packet {write['packet_num']} - {write['direction']}")
        print(f"    Handle: 0x{write['handle']:04x} ({write['handle_name']})")
        print(f"    Value: {write['value'].hex()}")
        print(f"    Length: {len(write['value'])} bytes")

        # Try to identify command type
        if len(write['value']) == 17 and write['value'][0] in [0x04, 0x05, 0x06]:
            opcode = write['value'][0]
            opcodes = {0x04: 'Pairing Network Name', 0x05: 'Pairing Password', 0x06: 'Pairing LTK'}
            print(f"    Type: {opcodes.get(opcode, 'Unknown')} (opcode 0x{opcode:02x})")
            print(f"    Encrypted: {write['value'][1:].hex()}")

    # Display notifications from Cync bulb
    print("\n" + "=" * 80)
    print("NOTIFICATIONS (from Cync bulb)")
    print("=" * 80)

    cync_notifs = [n for n in att_notifications if n['handle'] in CHAR_HANDLES]
    print(f"\nFound {len(cync_notifs)} notifications from Cync characteristics:")

    for i, notif in enumerate(cync_notifs[:20], 1):  # Show first 20
        print(f"\n[{i}] Packet {notif['packet_num']}")
        print(f"    Handle: 0x{notif['handle']:04x} ({notif['handle_name']})")
        print(f"    Value: {notif['value'].hex()}")
        print(f"    Length: {len(notif['value'])} bytes")

    # Analysis summary
    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)

    # Group writes by handle
    print("\nWrites by characteristic:")
    for handle, name in CHAR_HANDLES.items():
        writes_to_handle = [w for w in cync_writes if w['handle'] == handle]
        if writes_to_handle:
            print(f"  0x{handle:04x} ({name}): {len(writes_to_handle)} writes")

    print("\nNext Steps:")
    print("1. Look for pairing messages (opcodes 0x04-0x07) in Mesh Proxy In writes")
    print("2. Extract session key from encrypted pairing data")
    print("3. Identify control commands (look for patterns in repeated writes)")
    print("=" * 80)

    return {
        'writes': cync_writes,
        'notifications': cync_notifs
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/parse_hci_advanced.py <path_to_btsnoop_hci.log>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    analyze_hci_log(log_path)
