#!/usr/bin/env python3
"""
HCI Log Parser - Extract Session Keys and Control Commands
Parses btsnoop_hci.log files to extract GE Cync BLE control protocol

Usage:
    python src/parse_hci_log.py artifacts/hci_logs/cync_pairing_capture.log
"""

import sys
import struct
from pathlib import Path

# Target device
TARGET_MAC = "34:13:43:46:CA:84"
TARGET_MAC_BYTES = bytes.fromhex(TARGET_MAC.replace(":", ""))

# Known UUIDs
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

def parse_btsnoop_header(data):
    """Parse btsnoop file header"""
    if len(data) < 16:
        return None

    magic = data[0:8]
    if magic != b'btsnoop\x00':
        return None

    version, datalink = struct.unpack('>II', data[8:16])
    return {
        'version': version,
        'datalink': datalink
    }

def parse_btsnoop_packet(data, offset):
    """Parse a single btsnoop packet record"""
    if offset + 24 > len(data):
        return None, offset

    # Packet record header (24 bytes)
    orig_len, incl_len, flags, drops, timestamp = struct.unpack('>IIIIQ', data[offset:offset+24])

    packet_data = data[offset+24:offset+24+incl_len]

    return {
        'orig_len': orig_len,
        'incl_len': incl_len,
        'flags': flags,
        'timestamp': timestamp,
        'data': packet_data
    }, offset + 24 + incl_len

def extract_att_write_command(packet_data):
    """Extract ATT Write Command from HCI packet"""
    # Look for ATT Write Command (opcode 0x52) or Write Request (opcode 0x12)
    if len(packet_data) < 10:
        return None

    # Simple heuristic: look for characteristic write patterns
    # This will need refinement based on actual HCI structure

    for i in range(len(packet_data) - 16):
        # Look for potential UUID handles or characteristic data
        chunk = packet_data[i:i+16]

        # Check if this looks like encrypted data (high entropy)
        if all(b != 0 for b in chunk):
            return chunk

    return None

def analyze_hci_log(log_path):
    """Main analysis function"""
    print("=" * 80)
    print("HCI LOG ANALYZER - GE CYNC BLE PROTOCOL")
    print("=" * 80)
    print(f"Log file: {log_path}")
    print(f"Target device: {TARGET_MAC}")
    print("=" * 80)

    # Read file
    with open(log_path, 'rb') as f:
        data = f.read()

    print(f"\nFile size: {len(data)} bytes")

    # Parse header
    header = parse_btsnoop_header(data)
    if not header:
        print("[ERROR] Invalid btsnoop file format")
        return

    print(f"btsnoop version: {header['version']}")
    print(f"Datalink type: {header['datalink']}")

    # Parse packets
    print("\nParsing packets...")
    offset = 16  # After header
    packet_count = 0
    write_commands = []

    while offset < len(data):
        packet, new_offset = parse_btsnoop_packet(data, offset)
        if not packet:
            break

        offset = new_offset
        packet_count += 1

        # Look for ATT write commands
        write_data = extract_att_write_command(packet['data'])
        if write_data:
            write_commands.append({
                'timestamp': packet['timestamp'],
                'data': write_data,
                'packet_num': packet_count
            })

    print(f"Total packets: {packet_count}")
    print(f"Potential write commands found: {len(write_commands)}")

    # Display findings
    if write_commands:
        print("\n" + "=" * 80)
        print("POTENTIAL COMMANDS/SESSION KEYS")
        print("=" * 80)

        for i, cmd in enumerate(write_commands[:20], 1):  # Show first 20
            print(f"\n[{i}] Packet {cmd['packet_num']}")
            print(f"    Timestamp: {cmd['timestamp']}")
            print(f"    Data: {cmd['data'].hex()}")

            # Try to identify command type
            if len(cmd['data']) == 16:
                print(f"    Type: Potential 16-byte AES key or encrypted payload")
            elif cmd['data'].startswith(b'\x04'):
                print(f"    Type: Possible pairing network name (opcode 0x04)")
            elif cmd['data'].startswith(b'\x05'):
                print(f"    Type: Possible pairing password (opcode 0x05)")
            elif cmd['data'].startswith(b'\x06'):
                print(f"    Type: Possible pairing LTK (opcode 0x06)")

    print("\n" + "=" * 80)
    print("NEXT STEPS")
    print("=" * 80)
    print("1. Review the extracted commands above")
    print("2. Identify session key (look for 16-byte sequences)")
    print("3. Identify control commands (ON/OFF patterns)")
    print("4. I'll implement the control protocol based on findings")
    print("=" * 80)

    return write_commands

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/parse_hci_log.py <path_to_btsnoop_hci.log>")
        print("\nExample:")
        print("  python src/parse_hci_log.py artifacts/hci_logs/cync_pairing_capture.log")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"[ERROR] File not found: {log_path}")
        sys.exit(1)

    analyze_hci_log(log_path)
