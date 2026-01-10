
import struct
import binascii

def parse_btsnoop(filename):
    print(f"--- Parsing {filename} ---")
    with open(filename, 'rb') as f:
        header = f.read(16)
        if not header.startswith(b'btsnoop\0'):
            print("Not a btsnoop file")
            return

        while True:
            header = f.read(24)
            if not header or len(header) < 24:
                break
            
            orig_len, incl_len, flags, drops, timestamp = struct.unpack(">IIIIQ", header)
            data = f.read(incl_len)
            
            # Flags: bit 0 is set if it's a "received" packet (Controller -> Host)
            # bit 0 is 0 if it's a "sent" packet (Host -> Controller)
            is_received = flags & 0x01
            
            # We are looking for ATT packets. 
            # HCI ACL Data (Type 2) starts with 4 bytes of HCI header
            # Then L2CAP header (4 bytes)
            # Then ATT packet
            
            if len(data) > 8:
                # Basic check for ACL data + L2CAP
                # data[0:2] is connection handle + PB/BC flags
                # data[2:4] is total L2CAP payload length
                # data[4:6] is L2CAP pdu length
                # data[6:8] is L2CAP channel ID (0x0004 for ATT)
                
                cid = struct.unpack("<H", data[6:8])[0]
                if cid == 0x0004: # ATT Channel
                    att_data = data[8:]
                    opcode = att_data[0]
                    
                    # ATT OpCodes:
                    # 0x12: Write Request
                    # 0x52: Write Command (Write without response)
                    # 0x1b: Handle Value Notification
                    # 0x01: Error Response
                    
                    prefix = "RECV" if is_received else "SENT"
                    
                    if opcode in [0x12, 0x52]:
                        handle = struct.unpack("<H", att_data[1:3])[0]
                        payload = att_data[3:]
                        print(f"[{prefix}] WRITE to handle 0x{handle:04x} (h{handle}): {payload.hex()}")
                    elif opcode == 0x1b:
                        handle = struct.unpack("<H", att_data[1:3])[0]
                        payload = att_data[3:]
                        print(f"[{prefix}] NOTIFY from handle 0x{handle:04x} (h{handle}): {payload.hex()}")
                    elif opcode == 0x01:
                        req_opcode = att_data[1]
                        handle = struct.unpack("<H", att_data[2:4])[0]
                        err_code = att_data[4]
                        print(f"[{prefix}] ERROR for 0x{req_opcode:02x} on handle 0x{handle:04x}: 0x{err_code:02x}")

if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:]:
        parse_btsnoop(arg)
