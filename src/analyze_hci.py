
import pyshark
import sys
import os
import json
from pathlib import Path

# Path to the specific log file found
REPO_ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = REPO_ROOT / "artifacts" / "btbugreport" / "logs" / "btsnoop_hci.log"
OUTPUT_PATH = REPO_ROOT / "artifacts" / "outputs" / "hci_analysis_2.json"

found_packets = []

def analyze_packet(pkt):
    try:
        if not hasattr(pkt, 'btatt'):
            return

        # Check for:
        # 0x12: Write Request
        # 0x52: Write Command
        # 0x1b: Notification (Server -> Client)
        # 0x0b: Read Response (Server -> Client)
        opcode = getattr(pkt.btatt, 'opcode', '')
        
        if opcode in ['0x12', '0x52', '0x1b', '0x0b']:
            handle = getattr(pkt.btatt, 'handle', 'Unknown')
            value = getattr(pkt.btatt, 'value', None)
            uuid = getattr(pkt.btatt, 'uuid128', getattr(pkt.btatt, 'uuid16', '')) # UUID might not be present in Notifies
            
            if value:
                # Convert colon-hex to bytes object 
                hex_str = value.replace(':', '')
                
                # Determine direction/type
                pkt_type = "UNKNOWN"
                if opcode == '0x12': pkt_type = "WRITE_REQ (App -> Light)"
                elif opcode == '0x52': pkt_type = "WRITE_CMD (App -> Light)"
                elif opcode == '0x1b': pkt_type = "NOTIFY (Light -> App)"
                elif opcode == '0x0b': pkt_type = "READ_RSP (Light -> App)"
                
                print(f"[{pkt.number}] {pkt_type} | Handle: {handle} | Data: {hex_str}")
                
                found_packets.append({
                    "frame": int(pkt.number),
                    "type": pkt_type,
                    "handle": handle,
                    "uuid": str(uuid),
                    "data": hex_str,
                    "opcode": opcode
                })
                    
    except Exception as e:
        pass

def main():
    if not LOG_PATH.exists():
        print(f"File not found: {LOG_PATH}")
        return

    print(f"Parsing {LOG_PATH}...")
    print("Extracting CONVERSATION (Writes & Notifications)...")
    print("-" * 50)

    try:
        cap = pyshark.FileCapture(LOG_PATH, display_filter='btatt') 
        
        count = 0
        for pkt in cap:
            analyze_packet(pkt)
            count += 1
        
        print(f"\nScan complete. Processed {count} packets.")
        
        # Save to file
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with OUTPUT_PATH.open("w", encoding="utf-8") as f:
            json.dump(found_packets, f, indent=2)
        print(f"Saved findings to {OUTPUT_PATH}")
        
    except Exception as e:
        print(f"\nError using pyshark: {e}")

if __name__ == "__main__":
    main()
