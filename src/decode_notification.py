"""
Decode Initial Notification
Analyze: 010100efbb755d239432fc0000000032bd9bc1d371a887
"""

data = bytes.fromhex("010100efbb755d239432fc0000000032bd9bc1d371a887")

print("="*60)
print("INITIAL NOTIFICATION ANALYSIS")
print("="*60)
print(f"\nFull hex: {data.hex()}")
print(f"Length: {len(data)} bytes\n")

print("Byte-by-byte breakdown:")
print("-"*60)
for i, b in enumerate(data):
    binary = format(b, '08b')
    char = chr(b) if 32 <= b < 127 else '.'
    print(f"[{i:2d}] 0x{b:02x} = {b:3d} = {binary} = '{char}'")

print("\n" + "="*60)
print("PATTERN ANALYSIS")
print("="*60)

# Check for common patterns
print(f"\nFirst byte: 0x{data[0]:02x} (might be message type)")
print(f"Bytes 0-2: {data[0:3].hex()} (could be header)")
print(f"Bytes 3-10: {data[3:11].hex()} (could be device ID/address)")
print(f"Bytes 11-14: {data[11:15].hex()} (could be timestamp/counter)")
print(f"Bytes 15-22: {data[15:23].hex()} (could be signature/checksum)")

# Look for session ID pattern from context dump
print("\n" + "="*60)
print("SESSION ID SEARCH")
print("="*60)
found_session = False
for i in range(len(data) - 3):
    if data[i] == 0x04 and data[i+1] == 0x00 and data[i+2] == 0x00:
        print(f"✓ Session ID pattern at byte {i}: 0x{data[i+3]:02x}")
        found_session = True

if not found_session:
    print("✗ No '04 00 00 XX' pattern found")
    print("\nBut byte 11 is 0x00, byte 12 is 0x00... checking alternatives:")
    print(f"  If session at byte 13: 0x{data[13]:02x}")
    print(f"  If session at byte 14: 0x{data[14]:02x}")

# Try interpreting as mesh message
print("\n" + "="*60)
print("MESH MESSAGE STRUCTURE (GUESS)")
print("="*60)
print(f"Message Type: 0x{data[0]:02x}")
print(f"Sub-type: 0x{data[1]:02x}") 
print(f"Flags: 0x{data[2]:02x}")
print(f"Possible Device ID: {data[3:11].hex()}")
print(f"Possible Session: {data[11:15].hex()}")
print(f"Possible Key/Token: {data[15:].hex()}")

print("\n" + "="*60)
print("RECOMMENDATION")
print("="*60)
print("This notification likely contains:")
print("  1. Device identifier/address")
print("  2. Session token or network key")
print("  3. Encryption parameters")
print("\nWe need to:")
print("  1. Extract these values from the notification")
print("  2. Use them in our command payloads")
print("  3. Try simpler commands first (like b0c0 alone)")
