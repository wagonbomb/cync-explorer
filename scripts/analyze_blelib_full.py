#!/usr/bin/env python3
"""
Full analysis of libBleLib.so - Extract protocol details
"""

import struct
from pathlib import Path

LIB_PATH = Path(r"C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\apk_extracted\lib\arm64-v8a\libBleLib.so")

def read_elf_header(data):
    """Parse ELF header"""
    if data[:4] != b'\x7fELF':
        return None

    is_64bit = data[4] == 2
    is_little = data[5] == 1

    if is_64bit and is_little:
        # ELF64 Little Endian
        e_phoff = struct.unpack('<Q', data[32:40])[0]
        e_shoff = struct.unpack('<Q', data[40:48])[0]
        e_phnum = struct.unpack('<H', data[56:58])[0]
        e_shnum = struct.unpack('<H', data[60:62])[0]
        e_shstrndx = struct.unpack('<H', data[62:64])[0]
        e_shentsize = struct.unpack('<H', data[58:60])[0]

        return {
            'is_64bit': True,
            'e_phoff': e_phoff,
            'e_shoff': e_shoff,
            'e_phnum': e_phnum,
            'e_shnum': e_shnum,
            'e_shstrndx': e_shstrndx,
            'e_shentsize': e_shentsize
        }
    return None

def read_section_headers(data, elf):
    """Read section headers"""
    sections = []
    offset = elf['e_shoff']

    for i in range(elf['e_shnum']):
        if elf['is_64bit']:
            sh = struct.unpack('<IIQQQQIIQQ', data[offset:offset+64])
            sections.append({
                'sh_name': sh[0],
                'sh_type': sh[1],
                'sh_flags': sh[2],
                'sh_addr': sh[3],
                'sh_offset': sh[4],
                'sh_size': sh[5],
                'sh_link': sh[6],
                'sh_info': sh[7],
                'sh_addralign': sh[8],
                'sh_entsize': sh[9]
            })
            offset += 64

    return sections

def get_section_name(data, sections, shstrndx, name_offset):
    """Get section name from string table"""
    strtab = sections[shstrndx]
    start = strtab['sh_offset'] + name_offset
    end = data.find(b'\x00', start)
    return data[start:end].decode('utf-8', errors='replace')

def find_dynsym_and_dynstr(data, sections, shstrndx):
    """Find .dynsym and .dynstr sections"""
    dynsym = None
    dynstr = None

    for i, sec in enumerate(sections):
        name = get_section_name(data, sections, shstrndx, sec['sh_name'])
        if name == '.dynsym':
            dynsym = sec
        elif name == '.dynstr':
            dynstr = sec

    return dynsym, dynstr

def read_symbols(data, dynsym, dynstr):
    """Read dynamic symbols"""
    symbols = []

    if not dynsym or not dynstr:
        return symbols

    offset = dynsym['sh_offset']
    count = dynsym['sh_size'] // dynsym['sh_entsize']

    for i in range(count):
        # Elf64_Sym: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
        sym = struct.unpack('<IBBHQQ', data[offset:offset+24])

        name_offset = sym[0]
        st_info = sym[1]
        st_value = sym[4]
        st_size = sym[5]

        # Get name
        name_start = dynstr['sh_offset'] + name_offset
        name_end = data.find(b'\x00', name_start)
        name = data[name_start:name_end].decode('utf-8', errors='replace')

        sym_type = st_info & 0xf
        sym_bind = st_info >> 4

        if name and st_value:
            symbols.append({
                'name': name,
                'value': st_value,
                'size': st_size,
                'type': sym_type,
                'bind': sym_bind
            })

        offset += 24

    return symbols

def extract_strings(data, min_len=4):
    """Extract ASCII strings"""
    strings = []
    current = b''
    offset = 0

    for i, byte in enumerate(data):
        if 32 <= byte <= 126:
            if not current:
                offset = i
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                strings.append((offset, current.decode('ascii', errors='replace')))
            current = b''

    return strings

def find_hex_constants(data):
    """Find interesting byte patterns that might be protocol constants"""
    patterns = []

    # Look for patterns that match our known handshake
    known = [
        (b'\x00\x05\x01', 'START marker (000501)'),
        (b'\x00\x00\x01', 'KEY_EXCHANGE marker (000001)'),
        (b'\x31\x00', 'SYNC_0 (3100)'),
        (b'\x31\x01', 'SYNC_1 (3101)'),
        (b'\x32\x01\x19', 'AUTH marker (320119)'),
        (b'\xb0\xc0', 'Control prefix (b0c0)'),
        (b'\x04\x00\x00', 'Response prefix (040000)'),
    ]

    for pattern, desc in known:
        idx = 0
        while True:
            idx = data.find(pattern, idx)
            if idx == -1:
                break
            patterns.append((idx, pattern.hex(), desc))
            idx += 1

    return patterns

def analyze_function_bytes(data, symbols):
    """Try to analyze function code"""
    results = {}

    interesting = ['trsmitr_send_pkg_encode', 'made_session_key', 'parseKLVData',
                   'getCommandRequestData', 'trsmitr_recv_pkg_decode']

    for sym in symbols:
        if any(x in sym['name'] for x in interesting):
            if sym['size'] > 0:
                start = sym['value']
                # Need to find the file offset from virtual address
                # For simplicity, just note the symbol info
                results[sym['name']] = {
                    'address': hex(sym['value']),
                    'size': sym['size']
                }

    return results

def main():
    print("=" * 70)
    print("LIBBLELIB.SO FULL ANALYSIS")
    print("=" * 70)
    print()

    data = LIB_PATH.read_bytes()
    print(f"File size: {len(data)} bytes")

    # Parse ELF
    elf = read_elf_header(data)
    if not elf:
        print("Not a valid ELF file")
        return

    print(f"Architecture: {'64-bit' if elf['is_64bit'] else '32-bit'}")
    print(f"Sections: {elf['e_shnum']}")
    print()

    # Read sections
    sections = read_section_headers(data, elf)

    print("=" * 70)
    print("SECTIONS")
    print("=" * 70)
    for i, sec in enumerate(sections):
        name = get_section_name(data, sections, elf['e_shstrndx'], sec['sh_name'])
        if sec['sh_size'] > 0:
            print(f"  [{i:2d}] {name:20s} offset={sec['sh_offset']:08x} size={sec['sh_size']:6d}")
    print()

    # Get symbols
    dynsym, dynstr = find_dynsym_and_dynstr(data, sections, elf['e_shstrndx'])
    symbols = read_symbols(data, dynsym, dynstr)

    print("=" * 70)
    print("EXPORTED FUNCTIONS")
    print("=" * 70)
    func_symbols = [s for s in symbols if s['type'] == 2]  # STT_FUNC
    for sym in sorted(func_symbols, key=lambda x: x['value']):
        print(f"  {sym['value']:08x} [{sym['size']:4d}] {sym['name']}")
    print()

    # Find protocol-related functions
    print("=" * 70)
    print("KEY PROTOCOL FUNCTIONS")
    print("=" * 70)
    key_funcs = analyze_function_bytes(data, symbols)
    for name, info in key_funcs.items():
        print(f"  {name}")
        print(f"    Address: {info['address']}, Size: {info['size']} bytes")
    print()

    # Extract strings
    print("=" * 70)
    print("PROTOCOL-RELATED STRINGS")
    print("=" * 70)
    strings = extract_strings(data)
    keywords = ['trsmitr', 'session', 'key', 'klv', 'parse', 'send', 'recv',
                'encode', 'decode', 'command', 'data', 'request', 'ble', 'mesh']
    for offset, s in strings:
        if any(kw in s.lower() for kw in keywords):
            print(f"  [{offset:08x}] {s}")
    print()

    # Find known patterns
    print("=" * 70)
    print("KNOWN PROTOCOL PATTERNS IN BINARY")
    print("=" * 70)
    patterns = find_hex_constants(data)
    for offset, hex_val, desc in patterns:
        print(f"  [{offset:08x}] {hex_val} - {desc}")
    print()

    # Dump .rodata section for constants
    print("=" * 70)
    print("CONSTANTS IN .rodata")
    print("=" * 70)
    for sec in sections:
        name = get_section_name(data, sections, elf['e_shstrndx'], sec['sh_name'])
        if name == '.rodata':
            rodata = data[sec['sh_offset']:sec['sh_offset']+sec['sh_size']]
            print(f"  .rodata size: {len(rodata)} bytes")
            # Print first 256 bytes as hex
            for i in range(0, min(256, len(rodata)), 16):
                hex_str = ' '.join(f'{b:02x}' for b in rodata[i:i+16])
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in rodata[i:i+16])
                print(f"    {i:04x}: {hex_str:48s} {ascii_str}")
            break
    print()

    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()
