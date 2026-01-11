# GE Cync BLE Protocol Explorer

Reverse engineering the GE Cync smart light Bluetooth Mesh protocol for local control without cloud dependency.

## Project Status

**Current State:** Bluetooth Mesh provisioning protocol 90% complete

| Milestone | Status |
|-----------|--------|
| APK Decompilation | ✅ Complete |
| Native Library Analysis (Ghidra) | ✅ Complete |
| Protocol Specification | ✅ Complete |
| ECDH Key Exchange | ✅ Working |
| Confirmation/Random Exchange | ✅ Verified |
| AES-CCM Provisioning Data | 🔄 In Progress |
| Device Control | ⏳ Pending |

## Quick Start

```bash
# Clone and setup
git clone https://github.com/wagonbomb/cync-explorer.git
cd cync-explorer
pip install bleak cryptography pycryptodome

# Run provisioning test (requires Linux/WSL with BlueZ)
python src/linux_ble_provision_final.py
```

## Documentation

| Document | Description |
|----------|-------------|
| [PROTOCOL.md](PROTOCOL.md) | Complete Bluetooth Mesh protocol specification |
| [SETUP.md](SETUP.md) | Environment setup (Windows, WSL, BlueZ) |
| [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) | How we reverse engineered the protocol |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Development notes and progress log |

## Key Discovery

GE Cync lights use **Bluetooth Mesh** (not simple BLE GATT). The device must be **provisioned** before accepting control commands:

```
1. Provisioning Invite    → Device returns Capabilities
2. Provisioning Start     → Selects algorithm (P-256 ECDH)
3. Public Key Exchange    → ECDH shared secret
4. Confirmation Exchange  → AES-CMAC verification
5. Random Exchange        → Mutual authentication ✅ VERIFIED
6. Provisioning Data      → Network key, device key, address
7. Control Commands       → Turn on/off, brightness, etc.
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Python Client                          │
│  src/protocol/telink_framing.py - Packet framing           │
│  src/linux_ble_provision*.py - Provisioning scripts        │
└───────────────────────┬─────────────────────────────────────┘
                        │ BLE GATT
┌───────────────────────▼─────────────────────────────────────┐
│                   Bluetooth Mesh                            │
│  UUID 2adb/2adc - Mesh Provisioning In/Out                 │
│  UUID 2add/2ade - Mesh Proxy In/Out                        │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                  GE Cync Smart Light                        │
│  Telink BLE Mesh SoC                                        │
└─────────────────────────────────────────────────────────────┘
```

## Repository Structure

```
cync-explorer/
├── src/
│   ├── protocol/           # Protocol implementation
│   │   ├── telink_framing.py   # Telink 7-bit varlen framing
│   │   ├── mesh_protocol.py    # Handshake sequences
│   │   └── aes_crypto.py       # AES encryption
│   ├── linux_ble_*.py      # Linux BLE test scripts
│   └── cync_server.py      # Web server for control
├── scripts/
│   ├── ghidra/             # Ghidra analysis scripts
│   └── dex_analysis/       # DEX decompilation tools
├── decomp/                 # Decompiled code documentation
├── md/                     # Project documentation
└── tests/                  # Test scripts
```

## Requirements

- Python 3.8+
- Linux with BlueZ (or WSL2 with USB Bluetooth passthrough)
- Libraries: `bleak`, `cryptography`, `pycryptodome`

## Contributing

This is an active reverse engineering project. Key areas needing work:

1. **AES-CCM encryption** - Fix provisioning data encryption format
2. **Control commands** - Implement brightness, color temperature
3. **Multi-device** - Support for mesh networks with multiple lights

## License

MIT License - See LICENSE file

## Acknowledgments

- Bluetooth Mesh Specification for protocol details
- Ghidra for native library decompilation
- The Home Assistant community for inspiration
