"""
Known GE Cync devices in the network.
MAC addresses are stored normalized (uppercase, no separators).
"""

# All known Cync light MAC addresses (normalized: uppercase, no separators)
# User provided 32 devices
KNOWN_CYNC_MACS = [
    "786DEB4CEF15",
    "786DEB4D6869",
    "34134304F861",
    "34134322E745",
    "341343802483",
    "3413438035OD",
    "341343804189",
    "3413438O493D",
    "34134322D1AB",
    "341343230986",
    "3413434703C3",
    "341343470749",
    "786DEBB58D00",
    "786DEBB630CA",
    "786DEBE9C9A1",
    "78D6EBEB2CA3",
    "31134323OBC6",
    "341343803C1B",
    "341343804313",
    "786DEB4D6C29",
    "786DEB4D65C2",
    "786DEB4D2E44",
    "341343053E18",
    "34134306A9D0",
    "786DEBB2B07C",
    "786DEBB369FD",
    "786DEBBA5610",
    "786DEBBB4E00",
    "34134346B89D",
    "34134346BA2F",
    "34134346C225",
    "34134346CA85",
]

# Known GE/Cync MAC prefixes (OUI - first 3 bytes)
GE_MAC_PREFIXES = ["341343", "786DEB"]


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase with no separators."""
    return mac.replace(":", "").replace("-", "").upper()


def format_mac(mac: str) -> str:
    """Format normalized MAC with colons for display."""
    mac = normalize_mac(mac)
    return ":".join(mac[i:i+2] for i in range(0, 12, 2))


def is_known_cync(mac: str) -> bool:
    """Check if a MAC address is in our known Cync devices list."""
    norm_mac = normalize_mac(mac)
    
    # Check exact match
    if norm_mac in KNOWN_CYNC_MACS:
        return True
        
    # Check for off-by-one MACs (BLE often offset from WiFi)
    try:
        mac_int = int(norm_mac, 16)
        mac_plus_1 = f"{mac_int + 1:012X}"
        mac_minus_1 = f"{mac_int - 1:012X}"
        return (mac_plus_1 in KNOWN_CYNC_MACS) or (mac_minus_1 in KNOWN_CYNC_MACS)
    except ValueError:
        return False


def is_ge_mac_prefix(mac: str) -> bool:
    """Check if MAC has a known GE prefix."""
    normalized = normalize_mac(mac)
    return normalized[:6] in GE_MAC_PREFIXES


def get_all_macs_formatted() -> list:
    """Get all known MACs formatted with colons."""
    return [format_mac(mac) for mac in KNOWN_CYNC_MACS]


if __name__ == "__main__":
    print(f"Known Cync devices: {len(KNOWN_CYNC_MACS)}")
    print("-" * 40)
    for mac in KNOWN_CYNC_MACS:
        print(f"  {format_mac(mac)}")
