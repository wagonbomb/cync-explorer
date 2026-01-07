"""
Network Scanner for Cync Devices
Scans the local network to find Cync devices via WiFi/IP.
Uses ARP, ping sweep, and port scanning to discover devices.
"""

import asyncio
import subprocess
import socket
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Import known devices
try:
    from known_devices import KNOWN_CYNC_MACS, GE_MAC_PREFIXES, format_mac, normalize_mac
except ImportError:
    KNOWN_CYNC_MACS = []
    GE_MAC_PREFIXES = ["341343", "786DEB"]
    def normalize_mac(mac): return mac.replace(":", "").replace("-", "").upper()
    def format_mac(mac): 
        m = normalize_mac(mac)
        return ":".join(m[i:i+2] for i in range(0, 12, 2))


def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"


def get_network_prefix(ip: str) -> str:
    """Get the network prefix (first 3 octets) from an IP."""
    parts = ip.split(".")
    return ".".join(parts[:3])


def get_arp_table():
    """Get the ARP table from the system."""
    print("Reading ARP table...")
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout
    except Exception as e:
        print(f"Error reading ARP table: {e}")
        return ""


def parse_arp_table(arp_output: str) -> list:
    """Parse ARP table output into list of (IP, MAC) tuples."""
    devices = []
    
    # Windows ARP format: "  192.168.1.100       aa-bb-cc-dd-ee-ff     dynamic"
    # Also matches: "192.168.1.100         aa:bb:cc:dd:ee:ff"
    pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'
    
    for match in re.finditer(pattern, arp_output):
        ip = match.group(1)
        mac = match.group(2)
        devices.append((ip, mac))
    
    return devices


def ping_host(ip: str, timeout: float = 0.5) -> bool:
    """Ping a single host to check if it's alive and populate ARP."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
            capture_output=True,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def ping_sweep(network_prefix: str, start: int = 1, end: int = 254, workers: int = 50):
    """Ping sweep a network range to populate the ARP table."""
    print(f"Ping sweeping {network_prefix}.{start}-{end} ({end-start+1} hosts)...")
    
    ips = [f"{network_prefix}.{i}" for i in range(start, end + 1)]
    alive = []
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(ping_host, ips))
    
    for ip, is_alive in zip(ips, results):
        if is_alive:
            alive.append(ip)
    
    print(f"Found {len(alive)} responding hosts")
    return alive


def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a specific port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_cync_ports(ip: str) -> dict:
    """Scan common ports that Cync devices might use."""
    # Common IoT/smart home ports
    ports_to_check = {
        80: "HTTP",
        443: "HTTPS", 
        8080: "HTTP Alt",
        23778: "Cync Cloud Port",
        1883: "MQTT",
        8883: "MQTT SSL",
        5683: "CoAP",
    }
    
    open_ports = {}
    for port, name in ports_to_check.items():
        if check_port(ip, port):
            open_ports[port] = name
    
    return open_ports


def scan_network():
    """Main network scanning function."""
    print("=" * 80)
    print("CYNC NETWORK SCANNER (WiFi/IP)")
    print("=" * 80)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting network scan...")
    print()
    
    # Get local IP and network
    local_ip = get_local_ip()
    network_prefix = get_network_prefix(local_ip)
    print(f"Local IP: {local_ip}")
    print(f"Network: {network_prefix}.0/24")
    print()
    
    # First, read existing ARP table
    arp_output = get_arp_table()
    existing_devices = parse_arp_table(arp_output)
    print(f"Existing ARP entries: {len(existing_devices)}")
    
    # Ping sweep to discover more devices
    print()
    ping_sweep(network_prefix)
    
    # Read ARP table again after ping sweep
    print()
    arp_output = get_arp_table()
    all_devices = parse_arp_table(arp_output)
    print(f"Total ARP entries after sweep: {len(all_devices)}")
    
    # Categorize devices
    known_cync = []
    unknown_ge = []
    other_devices = []
    
    print()
    print("=" * 80)
    print(f"{'Status':<12} {'IP Address':<16} {'MAC Address':<20} {'Open Ports'}")
    print("=" * 80)
    
    for ip, mac in all_devices:
        mac_normalized = normalize_mac(mac)
        mac_display = format_mac(mac)
        mac_prefix = mac_normalized[:6]
        
        is_known = mac_normalized in KNOWN_CYNC_MACS
        has_ge_prefix = mac_prefix in GE_MAC_PREFIXES
        
        # For GE devices, check interesting ports
        ports_str = ""
        if is_known or has_ge_prefix:
            open_ports = scan_cync_ports(ip)
            if open_ports:
                ports_str = ", ".join(f"{p}({n})" for p, n in open_ports.items())
        
        if is_known:
            status = "✅ KNOWN"
            known_cync.append((ip, mac_normalized, ports_str))
            print(f"{status:<12} {ip:<16} {mac_display:<20} {ports_str}")
        elif has_ge_prefix:
            status = "⚠️ NEW GE"
            unknown_ge.append((ip, mac_normalized, ports_str))
            print(f"{status:<12} {ip:<16} {mac_display:<20} {ports_str}")
        else:
            other_devices.append((ip, mac_normalized))
            # Uncomment to see all devices:
            # print(f"{'   ':<12} {ip:<16} {mac_display:<20}")
    
    # Summary
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    if known_cync:
        print(f"\n✅ KNOWN CYNC DEVICES ON NETWORK ({len(known_cync)}):")
        for ip, mac, ports in known_cync:
            print(f"   {ip:<16} {format_mac(mac)}")
            if ports:
                print(f"                   Open ports: {ports}")
    
    if unknown_ge:
        print(f"\n⚠️  UNKNOWN GE DEVICES ({len(unknown_ge)}) - Not in known list:")
        for ip, mac, ports in unknown_ge:
            print(f"   {ip:<16} {format_mac(mac)}")
            if ports:
                print(f"                   Open ports: {ports}")
    
    print(f"\n📊 Total devices on network: {len(all_devices)}")
    print(f"   Known Cync: {len(known_cync)}")
    print(f"   Unknown GE: {len(unknown_ge)}")
    print(f"   Other: {len(other_devices)}")
    
    if not known_cync and not unknown_ge:
        print("\n⚠️  No Cync devices found on network!")
        print("   The MAC addresses might be different on WiFi vs what the app reports.")
        print("   Check your router's DHCP client list for devices.")
    
    return {
        "known": known_cync,
        "unknown_ge": unknown_ge,
        "other": other_devices
    }


if __name__ == "__main__":
    scan_network()
