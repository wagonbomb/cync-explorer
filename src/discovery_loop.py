"""
Discovery & Control Iteration Loop
Target: 34:13:43:46:CA:84

This script systematically tries different approaches to gain control:
1. Pairing/Bonding
2. Service discovery with pairing
3. Command testing with various authentication states
4. Brute force discovery of working commands
5. Key extraction and reverse engineering

Each iteration logs results to build knowledge base.
"""

import asyncio
from bleak import BleakClient, BleakScanner
from datetime import datetime
import json
import os
from pathlib import Path

TARGET_DEVICE = "34:13:43:46:CA:84"

# Characteristics
MESH_PROVISIONING_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

# Results storage
REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "artifacts" / "outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_FILE = OUTPUT_DIR / "discovery_results.json"
results = []
notifications = []


def log_result(iteration, test_name, success, data=None):
    """Log a test result."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "iteration": iteration,
        "test": test_name,
        "success": success,
        "data": data
    }
    results.append(result)
    print(f"  [{'✓' if success else '✗'}] {test_name}")
    if data:
        print(f"      {data}")


def save_results():
    """Save results to file."""
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)


def notification_handler(sender, data):
    """Capture all notifications."""
    hex_data = data.hex()
    notifications.append({
        "timestamp": datetime.now().isoformat(),
        "sender": str(sender),
        "hex": hex_data,
        "bytes": list(data)
    })
    print(f"    RX: {hex_data}")


async def iteration_1_pairing():
    """ITERATION 1: Attempt to pair/bond with device"""
    print("\n" + "="*60)
    print("ITERATION 1: PAIRING/BONDING ATTEMPT")
    print("="*60)
    
    try:
        print("Connecting with pairing enabled...")
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            print(f"✓ Connected")
            
            # Check if already paired
            if hasattr(client, 'is_paired'):
                paired = client.is_paired
                log_result(1, "Check pairing status", True, f"Paired: {paired}")
            
            # Try to pair
            print("\nAttempting to pair...")
            try:
                # In Bleak, pairing happens automatically on Windows when needed
                # We can trigger it by trying to access characteristics
                services = list(client.services)
                log_result(1, "Service access (triggers pairing)", True, f"{len(services)} services")
                
                # Try to read a characteristic that might require pairing
                for service in services:
                    for char in service.characteristics:
                        if "read" in char.properties:
                            try:
                                value = await client.read_gatt_char(char.uuid)
                                log_result(1, f"Read {char.uuid[:8]}", True, value.hex())
                            except Exception as e:
                                log_result(1, f"Read {char.uuid[:8]}", False, str(e))
                            break
                    break
                
            except Exception as e:
                log_result(1, "Pairing attempt", False, str(e))
            
            return True
            
    except Exception as e:
        log_result(1, "Connection with pairing", False, str(e))
        return False


async def iteration_2_paired_commands():
    """ITERATION 2: Try commands after pairing"""
    print("\n" + "="*60)
    print("ITERATION 2: COMMANDS AFTER PAIRING")
    print("="*60)
    
    notifications.clear()
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            print("✓ Connected")
            
            # Subscribe
            await client.start_notify(MESH_PROXY_OUT, notification_handler)
            log_result(2, "Subscribe to notifications", True)
            await asyncio.sleep(0.5)
            
            # Try handshake commands
            commands = [
                ("Handshake START", MESH_PROVISIONING_IN, "000501"),
                ("Handshake KEY", MESH_PROVISIONING_IN, "000001040000"),
                ("Sync 31-00", MESH_PROXY_IN, "3100"),
                ("Sync 31-01", MESH_PROXY_IN, "3101"),
                ("Sync 31-02", MESH_PROXY_IN, "3102"),
                ("Finalize", MESH_PROXY_IN, "320119000000"),
            ]
            
            for name, uuid, data_hex in commands:
                print(f"\n  TX: {name} -> {data_hex}")
                data = bytes.fromhex(data_hex)
                await client.write_gatt_char(uuid, data, response=False)
                log_result(2, f"Send {name}", True, data_hex)
                await asyncio.sleep(0.6)
            
            # Check for responses
            notif_count = len(notifications)
            log_result(2, "Total notifications received", notif_count > 0, f"{notif_count} notifications")
            
            await client.stop_notify(MESH_PROXY_OUT)
            return notif_count > 0
            
    except Exception as e:
        log_result(2, "Paired commands test", False, str(e))
        return False


async def iteration_3_brute_force_prefixes():
    """ITERATION 3: Brute force command prefixes"""
    print("\n" + "="*60)
    print("ITERATION 3: BRUTE FORCE COMMAND PREFIXES")
    print("="*60)
    print("Testing b0-bf prefix range...\n")
    
    notifications.clear()
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            print("✓ Connected")
            
            await client.start_notify(MESH_PROXY_OUT, notification_handler)
            await asyncio.sleep(0.3)
            
            # Try b0-bf with c0 suffix and ON/OFF payloads
            for prefix in range(0xb0, 0xc0):
                for payload in [0x01, 0x00]:
                    cmd = bytes([prefix, 0xc0, payload])
                    print(f"  Testing: {cmd.hex()}", end=" ")
                    
                    try:
                        await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
                        await asyncio.sleep(0.3)
                        
                        if len(notifications) > 0:
                            print("← GOT RESPONSE!")
                            log_result(3, f"Prefix {prefix:02x}", True, cmd.hex())
                        else:
                            print()
                    except Exception as e:
                        print(f"ERROR: {e}")
                        log_result(3, f"Prefix {prefix:02x}", False, str(e))
            
            await client.stop_notify(MESH_PROXY_OUT)
            return len(notifications) > 0
            
    except Exception as e:
        log_result(3, "Brute force prefixes", False, str(e))
        return False


async def iteration_4_analyze_initial_notification():
    """ITERATION 4: Deep analysis of initial notification"""
    print("\n" + "="*60)
    print("ITERATION 4: ANALYZE INITIAL NOTIFICATION")
    print("="*60)
    
    notifications.clear()
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            print("✓ Connected")
            
            await client.start_notify(MESH_PROXY_OUT, notification_handler)
            await asyncio.sleep(1)
            
            if len(notifications) > 0:
                initial = notifications[0]
                data = bytes.fromhex(initial["hex"])
                
                print(f"\nInitial notification: {initial['hex']}")
                print(f"Length: {len(data)} bytes")
                print("\nByte-by-byte analysis:")
                
                for i, b in enumerate(data):
                    print(f"  [{i:02d}] 0x{b:02x} = {b:3d} = {chr(b) if 32 <= b < 127 else '.'}")
                
                # Look for patterns
                print("\nPattern analysis:")
                if len(data) >= 4:
                    print(f"  First 4 bytes: {data[:4].hex()}")
                if len(data) >= 8:
                    print(f"  Bytes 4-7: {data[4:8].hex()}")
                
                # Look for potential session ID
                for i in range(len(data) - 3):
                    if data[i] == 0x04 and data[i+1] == 0x00 and data[i+2] == 0x00:
                        print(f"  → Session ID pattern at offset {i}: 0x{data[i+3]:02x}")
                
                log_result(4, "Initial notification analysis", True, initial["hex"])
            
            await client.stop_notify(MESH_PROXY_OUT)
            return len(notifications) > 0
            
    except Exception as e:
        log_result(4, "Notification analysis", False, str(e))
        return False


async def iteration_5_read_all_readable():
    """ITERATION 5: Read all readable characteristics"""
    print("\n" + "="*60)
    print("ITERATION 5: READ ALL READABLE CHARACTERISTICS")
    print("="*60)
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            print("✓ Connected\n")
            
            services = list(client.services)
            readable_chars = []
            
            for service in services:
                for char in service.characteristics:
                    if "read" in char.properties:
                        try:
                            print(f"Reading {char.uuid}...")
                            value = await client.read_gatt_char(char.uuid)
                            hex_val = value.hex()
                            print(f"  Value: {hex_val}")
                            
                            # Try to interpret as string
                            try:
                                str_val = value.decode('utf-8', errors='ignore')
                                if str_val.isprintable():
                                    print(f"  String: {str_val}")
                            except:
                                pass
                            
                            log_result(5, f"Read {char.uuid[:8]}", True, hex_val)
                            readable_chars.append({
                                "uuid": char.uuid,
                                "value": hex_val
                            })
                            
                        except Exception as e:
                            log_result(5, f"Read {char.uuid[:8]}", False, str(e))
            
            print(f"\nRead {len(readable_chars)} characteristics successfully")
            return len(readable_chars) > 0
            
    except Exception as e:
        log_result(5, "Read all characteristics", False, str(e))
        return False


async def iteration_6_telink_legacy_commands():
    """ITERATION 6: Try legacy Telink commands"""
    print("\n" + "="*60)
    print("ITERATION 6: LEGACY TELINK COMMANDS")
    print("="*60)
    
    TELINK_COMMAND = "00010203-0405-0607-0809-0a0b0c0d1912"
    
    notifications.clear()
    
    # Legacy Telink packet structure: 7E [LEN] [CMD] [PAYLOAD] CRC
    legacy_commands = [
        ("Power ON", "7e0704100001010069"),
        ("Power OFF", "7e0704100001000068"),
        ("Query Status", "7e0300da00dd"),
    ]
    
    try:
        async with BleakClient(TARGET_DEVICE, timeout=15.0) as client:
            print("✓ Connected\n")
            
            for name, cmd_hex in legacy_commands:
                print(f"  TX: {name} -> {cmd_hex}")
                try:
                    cmd = bytes.fromhex(cmd_hex)
                    await client.write_gatt_char(TELINK_COMMAND, cmd, response=False)
                    log_result(6, f"Send {name}", True, cmd_hex)
                    await asyncio.sleep(0.5)
                except Exception as e:
                    log_result(6, f"Send {name}", False, str(e))
            
            return True
            
    except Exception as e:
        log_result(6, "Legacy Telink commands", False, str(e))
        return False


async def main():
    """Run all discovery iterations"""
    print("\n" + "="*70)
    print(" DISCOVERY & CONTROL ITERATION LOOP")
    print(" Target: 34:13:43:46:CA:84")
    print("="*70)
    print(f" Started: {datetime.now().isoformat()}")
    print("="*70)
    
    iterations = [
        ("Pairing/Bonding", iteration_1_pairing),
        ("Commands After Pairing", iteration_2_paired_commands),
        ("Brute Force Prefixes", iteration_3_brute_force_prefixes),
        ("Analyze Initial Notification", iteration_4_analyze_initial_notification),
        ("Read All Characteristics", iteration_5_read_all_readable),
        ("Legacy Telink Commands", iteration_6_telink_legacy_commands),
    ]
    
    for i, (name, func) in enumerate(iterations, 1):
        try:
            await func()
            await asyncio.sleep(1)  # Brief pause between iterations
        except KeyboardInterrupt:
            print("\n\n⚠ Interrupted by user")
            break
        except Exception as e:
            print(f"\n✗ Iteration {i} crashed: {e}")
            log_result(i, name, False, str(e))
    
    # Save all results
    save_results()
    
    print("\n" + "="*70)
    print(" ITERATION COMPLETE")
    print("="*70)
    print(f" Results saved to: {RESULTS_FILE}")
    print(f" Total tests: {len(results)}")
    print(f" Successful: {sum(1 for r in results if r['success'])}")
    print(f" Failed: {sum(1 for r in results if not r['success'])}")
    print("="*70)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
        save_results()
