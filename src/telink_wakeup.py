#!/usr/bin/env python3
"""
Telink Wake-Up Protocol Test

Some Telink devices require a specific wake-up sequence before they
respond to commands. This script tries various initialization patterns.

Theory: The device may need:
1. A specific write to 1911/1912 before notifications work
2. An encrypted login using default credentials
3. A specific timing pattern between operations
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

# Telink mesh default credentials
DEFAULT_NAME = "telink_mesh1"
DEFAULT_PASSWORD = "123"  # Common Telink default

# UUIDs
UUID_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"  # Status/Notify
UUID_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"  # Command
UUID_1913 = "00010203-0405-0607-0809-0a0b0c0d1913"  # Data?
UUID_1914 = "00010203-0405-0607-0809-0a0b0c0d1914"  # Pair?
UUID_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
UUID_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
UUID_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
UUID_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

responses = []
any_notify = asyncio.Event()

def make_handler(name):
    def handler(char, data):
        hex_data = data.hex()
        print(f"  [{name}] NOTIFY: {hex_data}")
        responses.append((name, bytes(data)))
        any_notify.set()
    return handler

async def wait_any(timeout=3.0):
    global any_notify
    try:
        await asyncio.wait_for(any_notify.wait(), timeout)
        await asyncio.sleep(0.2)  # Collect more
        any_notify.clear()
        return True
    except asyncio.TimeoutError:
        any_notify.clear()
        return False

def encrypt_login(name, password, session_key):
    """
    Telink mesh login encryption (simplified).
    Real implementation may need proper key derivation.
    """
    from hashlib import md5
    # Basic Telink login uses MD5 of name+password
    combo = (name + password).encode('utf-8')
    hash_bytes = md5(combo).digest()
    return hash_bytes

async def main():
    print("=" * 70)
    print("TELINK WAKE-UP PROTOCOL TEST")
    print("=" * 70)
    print(f"Target: {TARGET_MAC}")
    print()

    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=15.0)
    if not device:
        print("[ERROR] Device not found")
        return

    print(f"Found: {device.name or 'Unknown'}")
    print()

    async with BleakClient(device, timeout=30.0) as client:
        print(f"[CONNECTED] MTU: {client.mtu_size}")
        print()

        # Subscribe to all available notification characteristics
        print("[1] Subscribing to all notify characteristics...")
        notify_chars = [
            ("PROV_OUT", UUID_PROV_OUT),
            ("PROXY_OUT", UUID_PROXY_OUT),
        ]

        for name, uuid in notify_chars:
            try:
                await client.start_notify(uuid, make_handler(name))
                print(f"  [OK] {name}")
            except Exception as e:
                print(f"  [FAIL] {name}: {e}")

        # Try 1911 separately (known to fail on Windows)
        try:
            await client.start_notify(UUID_1911, make_handler("1911"))
            print(f"  [OK] 1911")
        except Exception as e:
            print(f"  [SKIP] 1911: Windows BLE limitation")

        await asyncio.sleep(0.5)

        # ==================== TEST SEQUENCES ====================

        print("\n[2] Trying wake-up sequences...")

        # Sequence A: Simple ping to each characteristic
        print("\n  --- Sequence A: Simple pings ---")
        ping_patterns = [
            bytes([0x00]),  # Single null byte
            bytes([0x01]),  # Single one byte
            bytes([0xFF]),  # Single FF byte
            bytes([0x00, 0x00]),  # Two null bytes
        ]

        for pattern in ping_patterns:
            responses.clear()
            try:
                await client.write_gatt_char(UUID_1912, pattern, response=False)
                print(f"    1912 <- {pattern.hex()}")
                if await wait_any(timeout=1.0):
                    print(f"    *** RESPONSE ***")
            except Exception as e:
                pass

        # Sequence B: Telink login attempt
        print("\n  --- Sequence B: Telink login patterns ---")

        # Login opcode 0x04 with random data
        login_patterns = [
            bytes([0x04]),  # Just opcode
            bytes([0x04, 0x00, 0x00, 0x00, 0x00]),  # Opcode + zeros
            bytes([0x04]) + bytes(16),  # Opcode + 16 zeros
            bytes([0x05]),  # Alternative opcode
            bytes([0x06]),  # Alternative opcode
            bytes([0x07]),  # Alternative opcode
        ]

        for pattern in login_patterns:
            responses.clear()
            try:
                await client.write_gatt_char(UUID_1912, pattern, response=False)
                print(f"    1912 <- {pattern.hex()}")
                if await wait_any(timeout=1.0):
                    print(f"    *** RESPONSE ***")
            except Exception as e:
                pass

        # Sequence C: Cync handshake to 1912
        print("\n  --- Sequence C: Cync handshake on 1912 ---")
        cync_start = bytes.fromhex("000501000000000000000000")
        responses.clear()
        try:
            await client.write_gatt_char(UUID_1912, cync_start, response=False)
            print(f"    1912 <- {cync_start.hex()}")
            if await wait_any(timeout=2.0):
                print(f"    *** RESPONSE ***")
        except Exception as e:
            print(f"    Error: {e}")

        # Sequence D: Try all Telink characteristics
        print("\n  --- Sequence D: Handshake on each Telink char ---")
        telink_chars = [
            ("1911", UUID_1911),
            ("1912", UUID_1912),
            ("1913", UUID_1913),
            ("1914", UUID_1914),
        ]

        for name, uuid in telink_chars:
            responses.clear()
            try:
                await client.write_gatt_char(uuid, cync_start, response=False)
                print(f"    {name} <- {cync_start.hex()}")
                if await wait_any(timeout=1.0):
                    print(f"    *** RESPONSE on {name}! ***")
            except Exception as e:
                print(f"    {name}: Error {e}")

        # Sequence E: Write then read pattern
        print("\n  --- Sequence E: Write-then-read pattern ---")
        for name, uuid in telink_chars:
            responses.clear()
            try:
                # Write first
                await client.write_gatt_char(uuid, bytes([0x00]), response=False)
                await asyncio.sleep(0.1)
                # Then try to read
                data = await client.read_gatt_char(uuid)
                if data:
                    print(f"    {name} read: {data.hex()}")
            except Exception as e:
                pass

        # Sequence F: Read current values
        print("\n  --- Sequence F: Read all Telink values ---")
        for name, uuid in telink_chars:
            try:
                data = await client.read_gatt_char(uuid)
                print(f"    {name}: {data.hex() if data else 'empty'}")
            except Exception as e:
                print(f"    {name}: read error")

        # Summary
        print("\n" + "=" * 70)
        print("RESULTS SUMMARY")
        print("=" * 70)
        if responses:
            print(f"\nReceived {len(responses)} response(s):")
            for name, data in responses:
                print(f"  [{name}] {data.hex()}")
        else:
            print("\nNo responses received from any sequence.")
            print()
            print("The device is not responding to our commands.")
            print("This could mean:")
            print("1. Windows BLE can't enable required notifications")
            print("2. The device requires Android-specific BLE features")
            print("3. There's a timing/sequence we're missing")
            print()
            print("Recommended next steps:")
            print("1. Set up Android emulation (BlueStacks, Android-x86)")
            print("2. Install Cync app in emulator")
            print("3. Use Frida to hook BLE calls and capture exact protocol")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nStopped by user")
