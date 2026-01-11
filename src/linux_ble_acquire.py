#!/usr/bin/env python3
"""
Use BlueZ AcquireNotify directly for Telink notification
"""

import asyncio
import os
from dbus_fast.aio import MessageBus
from dbus_fast import BusType, Message, MessageType

from bleak import BleakScanner, BleakClient

TARGET_MAC = "34:13:43:46:CA:84"
DEVICE_PATH = f"/org/bluez/hci0/dev_{TARGET_MAC.replace(':', '_')}"

UUID_1911 = "00010203-0405-0607-0809-0a0b0c0d1911"
UUID_1912 = "00010203-0405-0607-0809-0a0b0c0d1912"

# The 1911 characteristic path (will be determined dynamically)
CHAR_1911_PATH = None

HANDSHAKE = [
    ("START", "000501000000000000000000"),
    ("KEY_EXCHANGE", "00000100000000000000040000"),
    ("SYNC_0", "3100"),
    ("SYNC_1", "3101"),
    ("SYNC_2", "3102"),
    ("SYNC_3", "3103"),
    ("SYNC_4", "3104"),
    ("MSG_1", "00000100000000000000160000"),
    ("MSG_2", "00000100000000000000010002"),
    ("AUTH", "320119000000"),
]

responses = []
response_event = asyncio.Event()

def handler(sender, data):
    hex_data = data.hex()
    print(f"  <- NOTIFY: {hex_data}")
    responses.append(data)
    response_event.set()

async def wait_response(timeout=2.0):
    global response_event
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        await asyncio.sleep(0.1)
        response_event.clear()
        return True
    except asyncio.TimeoutError:
        response_event.clear()
        return False

async def read_fd_notifications(fd, callback):
    """Read notifications from file descriptor"""
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)

    def read_callback():
        try:
            data = os.read(fd, 512)
            if data:
                callback(None, data)
        except Exception as e:
            print(f"FD read error: {e}")

    loop.add_reader(fd, read_callback)
    return reader

async def acquire_notify_dbus(bus, char_path):
    """Try to acquire notification using D-Bus directly"""
    print(f"  Trying AcquireNotify on {char_path}")

    try:
        msg = Message(
            destination='org.bluez',
            path=char_path,
            interface='org.bluez.GattCharacteristic1',
            member='AcquireNotify',
            signature='a{sv}',
            body=[{}]  # Empty options dict
        )

        reply = await bus.call(msg)

        if reply.message_type == MessageType.METHOD_RETURN:
            # AcquireNotify returns (fd, mtu)
            fd, mtu = reply.body
            print(f"  [OK] AcquireNotify succeeded! FD={fd}, MTU={mtu}")
            return fd, mtu
        else:
            print(f"  [FAIL] {reply.body}")
            return None, None

    except Exception as e:
        print(f"  [ERROR] {e}")
        return None, None

async def main():
    print("=" * 60)
    print("BLE WITH DBUS ACQUIRE NOTIFY")
    print("=" * 60)
    print()

    print("[0] Finding device...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=30.0)

    if not device:
        print("  Device not found!")
        return

    print(f"  Found: {device.name} ({device.address})")

    print()
    print("[1] Connecting...")

    client = BleakClient(device, timeout=30.0)

    try:
        await client.connect()
        print(f"  Connected! MTU: {client.mtu_size}")

        # Wait for services
        await asyncio.sleep(2.0)
        services = client.services

        # Find 1911 characteristic handle
        char_1911 = None
        for service in services:
            for char in service.characteristics:
                if "1911" in char.uuid:
                    char_1911 = char
                    print(f"  Found 1911: Handle {char.handle}")
                    break

        print()
        print("[2] Trying notification methods...")

        subscribed = False
        notify_fd = None

        # Method 1: Try standard start_notify
        print("  Method 1: start_notify")
        try:
            await client.start_notify(UUID_1911, handler)
            print("  [OK] start_notify worked!")
            subscribed = True
        except Exception as e:
            print(f"  [FAIL] {e}")

        # Method 2: Try D-Bus AcquireNotify if Method 1 failed
        if not subscribed:
            print("  Method 2: D-Bus AcquireNotify")
            try:
                bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

                # Build the characteristic path
                # Format: /org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX/serviceXXXX/charXXXX
                char_path = f"{DEVICE_PATH}/service000c/char0010"  # Service/char indices vary
                notify_fd, mtu = await acquire_notify_dbus(bus, char_path)

                if notify_fd:
                    print(f"  Setting up FD reader...")
                    asyncio.create_task(read_fd_notifications(notify_fd, handler))
                    subscribed = True

            except Exception as e:
                print(f"  [FAIL] {e}")

        if not subscribed:
            print("  [WARN] Could not subscribe - continuing without notifications")

        await asyncio.sleep(0.5)

        print()
        print("[3] Sending handshake...")
        print("-" * 60)

        for name, cmd_hex in HANDSHAKE:
            cmd = bytes.fromhex(cmd_hex)
            responses.clear()

            print(f"\n  [{name}] -> {cmd_hex}")

            try:
                await client.write_gatt_char(UUID_1912, cmd, response=False)
                if subscribed:
                    if await wait_response(timeout=2.0):
                        pass
                    else:
                        print(f"  (no response)")
                else:
                    await asyncio.sleep(0.3)
            except Exception as e:
                print(f"  Error: {e}")

        print()
        print("=" * 60)

        # Control commands
        print("\n[4] Control commands...")
        for name, cmd in [("ON", "b0c00101"), ("OFF", "b0c00100")]:
            print(f"\n  [{name}] -> {cmd}")
            try:
                await client.write_gatt_char(UUID_1912, bytes.fromhex(cmd), response=False)
                print("  Sent - check light!")
                await asyncio.sleep(3.0)
            except Exception as e:
                print(f"  Error: {e}")

    finally:
        if notify_fd:
            try:
                os.close(notify_fd)
            except:
                pass
        await client.disconnect()

    print()
    print("Done!")

if __name__ == "__main__":
    asyncio.run(main())
