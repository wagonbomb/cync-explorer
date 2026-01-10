"""
Test exact handshake sequence from HCI logs with response validation.
Based on analyze_hci_deep.ps1 findings showing working command-response pairs.
"""

import asyncio
from bleak import BleakClient, BleakScanner

TARGET_MAC = "34:13:43:46:CA:84"

# UUIDs
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

responses = []
response_event = asyncio.Event()

def notification_handler(sender, data):
    """Capture all notifications"""
    global responses
    hex_data = data.hex()
    print(f"  ← RESPONSE: {hex_data}")
    responses.append(hex_data)
    response_event.set()

async def send_and_wait(client, uuid, command_hex, expected_prefix=None, timeout=2.0):
    """Send command and wait for response"""
    global responses, response_event
    
    responses.clear()
    response_event.clear()
    
    command = bytes.fromhex(command_hex)
    print(f"\n→ SEND: {command_hex}")
    
    await client.write_gatt_char(uuid, command, response=False)
    
    # Wait for response
    try:
        await asyncio.wait_for(response_event.wait(), timeout)
        
        if responses:
            latest = responses[-1]
            if expected_prefix and not latest.startswith(expected_prefix):
                print(f"  ⚠️  WARNING: Expected prefix {expected_prefix}, got {latest}")
                return None
            return latest
        else:
            print(f"  ✗ No response received")
            return None
            
    except asyncio.TimeoutError:
        print(f"  ✗ Timeout waiting for response")
        return None

async def main():
    print(f"Testing exact HCI handshake sequence on {TARGET_MAC}\n")
    
    # Find device
    print("Scanning...")
    device = await BleakScanner.find_device_by_address(TARGET_MAC, timeout=10.0)
    if not device:
        print(f"✗ Device not found")
        return
    print(f"✓ Found device\n")
    
    # Connect
    async with BleakClient(device, timeout=15.0) as client:
        print(f"✓ Connected (MTU: {client.mtu_size})\n")
        
        # Subscribe to notifications
        print("Subscribing to Provisioning Out and Proxy Out...")
        await client.start_notify(MESH_PROV_OUT, notification_handler)
        await client.start_notify(MESH_PROXY_OUT, notification_handler)
        await asyncio.sleep(1.0)
        print("✓ Subscribed\n")
        
        print("="*60)
        print("HANDSHAKE SEQUENCE FROM HCI LOGS")
        print("="*60)
        
        # Step 1: Start session
        resp1 = await send_and_wait(client, MESH_PROV_IN, "000501000000000000000000", "000601")
        if not resp1:
            print("\n✗ FAILED: Step 1 - No response to session start")
            return
        
        # Step 2: Request capabilities
        resp2 = await send_and_wait(client, MESH_PROV_IN, "00000100000000000000040000", "000101")
        if not resp2:
            print("\n✗ FAILED: Step 2 - No capabilities response")
            return
        
        # Step 3-7: Exchange keys (3100-3104)
        for i in range(5):
            cmd = f"31{i:02x}"
            expected = f"31{i:02x}"
            resp = await send_and_wait(client, MESH_PROV_IN, cmd, expected)
            if not resp:
                print(f"\n✗ FAILED: Step {i+3} - No response to {cmd}")
                return
        
        print("\n✓ Key exchange complete!")
        
        # Step 8: Finalize session
        resp8 = await send_and_wait(client, MESH_PROV_IN, "00000100000000000000160000", "000101")
        if not resp8:
            print("\n✗ FAILED: Step 8 - No session finalization response")
            return
        
        # Step 9: Activate
        resp9 = await send_and_wait(client, MESH_PROV_IN, "320119000000", "3202")
        if not resp9:
            print("\n✗ FAILED: Step 9 - No activation response")
            return
        
        print("\n" + "="*60)
        print("SESSION ESTABLISHED - TESTING CONTROL")
        print("="*60)
        
        # Now try control commands
        print("\nTrying light control via Mesh Proxy...")
        
        # Turn ON
        await send_and_wait(client, MESH_PROXY_IN, "b0c001", "b1", timeout=3.0)
        await asyncio.sleep(1.0)
        
        # Turn OFF
        await send_and_wait(client, MESH_PROXY_IN, "b0c000", "b1", timeout=3.0)
        await asyncio.sleep(1.0)
        
        # Turn ON again
        await send_and_wait(client, MESH_PROXY_IN, "b0c001", "b1", timeout=3.0)
        
        print("\n" + "="*60)
        print("DID THE LIGHT CHANGE? (Check physically)")
        print("="*60)
        
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    asyncio.run(main())
