"""
Single Command Iterator
Tests one command per connection to avoid disconnects

Target: 34:13:43:46:CA:84
"""

import asyncio
from bleak import BleakClient

TARGET = "34:13:43:46:CA:84"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

notif_received = []

def handler(sender, data):
    hex_data = data.hex()
    notif_received.append(hex_data)
    print(f"  << {hex_data}")

async def send_single_command(cmd_hex, wait_time=2.0):
    """Send one command and wait for response"""
    global notif_received
    notif_received = []
    
    try:
        async with BleakClient(TARGET, timeout=10.0) as client:
            await client.start_notify(MESH_PROXY_OUT, handler)
            await asyncio.sleep(0.3)
            
            # Clear initial notification
            notif_received = []
            
            # Send command
            print(f"  >> {cmd_hex}")
            await client.write_gatt_char(MESH_PROXY_IN, bytes.fromhex(cmd_hex), response=False)
            await asyncio.sleep(wait_time)
            
            try:
                await client.stop_notify(MESH_PROXY_OUT)
            except:
                pass
            
            return len(notif_received) > 0
    except Exception as e:
        print(f"  ERROR: {e}")
        return False

async def main():
    print("="*60)
    print("SINGLE COMMAND ITERATOR")
    print("Testing commands one at a time with reconnects")
    print("="*60)
    print()
    
    # Test commands from simplest to complex
    test_commands = [
        # Session-based control (b0-b5 most likely)
        "b0c001",  # Session 0 ON
        "b0c000",  # Session 0 OFF
        "b1c001",  # Session 1 ON
        "b1c000",  # Session 1 OFF
        "b2c001",  # Session 2 ON
        "b2c000",  # Session 2 OFF
        "b3c001",  # Session 3 ON
        "b3c000",  # Session 3 OFF
        "b4c001",  # Session 4 ON
        "b4c000",  # Session 4 OFF
        "b5c001",  # Session 5 ON
        "b5c000",  # Session 5 OFF
        
        # Try with longer payloads
        "b0c00100",
        "b0c00000",
        
        # Try different second byte
        "b0d001",
        "b0d000",
        
        # Simple payloads
        "01",
        "00",
        "0001",
        "0000",
    ]
    
    results = []
    
    for i, cmd in enumerate(test_commands, 1):
        print(f"[{i}/{len(test_commands)}] {cmd}")
        got_response = await send_single_command(cmd, wait_time=1.5)
        results.append((cmd, got_response))
        
        if got_response:
            print("  ✓ GOT RESPONSE!")
        
        print()
        await asyncio.sleep(0.5)  # Pause between tests
    
    print("="*60)
    print("RESULTS SUMMARY")
    print("="*60)
    
    responses = [cmd for cmd, resp in results if resp]
    if responses:
        print(f"✓ Commands that got responses: {len(responses)}")
        for cmd in responses:
            print(f"  - {cmd}")
    else:
        print("✗ No commands received responses")
    
    print()
    print("Check if the light physically changed state during any test!")

if __name__ == "__main__":
    asyncio.run(main())
