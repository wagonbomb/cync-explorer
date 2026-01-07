
import asyncio
import json
import logging
import os
import sys
from datetime import datetime

from aiohttp import web
from bleak import BleakScanner, BleakClient

# Add local path to imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from ble_scanner import enhanced_scan, format_mac, normalize_mac
from known_devices import KNOWN_CYNC_MACS

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cync_server")

# Global state
connected_clients = {}

async def handle_root(request):
    """Serve the main HTML page."""
    return web.FileResponse('./static/index.html')

async def handle_scan(request):
    """Run BLE scan and return results."""
    logger.info("Starting BLE scan request...")
    
    # Run the enhanced scan
    scan_results = await enhanced_scan(timeout=10.0, connect_to_ge=False)
    
    # Process devices to add alias info for the frontend
    processed_devices = []
    
    # Combine GE devices and potentially others if needed
    for address, device, adv_data in scan_results.get("ge_devices", []):
        
        # Check aliases
        scan_mac = normalize_mac(address)
        alias_of = None
        
        try:
            mac_int = int(scan_mac, 16)
            plus_1 = f"{mac_int + 1:012X}"
            minus_1 = f"{mac_int - 1:012X}"
            
            if plus_1 in KNOWN_CYNC_MACS:
                alias_of = format_mac(plus_1)
            elif minus_1 in KNOWN_CYNC_MACS:
                alias_of = format_mac(minus_1)
            elif scan_mac in KNOWN_CYNC_MACS:
                alias_of = "Exact Match"
        except:
            pass

        processed_devices.append({
            "address": address,
            "name": device.name,
            "rssi": adv_data.rssi,
            "advertisement": {
                "local_name": adv_data.local_name,
                "rssi": adv_data.rssi
            },
            "alias_of": alias_of
        })
    
    # Sort by RSSI
    processed_devices.sort(key=lambda x: x['rssi'], reverse=True)
    
    return web.json_response({"devices": processed_devices})

async def handle_connect(request):
    """Explicitly connect to a device."""
    try:
        data = await request.json()
        mac = data.get('mac')
        if not mac: return web.json_response({"success": False, "error": "No MAC"}, status=400)
        
        logger.info(f"Connect request: {mac}")
        client = connected_clients.get(mac)
        
        if client and client.is_connected:
            return web.json_response({"success": True, "message": "Already connected", "initial_state": False}) 
            # ideally we should read state here too, but for now simple check
            
        # Connect
        client = BleakClient(mac, timeout=15.0)
        await client.connect()
        connected_clients[mac] = client
        logger.info(f"Connected to {mac}")
        
        # Read Initial State
        initial_state = False
        try:
             # Correct Telink UUID
            CONTROL_CHAR_UUID = "00010203-0405-0607-0809-0a0b0c0d1911" 
            val = await client.read_gatt_char(CONTROL_CHAR_UUID)
            logger.info(f"Initial state read: {val.hex()}")
            # Simple heuristic: if value is not 00 or 0000, assume ON
            # This varies by firmware, but often 0x00 is OFF
            if any(b != 0 for b in val):
                initial_state = True
        except Exception as e:
            logger.warning(f"Could not read initial state: {e}")
        
        return web.json_response({"success": True, "initial_state": initial_state})
    except Exception as e:
        logger.error(f"Connect error: {e}")
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_disconnect(request):
    """Disconnect from a device."""
    try:
        data = await request.json()
        mac = data.get('mac')
        if not mac: return web.json_response({"success": False, "error": "No MAC"}, status=400)
        
        client = connected_clients.get(mac)
        if client:
            await client.disconnect()
            del connected_clients[mac]
            
        return web.json_response({"success": True})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_control(request):
    """Handle control commands (ON/OFF)."""
    try:
        data = await request.json()
        mac = data.get('mac')
        action = data.get('action')
        
        if not mac or not action:
            return web.json_response({"success": False, "error": "Missing mac or action"}, status=400)
            
        logger.info(f"Control request: {mac} -> {action}")
        
        # Connect if not connected (Auto-connect fallback)
        client = connected_clients.get(mac)
        
        if not client or not client.is_connected:
            logger.info(f"Auto-connecting to {mac}...")
            client = BleakClient(mac, timeout=15.0)
            await client.connect()
            connected_clients[mac] = client
        
        # Determine command bytes
        # Correct Telink UUID from scan logs
        CONTROL_CHAR_UUID = "00010203-0405-0607-0809-0a0b0c0d1911" 
        
        # Command values
        # For Cync/Telink Mesh, simple 0x01 often doesn't work directly on this char without session
        # But let's try the common Telink On/Off commands first
        
        if action == 'on':
             # Try simple ON first
             cmd = bytes([0x01])
        elif action == 'off':
             cmd = bytes([0x00])
             
        try:
            # Try to find the characteristic if the specific UUID isn't valid for this device
            target_uuid = CONTROL_CHAR_UUID
            found_char = False
            
            # Check if this service/char is actually present in the client services
            for service in client.services:
                for char in service.characteristics:
                    if char.uuid == CONTROL_CHAR_UUID:
                        found_char = True
                        break
                    # Fallback: look for other writable characteristics if exact match not found
                    if not found_char and ("write" in char.properties or "write-without-response" in char.properties):
                        # Use the first writable one we find as a fallback
                         # Prefer characteristics starting with 00010203
                        if str(char.uuid).startswith("00010203"):
                            target_uuid = str(char.uuid)
            
            logger.info(f"Targeting characteristic: {target_uuid}")
            
            # Try simple write
            try:
                await client.write_gatt_char(target_uuid, cmd, response=True)
                logger.info(f"Write success: {cmd.hex()}")
            except Exception as e:
                 logger.info(f"Simple write failed ({e}), trying Magic Packet...")
                 # Magic Packet for Cync/Ge
                 if action == 'on':
                    cmd = bytes.fromhex("7e0004010100ff00ef")
                 elif action == 'off':
                    cmd = bytes.fromhex("7e0004000100ff00ef")
                 
                 await client.write_gatt_char(target_uuid, cmd, response=True)
                 logger.info(f"Magic write success: {cmd.hex()}")

        except Exception as e:
            logger.error(f"Write failure: {e}")
            raise e

        return web.json_response({"success": True})
        
    except Exception as e:
        logger.error(f"Control error: {e}")
        return web.json_response({"success": False, "error": str(e)}, status=500)

app = web.Application()
app.router.add_get('/', handle_root)
app.router.add_get('/api/scan', handle_scan)
app.router.add_post('/api/connect', handle_connect)
app.router.add_post('/api/disconnect', handle_disconnect)
app.router.add_post('/api/control', handle_control)
app.router.add_static('/static/', path='./static', name='static')

if __name__ == '__main__':
    web.run_app(app, port=8080)
