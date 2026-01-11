
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from collections import deque

from aiohttp import web
from bleak import BleakScanner, BleakClient

# Add local path to imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from ble_scanner import enhanced_scan, format_mac, normalize_mac
from known_devices import KNOWN_CYNC_MACS

# Import protocol modules
from protocol.mesh_protocol import MeshProtocol
from protocol.command_builder import CommandBuilder, DataPointID
from protocol.klv_encoder import DataType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cync_server")

# Global state
connected_clients = {}
# mac -> {session_id: int, cmd_prefix: bytes, manual: bool, bx_counter: int}
active_sessions = {} 

# UUIDs
MESH_PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
MESH_PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
MESH_PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
MESH_PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"
TELINK_CMD = "00010203-0405-0607-0809-0a0b0c0d1912"
TELINK_STATUS = "00010203-0405-0607-0809-0a0b0c0d1911"

async def handle_root(request):
    """Serve the main HTML page."""
    return web.FileResponse('./static/index.html')

async def handle_scan(request):
    """Run BLE scan and return results."""
    logger.info("Starting BLE scan request...")
    scan_results = await enhanced_scan(timeout=10.0, connect_to_ge=False)
    processed_devices = []
    
    for address, device, adv_data in scan_results.get("ge_devices", []):
        scan_mac = normalize_mac(address)
        alias_of = None
        try:
            mac_int = int(scan_mac, 16)
            plus_1 = f"{mac_int + 1:012X}"
            minus_1 = f"{mac_int - 1:012X}"
            if plus_1 in KNOWN_CYNC_MACS: alias_of = format_mac(plus_1)
            elif minus_1 in KNOWN_CYNC_MACS: alias_of = format_mac(minus_1)
            elif scan_mac in KNOWN_CYNC_MACS: alias_of = "Exact Match"
        except: pass

        processed_devices.append({
            "address": address, "name": device.name, "rssi": adv_data.rssi,
            "advertisement": {"local_name": adv_data.local_name, "rssi": adv_data.rssi},
            "alias_of": alias_of
        })
    
    processed_devices.sort(key=lambda x: x['rssi'], reverse=True)
    return web.json_response({"devices": processed_devices})

async def handle_connect(request):
    """Connect and enable all notifications."""
    try:
        data = await request.json()
        mac = data.get('mac')
        if not mac: return web.json_response({"success": False}, status=400)
        
        client = connected_clients.get(mac)
        if client and client.is_connected:
            return web.json_response({"success": True, "message": "Already connected", "initial_state": False})
            
        # Create disconnection callback to monitor connection status
        def disconnection_callback(client_obj):
            logger.warning(f"[{mac}] !!! DEVICE DISCONNECTED !!!")
            logger.warning(f"   Connection lost at: {asyncio.get_event_loop().time()}")

        client = BleakClient(mac, timeout=20.0, disconnected_callback=disconnection_callback)
        await client.connect()
        connected_clients[mac] = client

        client.handshake_event = asyncio.Event()
        client.handshake_data = None
        client.last_notifies = deque(maxlen=50)
        client.connect_time = asyncio.get_event_loop().time()
        logger.info(f"[{mac}] Connected at: {client.connect_time}")

        def notification_handler(sender, data):
             client.last_notifies.append((sender, data))
             logger.info(f"   [NOTIFY] {sender}: {data.hex()}")
             if b"\x04\x00\x00" in data:
                 client.handshake_data = data
                 client.handshake_event.set()

        # Enable all notify chars
        for service in client.services:
            for char in service.characteristics:
                if "notify" in char.properties:
                    try: 
                        await client.start_notify(char, notification_handler)
                        logger.info(f"   Listening on {char.uuid}")
                    except: pass
        
        return web.json_response({"success": True})
    except Exception as e:
        logger.error(f"Connect error: {e}")
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_handshake(request):
    """Mesh Handshake Protocol using protocol modules."""
    try:
        data = await request.json()
        mac = data.get('mac')
        client = connected_clients.get(mac)
        if not client or not client.is_connected:
            return web.json_response({"success": False, "error": "Not connected"}, status=400)

        logger.info(f"[{mac}] Starting Mesh Handshake Protocol...")
        client.handshake_event.clear()
        client.handshake_data = None

        # 1. Send Handshake Start packet (dual-path)
        start_pkt = MeshProtocol.create_handshake_start()
        logger.info(f"   Step 1: Handshake Start -> {start_pkt.hex()}")

        for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
            try:
                await client.write_gatt_char(uuid, start_pkt, response=False)
            except Exception as e:
                logger.warning(f"   Failed to send start to {uuid}: {e}")

        await asyncio.sleep(0.2)  # Wait for device to process

        # 2. Send Key Exchange packet (dual-path)
        key_pkt = MeshProtocol.create_key_exchange()
        logger.info(f"   Step 2: Key Exchange -> {key_pkt.hex()}")

        for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
            try:
                await client.write_gatt_char(uuid, key_pkt, response=False)
            except Exception as e:
                logger.warning(f"   Failed to send key exchange to {uuid}: {e}")

        # 3. Wait for Session ID response
        session_id = None
        try:
            logger.info("   Step 3: Waiting for Session ID response...")
            await asyncio.wait_for(client.handshake_event.wait(), timeout=5.0)

            if client.handshake_data:
                logger.info(f"   Received data: {client.handshake_data.hex()}")
                session_id = MeshProtocol.parse_session_response(client.handshake_data)

                if session_id is not None:
                    logger.info(f"   ✅ Session ID Found: 0x{session_id:02X}")
                else:
                    logger.warning("   Could not parse session ID from response")
        except asyncio.TimeoutError:
            logger.warning("   ⏰ Timeout waiting for session ID")
        except Exception as e:
            logger.error(f"   Error waiting for session ID: {e}")

        # Use default if we didn't get one
        if session_id is None:
            session_id = 0x01
            logger.info(f"   Using default session ID: 0x{session_id:02X}")

        # 4. Send Sync Sequence (31 00 through 31 04) - ONLY to MESH_PROXY_IN
        logger.info("   Step 4: Sending Sync Sequence...")
        for i in range(5):
            sync_pkt = MeshProtocol.create_sync_packet(i)
            logger.info(f"   Sync {i}: {sync_pkt.hex()}")

            # Per protocol spec: sync packets ONLY to 2add (MESH_PROXY_IN)
            try:
                await client.write_gatt_char(MESH_PROXY_IN, sync_pkt, response=False)
            except Exception as e:
                logger.warning(f"   Failed to send sync {i}: {e}")

            await asyncio.sleep(0.1)

        # 5. Send Auth Finalize - ONLY to MESH_PROXY_IN
        finalize_pkt = MeshProtocol.create_auth_finalize()
        logger.info(f"   Step 5: Auth Finalize -> {finalize_pkt.hex()}")

        # Per protocol spec: auth finalize ONLY to 2add (MESH_PROXY_IN)
        try:
            await client.write_gatt_char(MESH_PROXY_IN, finalize_pkt, response=False)
        except Exception as e:
            logger.warning(f"   Failed to send auth finalize: {e}")

        await asyncio.sleep(0.3)

        # 6. Calculate prefix and store session
        prefix_byte = MeshProtocol.calculate_prefix(session_id)

        active_sessions[mac] = {
            "session_id": session_id,
            "cmd_prefix": bytes([prefix_byte]),
            "bx_counter": 0,
            "manual": False
        }

        logger.info(f"   🚀 Handshake Complete!")
        logger.info(f"      Session ID: 0x{session_id:02X}")
        logger.info(f"      Prefix: 0x{prefix_byte:02X}")

        # 7. Send immediate test command to keep connection alive
        try:
            logger.info("   Step 6: Verifying connection with test command...")
            # Send a state query or power status command
            test_cmd = CommandBuilder.build_power_command(True, prefix=prefix_byte)
            await client.write_gatt_char(MESH_PROXY_IN, test_cmd, response=False)
            await asyncio.sleep(0.1)
            logger.info(f"   ✅ Connection verified - sent test command: {test_cmd.hex()}")
        except Exception as e:
            logger.warning(f"   ⚠️ Connection test failed: {e}")
            # Continue anyway - session is established

        return web.json_response({
            "success": True,
            "session_id": f"{session_id:02X}",
            "prefix": f"{prefix_byte:02X}"
        })

    except Exception as e:
        logger.error(f"Handshake error: {e}", exc_info=True)
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_control(request):
    """Power control using protocol modules."""
    try:
        data = await request.json()
        mac = data.get('mac')
        action = data.get('action')

        if not mac:
            return web.json_response({"success": False, "error": "Missing mac parameter"}, status=400)

        if not action:
            return web.json_response({"success": False, "error": "Missing action parameter (on/off)"}, status=400)

        client = connected_clients.get(mac)
        if not client or not client.is_connected:
            return web.json_response({"success": False, "error": "Not connected"}, status=400)

        session = active_sessions.get(mac)

        # Build power command using protocol module
        on = (action.lower() == 'on')

        if session:
            prefix = session['cmd_prefix'][0]
            cmd = CommandBuilder.build_power_command(on, prefix=prefix)
            logger.info(f"[{mac}] Power {action} (with prefix 0x{prefix:02X}): {cmd.hex()}")
        else:
            cmd = CommandBuilder.build_power_command(on)
            logger.info(f"[{mac}] Power {action} (no session): {cmd.hex()}")

        # Send command via multiple paths for reliability
        try:
            await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
            await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)

            return web.json_response({
                "success": True,
                "message": f"Power {action}",
                "command": cmd.hex()
            })
        except Exception as e:
            logger.error(f"Failed to send command: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)
    except Exception as e:
        logger.error(f"Control error: {e}")
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_brute_force(request):
    """Brute force prefixes (00-FF) on both Telink and Proxy paths."""
    try:
        data = await request.json()
        mac = data.get('mac'); client = connected_clients.get(mac)
        if not client: return web.json_response({"success": False}, status=400)
        
        logger.info(f"[{mac}] Starting BRUTE FORCE SWEEP (Proxy + Telink)...")
        for p in range(256):
            cmd = bytes([p, 0x00]) # Prefix + OFF
            try: 
                await client.write_gatt_char(TELINK_CMD, cmd, response=False)
                await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
                await asyncio.sleep(0.1)
            except: pass
        return web.json_response({"success": True})
    except: return web.json_response({"success": False}, status=500)

async def handle_set_session_id(request):
    """Bypass capture by manually setting the session ID."""
    try:
        data = await request.json()
        mac = data.get('mac')
        sid_hex = data.get('session_id')
        if not mac or not sid_hex: return web.json_response({"success": False}, status=400)
        
        sid = int(sid_hex, 16)
        prefix_byte = (((sid & 0x0F) + 0x0A) << 4) & 0xFF
        active_sessions[mac] = {
            "session_id": sid,
            "cmd_prefix": bytes([prefix_byte]),
            "bx_counter": 0,
            "manual": True
        }
        logger.info(f"[{mac}] Manual SID set: {sid:02X} (Transformed: {prefix_byte:02X})")
        return web.json_response({"success": True})
    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_set_prefix(request):
    try:
        data = await request.json()
        mac = data.get('mac'); prefix = data.get('prefix')
        active_sessions[mac] = {"session_id": 0, "cmd_prefix": bytes.fromhex(prefix), "manual": True}
        return web.json_response({"success": True})
    except: return web.json_response({"success": False}, status=500)

async def handle_disconnect(request):
    try:
        data = await request.json()
        mac = data.get('mac'); client = connected_clients.get(mac)
        if client: await client.disconnect(); del connected_clients[mac]
        return web.json_response({"success": True})
    except: return web.json_response({"success": False}, status=500)

async def handle_replay(request):
    try:
        data = await request.json()
        mac = data.get('mac'); hex_data = data.get('data'); uuid = data.get('uuid')
        client = connected_clients.get(mac)
        if client: await client.write_gatt_char(uuid, bytes.fromhex(hex_data), response=False)
        return web.json_response({"success": True})
    except: return web.json_response({"success": False}, status=500)

async def handle_get_captured(request):
    return web.json_response({"packets": [
        {"name": "Magic ON (7E)", "data": "7e0004010100ff00ef", "uuid": TELINK_CMD},
        {"name": "Magic OFF (7E)", "data": "7e0004000100ff00ef", "uuid": TELINK_CMD}
    ]})

async def handle_brightness(request):
    """Set brightness level (0-100%)."""
    try:
        data = await request.json()
        mac = data.get('mac')
        level = data.get('level')  # 0-100

        if not mac or level is None:
            return web.json_response({"success": False, "error": "Missing mac or level"}, status=400)

        if not 0 <= level <= 100:
            return web.json_response({"success": False, "error": "Level must be 0-100"}, status=400)

        client = connected_clients.get(mac)
        if not client or not client.is_connected:
            return web.json_response({"success": False, "error": "Not connected"}, status=400)

        session = active_sessions.get(mac)

        # Build brightness command using protocol module
        if session:
            prefix = session['cmd_prefix'][0]
            cmd = CommandBuilder.build_brightness_percent_command(level, prefix=prefix)
        else:
            # No session, try without prefix
            cmd = CommandBuilder.build_brightness_percent_command(level)

        logger.info(f"[{mac}] Brightness {level}%: {cmd.hex()}")

        # Try sending via multiple paths
        try:
            await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
            await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
            return web.json_response({"success": True, "message": f"Set brightness to {level}%", "command": cmd.hex()})
        except Exception as e:
            logger.error(f"Brightness command error: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    except Exception as e:
        logger.error(f"Brightness handler error: {e}")
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_color_temp(request):
    """Set color temperature (2700-6500K)."""
    try:
        data = await request.json()
        mac = data.get('mac')
        kelvin = data.get('kelvin')

        if not mac or kelvin is None:
            return web.json_response({"success": False, "error": "Missing mac or kelvin"}, status=400)

        if not 2700 <= kelvin <= 6500:
            return web.json_response({"success": False, "error": "Kelvin must be 2700-6500"}, status=400)

        client = connected_clients.get(mac)
        if not client or not client.is_connected:
            return web.json_response({"success": False, "error": "Not connected"}, status=400)

        session = active_sessions.get(mac)

        # Build color temp command using protocol module
        if session:
            prefix = session['cmd_prefix'][0]
            cmd = CommandBuilder.build_color_temp_command(kelvin, prefix=prefix)
        else:
            cmd = CommandBuilder.build_color_temp_command(kelvin)

        logger.info(f"[{mac}] Color temp {kelvin}K: {cmd.hex()}")

        # Try sending via multiple paths
        try:
            await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
            await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
            return web.json_response({"success": True, "message": f"Set color temp to {kelvin}K", "command": cmd.hex()})
        except Exception as e:
            logger.error(f"Color temp command error: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    except Exception as e:
        logger.error(f"Color temp handler error: {e}")
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_power_protocol(request):
    """Power control using protocol modules (explicit API for testing)."""
    try:
        data = await request.json()
        mac = data.get('mac')
        action = data.get('action')  # 'on' or 'off'

        if not mac or not action:
            return web.json_response({"success": False, "error": "Missing mac or action"}, status=400)

        client = connected_clients.get(mac)
        if not client or not client.is_connected:
            return web.json_response({"success": False, "error": "Not connected"}, status=400)

        session = active_sessions.get(mac)

        # Build power command using protocol module
        on = (action == 'on')
        if session:
            prefix = session['cmd_prefix'][0]
            cmd = CommandBuilder.build_power_command(on, prefix=prefix)
        else:
            cmd = CommandBuilder.build_power_command(on)

        logger.info(f"[{mac}] Power {action} (Protocol): {cmd.hex()}")

        # Try sending via multiple paths
        try:
            await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
            await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
            return web.json_response({"success": True, "message": f"Power {action}", "command": cmd.hex()})
        except Exception as e:
            logger.error(f"Power command error: {e}")
            return web.json_response({"success": False, "error": str(e)}, status=500)

    except Exception as e:
        logger.error(f"Power protocol handler error: {e}")
        return web.json_response({"success": False, "error": str(e)}, status=500)

app = web.Application()
app.router.add_get('/', handle_root); app.router.add_get('/api/scan', handle_scan)
app.router.add_post('/api/connect', handle_connect); app.router.add_post('/api/disconnect', handle_disconnect)
app.router.add_post('/api/control', handle_control); app.router.add_post('/api/handshake', handle_handshake)
app.router.add_post('/api/brute_force', handle_brute_force); app.router.add_post('/api/set_prefix', handle_set_prefix)
app.router.add_post('/api/set_session_id', handle_set_session_id)
app.router.add_post('/api/replay', handle_replay); app.router.add_get('/api/captured', handle_get_captured)
# New protocol-based endpoints
app.router.add_post('/api/brightness', handle_brightness)
app.router.add_post('/api/color_temp', handle_color_temp)
app.router.add_post('/api/power_protocol', handle_power_protocol)
app.router.add_static('/static/', path='./static', name='static')

if __name__ == '__main__':
    web.run_app(app, port=8081)
