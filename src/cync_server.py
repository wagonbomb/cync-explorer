
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
            
        client = BleakClient(mac, timeout=20.0)
        await client.connect()
        connected_clients[mac] = client
        
        client.handshake_event = asyncio.Event()
        client.handshake_data = None
        client.last_notifies = deque(maxlen=50)

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
    """Mesh Proxy 31/32 Handshake with Dual-Path Knocking."""
    try:
        data = await request.json()
        mac = data.get('mac')
        client = connected_clients.get(mac)
        if not client or not client.is_connected:
            return web.json_response({"success": False, "error": "Not connected"}, status=400)

        logger.info(f"[{mac}] Starting Mesh Handshake Protocol (Dual Path)...")
        client.handshake_event.clear()
        client.handshake_data = None
        
        # 1. Telink Login Burst (Knock on both Provisioning and Proxy)
        start_pkt = bytes.fromhex("000501000000000000000000")
        key_pkt = bytes.fromhex("00000100000000000000040000")
        
        for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
            try:
                logger.info(f"   Knocking on {uuid}...")
                await client.write_gatt_char(uuid, start_pkt, response=False)
                await asyncio.sleep(0.1)
                await client.write_gatt_char(uuid, key_pkt, response=False)
            except: pass
        
        session_id = 0
        try:
            # Wait for pattern 04 00 00 in ANY notification
            await asyncio.wait_for(client.handshake_event.wait(), timeout=4.0)
            if client.handshake_data:
                idx = client.handshake_data.find(b"\x04\x00\x00")
                if idx != -1 and len(client.handshake_data) > idx + 3:
                    session_id = client.handshake_data[idx + 3]
                    logger.info(f"   ✨ Session ID Found: {session_id:02X}")
        except:
            logger.warning("   ⏰ No ID captured, assuming 01")
            session_id = 1

        # 2. Sync Sequence (3100-3104) - Send to BOTH paths
        for i in range(5):
            pkt = bytes.fromhex(f"310{i}")
            for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
                try: await client.write_gatt_char(uuid, pkt, response=False)
                except: pass
            await asyncio.sleep(0.15)
            
        # 3. Auth Finalize (3201)
        for uuid in [MESH_PROV_IN, MESH_PROXY_IN]:
            try: await client.write_gatt_char(uuid, bytes.fromhex("320119000000"), response=False)
            except: pass
        await asyncio.sleep(0.3)

        # 4. Session Setup
        prefix_byte = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF
        cmd_prefix = bytes([prefix_byte])
        active_sessions[mac] = {
            "session_id": session_id,
            "cmd_prefix": cmd_prefix,
            "bx_counter": 0,
            "manual": False
        }
        
        logger.info(f"   🚀 Session Active: ID={session_id:02X}, Transformed ID={prefix_byte:02X}")
        return web.json_response({"success": True, "session_id": f"{session_id:02X}", "prefix": cmd_prefix.hex()})

    except Exception as e:
        logger.error(f"Handshake error: {e}")
        return web.json_response({"success": False, "error": str(e)}, status=500)

async def handle_control(request):
    """Dynamic Control using bX Prefix or Legacy 7E."""
    try:
        data = await request.json()
        mac = data.get('mac'); action = data.get('action')
        client = connected_clients.get(mac)
        if not client or not client.is_connected: return web.json_response({"success": False}, status=400)

        session = active_sessions.get(mac)
        
        # Payload: App uses long PDUs, but sometimes short ones work.
        # We'll try: [Prefix] + [Action 01/00]
        # And we'll also try a wrapped Telink command.
        
        # Strategy A: Mesh Proxy bX Prefix
        if session and not session.get('manual'):
            cnt = session.get('bx_counter', 0)
            transformed_id = session['cmd_prefix'][0]
            # Prefix is [TransformedID] [ProxyHeader_C0]
            prefix = bytes([transformed_id, 0xC0])
            
            # Action payload (0x01 on, 0x00 off)
            payload = bytes([0x01 if action == 'on' else 0x00])
            cmd = prefix + payload
            
            logger.info(f"Strategy A (bX Proxy): {cmd.hex()} via {MESH_PROXY_IN}")
            session['bx_counter'] = (cnt + 1) % 16
            try:
                await client.write_gatt_char(MESH_PROXY_IN, cmd, response=False)
                # Also try sending to PROV_IN just in case
                await client.write_gatt_char(MESH_PROV_IN, cmd, response=False)
                return web.json_response({"success": True, "message": f"Sent bX Proxy: {cmd.hex()}"})
            except: pass

        # Strategy B: Handshake Prefix (Telink) - The "Door Knock" style
        if session:
            prefix = session['cmd_prefix']
            cmd = prefix + bytes([0x01 if action == 'on' else 0x00])
            logger.info(f"Strategy B (Session CMD): {cmd.hex()} via {TELINK_CMD}")
            try:
                await client.write_gatt_char(TELINK_CMD, cmd, response=True)
                return web.json_response({"success": True, "message": f"Sent Session CMD: {cmd.hex()}"})
            except: pass

        # Strategy C: Legacy 7E (Last resort)
        legacy_cmd = bytes.fromhex("7e0004010100ff00ef" if action == 'on' else "7e0004000100ff00ef")
        logger.info(f"Strategy C (Legacy 7E): {legacy_cmd.hex()}")
        for uuid in [TELINK_CMD, MESH_PROXY_IN]:
            try:
                await client.write_gatt_char(uuid, legacy_cmd, response=False)
                return web.json_response({"success": True, "message": "Sent Legacy Command"})
            except: pass

        return web.json_response({"success": False, "error": "All strategies failed"})
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

app = web.Application()
app.router.add_get('/', handle_root); app.router.add_get('/api/scan', handle_scan)
app.router.add_post('/api/connect', handle_connect); app.router.add_post('/api/disconnect', handle_disconnect)
app.router.add_post('/api/control', handle_control); app.router.add_post('/api/handshake', handle_handshake)
app.router.add_post('/api/brute_force', handle_brute_force); app.router.add_post('/api/set_prefix', handle_set_prefix)
app.router.add_post('/api/set_session_id', handle_set_session_id)
app.router.add_post('/api/replay', handle_replay); app.router.add_get('/api/captured', handle_get_captured)
app.router.add_static('/static/', path='./static', name='static')

if __name__ == '__main__':
    web.run_app(app, port=8080)
