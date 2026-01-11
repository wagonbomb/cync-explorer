#!/usr/bin/env python3
"""
Automated test script to turn OFF the light at MAC: 34:13:43:46:CA:84
Tests multiple command methods and logs all results.
"""

import requests
import time
import json

# Configuration
BASE_URL = "http://localhost:8081"
MAC_ADDRESS = "34:13:43:46:CA:84"  # Your test device

def log(message, level="INFO"):
    """Print formatted log message"""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def test_api_call(name, method, endpoint, data=None):
    """Make API call and return result"""
    url = f"{BASE_URL}{endpoint}"
    log(f"Testing: {name}")
    log(f"  > {method} {endpoint}")
    if data:
        log(f"  > Data: {json.dumps(data)}")

    try:
        if method == "GET":
            response = requests.get(url, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=10)

        log(f"  < Status: {response.status_code}")

        try:
            result = response.json()
            log(f"  < Response: {json.dumps(result, indent=2)}")
            return response.status_code, result
        except:
            log(f"  < Response: {response.text[:200]}")
            return response.status_code, response.text

    except Exception as e:
        log(f"  X ERROR: {e}", "ERROR")
        return None, str(e)

def main():
    print("=" * 80)
    print("GE Cync Light Control - Automated OFF Test")
    print("=" * 80)
    print(f"Target Device: {MAC_ADDRESS}")
    print(f"Server: {BASE_URL}")
    print("=" * 80)
    print()

    # Test 1: Check server is running
    log("Step 1: Verify server is running")
    status, result = test_api_call("Server Status", "GET", "/")
    if status != 200:
        log("Server not responding! Exiting.", "ERROR")
        return
    log("OK Server is running\n")
    time.sleep(1)

    # Test 2: Connect to device
    log("Step 2: Connect to device")
    status, result = test_api_call(
        "Connect",
        "POST",
        "/api/connect",
        {"mac": MAC_ADDRESS}
    )

    if status == 200 and result.get("success"):
        log("OK Connected to device\n")
    else:
        log("FAIL Connection failed", "ERROR")
        log("Trying to continue anyway...\n")

    time.sleep(2)

    # Test 3: Perform handshake
    log("Step 3: Perform handshake")
    status, result = test_api_call(
        "Handshake",
        "POST",
        "/api/handshake",
        {"mac": MAC_ADDRESS}
    )

    session_id = None
    prefix = None

    if status == 200 and result.get("success"):
        session_id = result.get("session_id")
        prefix = result.get("prefix")
        log(f"OK Handshake complete! Session ID: {session_id}, Prefix: {prefix}\n")
    else:
        log("FAIL Handshake failed", "WARN")
        log("Will try commands without session...\n")

    time.sleep(2)

    # Test 4: Try turning OFF using original control endpoint
    log("Step 4: Turn OFF using /api/control (original)")
    status, result = test_api_call(
        "Control OFF",
        "POST",
        "/api/control",
        {"mac": MAC_ADDRESS, "action": "off"}
    )

    if status == 200 and result.get("success"):
        log("OK SUCCESS! Light should be OFF via control endpoint\n")
    else:
        log("FAIL Control endpoint failed\n")

    time.sleep(2)

    # Test 5: Try using protocol-based power endpoint
    log("Step 5: Turn OFF using /api/power_protocol (new)")
    status, result = test_api_call(
        "Power Protocol OFF",
        "POST",
        "/api/power_protocol",
        {"mac": MAC_ADDRESS, "action": "off"}
    )

    if status == 200 and result.get("success"):
        log("OK SUCCESS! Light should be OFF via power_protocol\n")
        if result.get("command"):
            log(f"  Command sent: {result['command']}")
    else:
        log("FAIL Power protocol endpoint failed\n")

    time.sleep(2)

    # Test 6: Try brightness at 0%
    log("Step 6: Set brightness to 0% (alternative OFF)")
    status, result = test_api_call(
        "Brightness 0%",
        "POST",
        "/api/brightness",
        {"mac": MAC_ADDRESS, "level": 0}
    )

    if status == 200 and result.get("success"):
        log("OK SUCCESS! Set brightness to 0%\n")
        if result.get("command"):
            log(f"  Command sent: {result['command']}")
    else:
        log("FAIL Brightness endpoint failed\n")

    time.sleep(2)

    # Test 7: Manual session ID if handshake failed
    if not session_id:
        log("Step 7: Try with manual session ID (0x05)")
        status, result = test_api_call(
            "Set Manual Session ID",
            "POST",
            "/api/set_session_id",
            {"mac": MAC_ADDRESS, "session_id": "05"}
        )

        if status == 200:
            log("OK Manual session ID set\n")
            time.sleep(1)

            # Retry control with manual session
            log("Step 7b: Retry control with manual session")
            status, result = test_api_call(
                "Control OFF (with manual session)",
                "POST",
                "/api/control",
                {"mac": MAC_ADDRESS, "action": "off"}
            )

            if status == 200 and result.get("success"):
                log("OK SUCCESS with manual session!\n")
            else:
                log("FAIL Still failed with manual session\n")

    # Summary
    print()
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print("Check your light - it should be OFF if any test succeeded.")
    print("Review the logs above to see which method worked.")
    print()
    print("Successful methods can be used for future control.")
    print("=" * 80)

if __name__ == "__main__":
    main()
