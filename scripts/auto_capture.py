#!/usr/bin/env python3
"""
Automated Cync Protocol Capture

This script automates all the ADB/Frida setup and captures the BLE protocol.
You just need to interact with the Cync app when prompted.
"""

import subprocess
import sys
import time
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRIDA_SERVER = os.path.join(REPO_ROOT, "tools-local", "android", "frida-server-android-x86_64")
CYNC_APK = os.path.join(REPO_ROOT, "artifacts", "com.ge.cbyge_6.20.0.54634-60b11b1f5-114634_minAPI26(arm64-v8a,armeabi-v7a)(nodpi).apk")
FRIDA_SCRIPT = os.path.join(REPO_ROOT, "scripts", "frida_simple_hook.js")
OUTPUT_FILE = os.path.join(REPO_ROOT, "artifacts", "outputs", "frida_capture.log")

def run(cmd, check=True, capture=False):
    """Run a command"""
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if check and result.returncode != 0:
        print(f"  [FAIL] Command failed")
        return None
    return result.stdout if capture else True

def check_adb():
    """Check if ADB is available and connected"""
    # Try system adb first
    result = subprocess.run("adb devices", shell=True, capture_output=True, text=True)
    if result.returncode == 0 and "device" in result.stdout:
        lines = result.stdout.strip().split('\n')
        for line in lines[1:]:  # Skip header
            if '\tdevice' in line:
                print(f"  [OK] ADB connected: {line.split()[0]}")
                return True

    # Try BlueStacks ADB
    bs_adb = r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe"
    if os.path.exists(bs_adb):
        print(f"  Using BlueStacks ADB: {bs_adb}")
        os.environ['PATH'] = os.path.dirname(bs_adb) + os.pathsep + os.environ['PATH']
        return True

    return False

def main():
    print("=" * 60)
    print("CYNC PROTOCOL AUTO-CAPTURE")
    print("=" * 60)
    print()

    # Step 1: Check ADB
    print("[1/6] Checking ADB connection...")
    if not check_adb():
        print()
        print("  ADB not connected. Trying to connect to BlueStacks...")
        run("adb connect localhost:5555", check=False)
        time.sleep(2)
        if not check_adb():
            print()
            print("  [ERROR] Cannot connect to Android device")
            print()
            print("  Make sure:")
            print("  1. BlueStacks is running")
            print("  2. ADB is enabled in BlueStacks settings")
            print("     (Settings -> Advanced -> Android Debug Bridge)")
            print()
            input("  Press Enter after enabling ADB...")
            run("adb connect localhost:5555", check=False)
            time.sleep(2)

    # Step 2: Check if Cync is installed
    print()
    print("[2/6] Checking Cync app...")
    result = subprocess.run("adb shell pm list packages | grep cbyge",
                          shell=True, capture_output=True, text=True)
    if "cbyge" not in result.stdout:
        print("  Cync not installed. Installing...")
        if os.path.exists(CYNC_APK):
            run(f'adb install "{CYNC_APK}"')
        else:
            print(f"  [ERROR] APK not found: {CYNC_APK}")
            return
    else:
        print("  [OK] Cync already installed")

    # Step 3: Push Frida server
    print()
    print("[3/6] Setting up Frida server...")
    if os.path.exists(FRIDA_SERVER):
        run(f'adb push "{FRIDA_SERVER}" /data/local/tmp/frida-server')
        run("adb shell chmod 755 /data/local/tmp/frida-server")
    else:
        print(f"  [ERROR] Frida server not found: {FRIDA_SERVER}")
        return

    # Step 4: Start Frida server
    print()
    print("[4/6] Starting Frida server...")
    # Kill any existing
    run("adb shell pkill -f frida-server", check=False)
    time.sleep(1)
    # Start in background
    subprocess.Popen("adb shell /data/local/tmp/frida-server &",
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    print("  [OK] Frida server started")

    # Step 5: Instructions
    print()
    print("[5/6] Ready to capture!")
    print("=" * 60)
    print()
    print("  I will now start Frida and capture all BLE traffic.")
    print()
    print("  When you see 'BLE hooks installed', do this in the app:")
    print("  1. Open Cync app")
    print("  2. Tap '+' to add a device")
    print("  3. Select your light type")
    print("  4. Follow pairing instructions")
    print()
    print(f"  Output will be saved to: {OUTPUT_FILE}")
    print()
    input("  Press Enter to start capture...")

    # Step 6: Run Frida
    print()
    print("[6/6] Starting Frida capture...")
    print("=" * 60)
    print()

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # Run frida with output to both console and file
    cmd = f'frida -U -f com.ge.cbyge -l "{FRIDA_SCRIPT}" --no-pause'
    print(f"  $ {cmd}")
    print()
    print("  [Ctrl+C to stop capture]")
    print()

    try:
        with open(OUTPUT_FILE, 'w') as f:
            process = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in process.stdout:
                print(line, end='')
                f.write(line)
                f.flush()
    except KeyboardInterrupt:
        print()
        print()
        print("=" * 60)
        print("CAPTURE COMPLETE")
        print("=" * 60)
        print(f"Output saved to: {OUTPUT_FILE}")
        print()

if __name__ == "__main__":
    main()
