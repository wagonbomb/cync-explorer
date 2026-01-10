"""
Interactive BLE code explorer for Cync APK reverse engineering

This script helps find BLE provisioning code by searching for specific
patterns in the decompiled Smali code.
"""
import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SMALI_DIR = REPO_ROOT / "artifacts" / "cync_smali" / "smali"

# Specific UUIDs from our BLE tests
TELINK_SERVICE = "00010203-0405-0607-0809"
MESH_PROV_IN = "2b11"  # Data to device  
MESH_PROV_OUT = "2b12"  # Data from device
MESH_PROXY_IN = "2b10"
MESH_PROXY_OUT = "2b13"
TELINK_CMD = "1912"
TELINK_STATUS = "1914"

def search_for_uuid(uuid_part):
    """Search for files containing a specific UUID"""
    print(f"\n🔍 Searching for UUID: {uuid_part}")
    print("=" * 80)
    
    matches = []
    for root, dirs, files in os.walk(SMALI_DIR):
        for file in files:
            if not file.endswith('.smali'):
                continue
            
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if uuid_part.lower() in content.lower():
                        # Count occurrences
                        count = len(re.findall(uuid_part, content, re.IGNORECASE))
                        matches.append((filepath, count))
            except Exception as e:
                pass
    
    # Sort by number of occurrences
    matches.sort(key=lambda x: x[1], reverse=True)
    
    print(f"Found {len(matches)} files")
    for filepath, count in matches[:10]:  # Top 10
        rel_path = str(Path(filepath).relative_to(SMALI_DIR))
        print(f"  [{count:2d} matches] {rel_path}")
    
    return matches

def search_for_writecharacteristic():
    """Find files that call BluetoothGatt.writeCharacteristic"""
    print(f"\n🔍 Searching for BluetoothGatt.writeCharacteristic calls")
    print("=" * 80)
    
    matches = []
    pattern = re.compile(r'invoke-.*BluetoothGatt.*writeCharacteristic', re.IGNORECASE)
    
    for root, dirs, files in os.walk(SMALI_DIR):
        for file in files:
            if not file.endswith('.smali'):
                continue
            
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if pattern.search(content):
                        # Count occurrences
                        count = len(pattern.findall(content))
                        matches.append((filepath, count))
            except Exception as e:
                pass
    
    matches.sort(key=lambda x: x[1], reverse=True)
    
    print(f"Found {len(matches)} files")
    for filepath, count in matches[:10]:
        rel_path = str(Path(filepath).relative_to(SMALI_DIR))
        print(f"  [{count:2d} calls] {rel_path}")
    
    return matches

def analyze_file(filepath):
    """Analyze a specific Smali file for BLE operations"""
    print(f"\n📄 Analyzing: {filepath}")
    print("=" * 80)
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Find class name
        for line in lines:
            if line.startswith('.class'):
                print(f"Class: {line.strip()}")
                break
        
        # Find BLE-related methods
        print("\n🔧 BLE-related methods:")
        in_method = False
        method_name = ""
        method_lines = []
        
        for i, line in enumerate(lines):
            if line.startswith('.method'):
                in_method = True
                method_name = line.strip()
                method_lines = [line]
            elif line.startswith('.end method'):
                in_method = False
                # Check if method contains BLE code
                method_text = ''.join(method_lines)
                if any(term in method_text.lower() for term in [
                    'bluetooth', 'characteristic', 'gatt', '2b11', '2b12', 
                    '1912', 'writecharacteristic', 'setcharacteristicnotification'
                ]):
                    print(f"\n  {method_name}")
                    print(f"  Lines {i - len(method_lines) + 1} to {i + 1}")
                    # Show key operations
                    for ml in method_lines:
                        if any(term in ml.lower() for term in [
                            'invoke', 'const-string', '2b11', '2b12', 'uuid'
                        ]):
                            print(f"    {ml.rstrip()}")
                method_lines = []
            elif in_method:
                method_lines.append(line)
        
    except Exception as e:
        print(f"Error analyzing file: {e}")

def main():
    """Main interactive menu"""
    if not SMALI_DIR.exists():
        print(f"❌ Error: {SMALI_DIR} not found!")
        print("Make sure the APK has been decompiled into artifacts/")
        return
    
    print("=" * 80)
    print("🔬 CYNC BLE CODE EXPLORER")
    print("=" * 80)
    print("\nThis tool helps you find BLE provisioning code in the decompiled APK")
    print("\nAvailable searches:")
    print("  1. Search for Mesh Provisioning In UUID (2b11)")
    print("  2. Search for Mesh Provisioning Out UUID (2b12)")
    print("  3. Search for Telink Service UUID")
    print("  4. Search for Telink Command characteristic (1912)")
    print("  5. Find BluetoothGatt.writeCharacteristic calls")
    print("  6. Custom UUID search")
    print("  7. Analyze a specific file")
    print("  0. Exit")
    
    while True:
        print("\n" + "-" * 80)
        choice = input("\nEnter choice (0-7): ").strip()
        
        if choice == '0':
            print("Goodbye!")
            break
        elif choice == '1':
            matches = search_for_uuid(MESH_PROV_IN)
            if matches:
                inp = input("\nAnalyze top file? (y/n): ")
                if inp.lower() == 'y':
                    analyze_file(matches[0][0])
        elif choice == '2':
            matches = search_for_uuid(MESH_PROV_OUT)
            if matches:
                inp = input("\nAnalyze top file? (y/n): ")
                if inp.lower() == 'y':
                    analyze_file(matches[0][0])
        elif choice == '3':
            matches = search_for_uuid(TELINK_SERVICE)
            if matches:
                inp = input("\nAnalyze top file? (y/n): ")
                if inp.lower() == 'y':
                    analyze_file(matches[0][0])
        elif choice == '4':
            matches = search_for_uuid(TELINK_CMD)
            if matches:
                inp = input("\nAnalyze top file? (y/n): ")
                if inp.lower() == 'y':
                    analyze_file(matches[0][0])
        elif choice == '5':
            matches = search_for_writecharacteristic()
            if matches:
                inp = input("\nAnalyze top file? (y/n): ")
                if inp.lower() == 'y':
                    analyze_file(matches[0][0])
        elif choice == '6':
            uuid = input("Enter UUID or hex string to search: ").strip()
            matches = search_for_uuid(uuid)
            if matches:
                inp = input("\nAnalyze top file? (y/n): ")
                if inp.lower() == 'y':
                    analyze_file(matches[0][0])
        elif choice == '7':
            filepath = input("Enter file path (relative to smali/): ").strip()
            full_path = SMALI_DIR / filepath
            if full_path.exists():
                analyze_file(str(full_path))
            else:
                print(f"❌ File not found: {full_path}")

if __name__ == "__main__":
    main()
