"""
Search decompiled Smali code for BLE/Telink provisioning logic
"""
import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SMALI_DIR = REPO_ROOT / "artifacts" / "cync_smali" / "smali"
OUTPUT_FILE = REPO_ROOT / "artifacts" / "outputs" / "smali_search_results.txt"
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

# Search patterns for BLE provisioning
PATTERNS = {
    "Telink Mesh": ["telink", "mesh"],
    "BLE UUIDs": [
        "00010203-0405-0607-0809",
        "000102030405060708090a0b0c0d2b11",  # Provisioning In
        "000102030405060708090a0b0c0d2b12",  # Provisioning Out  
        "00010203-0405-0607-0809-0a0b0c0d1912",  # Telink Command
    ],
    "BLE Operations": ["BluetoothGatt", "writeCharacteristic", "setCharacteristicNotification"],
    "Provisioning": ["provision", "pair", "password", "authenticate"],
    "Device Name": ["telink_mesh1", "C by GE"],
}

def search_files(directory, max_files=10000):
    """Search Smali files for patterns"""
    results = {}
    files_searched = 0
    
    print(f"Searching in {directory}...")
    
    for root, dirs, files in os.walk(directory):
        # Skip resource directories
        if 'res' in root or 'assets' in root:
            continue
            
        for file in files:
            if not file.endswith('.smali'):
                continue
                
            filepath = os.path.join(root, file)
            files_searched += 1
            
            if files_searched % 1000 == 0:
                print(f"Searched {files_searched} files...")
            
            if files_searched > max_files:
                print(f"Reached max files limit ({max_files})")
                break
                
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for category, patterns in PATTERNS.items():
                        for pattern in patterns:
                            if pattern.lower() in content.lower():
                                if filepath not in results:
                                    results[filepath] = []
                                results[filepath].append((category, pattern))
                                
            except Exception as e:
                continue
                
    return results, files_searched

def main():
    print("="*80)
    print("SMALI CODE SEARCH FOR BLE PROVISIONING")
    print("="*80)
    
    if not SMALI_DIR.exists():
        print(f"ERROR: {SMALI_DIR} not found!")
        return
        
    results, total_searched = search_files(SMALI_DIR)
    
    print(f"\nSearched {total_searched} Smali files")
    print(f"Found matches in {len(results)} files\n")
    
    # Write results
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("SMALI SEARCH RESULTS - BLE PROVISIONING\n")
        f.write("="*80 + "\n\n")
        f.write(f"Total files searched: {total_searched}\n")
        f.write(f"Files with matches: {len(results)}\n\n")
        
        # Sort by number of matches
        sorted_results = sorted(results.items(), key=lambda x: len(x[1]), reverse=True)
        
        for filepath, matches in sorted_results[:100]:  # Top 100 files
            rel_path = str(Path(filepath).relative_to(SMALI_DIR))
            f.write(f"\n{'='*80}\n")
            f.write(f"FILE: {rel_path}\n")
            f.write(f"Matches: {len(matches)}\n")
            f.write(f"{'='*80}\n")
            
            for category, pattern in matches:
                f.write(f"  [{category}] {pattern}\n")
                
    print(f"\nResults written to: {OUTPUT_FILE}")
    print("\nTop 10 most relevant files:")
    for i, (filepath, matches) in enumerate(sorted_results[:10], 1):
        rel_path = str(Path(filepath).relative_to(SMALI_DIR))
        print(f"{i}. {rel_path} ({len(matches)} matches)")

if __name__ == "__main__":
    main()
