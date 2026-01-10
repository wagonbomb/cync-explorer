"""
Extract and search for relevant strings/code from Cync APK
Bypasses decompilation by directly searching APK contents
"""
import zipfile
import re
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APK_PATH = REPO_ROOT / "artifacts" / "com.ge.cbyge_6.20.0.54634-60b11b1f5-114634_minAPI26(arm64-v8a,armeabi-v7a)(nodpi).apk"
OUTPUT_FILE = REPO_ROOT / "artifacts" / "outputs" / "apk_strings_analysis.txt"
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

print(f"Analyzing {APK_PATH}...")

# Search patterns
PATTERNS = {
    "BLE UUIDs": [
        b"00010203-0405-0607-0809",  # Telink service UUID
        b"000102030405060708090a0b0c0d2b11",  # Provisioning In
        b"000102030405060708090a0b0c0d2b12",  # Provisioning Out
        b"000102030405060708090a0b0c0d2b10",  # Proxy Data In
        b"000102030405060708090a0b0c0d2b13",  # Proxy Data Out
        b"00010203-0405-0607-0809-0a0b0c0d2b11",  # With dashes
        b"00010203-0405-0607-0809-0a0b0c0d2b12",
        b"00010203-0405-0607-0809-0a0b0c0d2b10",
        b"00010203-0405-0607-0809-0a0b0c0d2b13",
    ],
    "Device Names": [
        b"telink_mesh1",
        b"telink_mesh",
        b"C by GE",
        b"cync",
        b"CYNC",
    ],
    "Passwords": [
        b"123",
        b"password",
        b"pair",
        b"provision",
    ],
    "Commands": [
        b"0x0c",
        b"\\x0c",
        b"command",
        b"control",
        b"brightness",
        b"power",
        b"on_off",
    ],
    "Encryption": [
        b"encrypt",
        b"decrypt",
        b"AES",
        b"key",
        b"session",
    ],
}

results = {}

try:
    with zipfile.ZipFile(APK_PATH, 'r') as apk:
        print(f"\nAPK contains {len(apk.namelist())} files")
       
        # Focus on DEX files and resources
        interesting_files = [
            f for f in apk.namelist()
            if f.endswith('.dex') or 
               f.endswith('.xml') or
               'resources' in f.lower() or
               'strings' in f.lower()
        ]
        
        print(f"Analyzing {len(interesting_files)} interesting files...")
       
        for filename in interesting_files:
            print(f"\nScanning: {filename}")
            try:
                content = apk.read(filename)
                file_results = []
               
                for category, patterns in PATTERNS.items():
                    for pattern in patterns:
                        if pattern in content:
                            # Find context around match
                            idx = content.find(pattern)
                            start = max(0, idx - 100)
                            end = min(len(content), idx + len(pattern) + 100)
                            context = content[start:end]
                           
                            # Try to decode as UTF-8, fallback to repr
                            try:
                                context_str = context.decode('utf-8', errors='ignore')
                            except:
                                context_str = repr(context)
                           
                            file_results.append({
                                'category': category,
                                'pattern': pattern.decode('utf-8', errors='ignore'),
                                'position': idx,
                                'context': context_str
                            })
                           
                if file_results:
                    results[filename] = file_results
                   
            except Exception as e:
                print(f"  Error reading {filename}: {e}")
       
    # Write results
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("CYNC APK STRING ANALYSIS\n")
        f.write("="*80 + "\n\n")
       
        for filename, matches in results.items():
            f.write(f"\n{'='*80}\n")
            f.write(f"FILE: {filename}\n")
            f.write(f"{'='*80}\n")
           
            for match in matches:
                f.write(f"\nCategory: {match['category']}\n")
                f.write(f"Pattern: {match['pattern']}\n")
                f.write(f"Position: {match['position']}\n")
                f.write(f"Context:\n{match['context']}\n")
                f.write("-"*80 + "\n")
   
    print(f"\n\n{'='*80}")
    print(f"ANALYSIS COMPLETE!")
    print(f"{'='*80}")
    print(f"Found matches in {len(results)} files")
    print(f"Results saved to: {OUTPUT_FILE}")
    print("\nFiles with matches:")
    for filename in results.keys():
        print(f"  - {filename}")
   
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
