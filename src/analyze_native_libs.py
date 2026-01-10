#!/usr/bin/env python3
"""
Quick native library analysis for Cync BLE
Uses objdump and strings instead of Ghidra for immediate analysis
"""

import subprocess
import re
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LIB_DIR = REPO_ROOT / "artifacts" / "ghidra_analysis" / "libraries"

def analyze_with_strings(lib_path):
    """Extract and search strings from library"""
    print(f"\n{'='*80}")
    print(f"STRINGS ANALYSIS: {os.path.basename(lib_path)}")
    print(f"{'='*80}")
    
    try:
        result = subprocess.run(
            ['strings', lib_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        strings_list = result.stdout.split('\n')
        
        # BLE-related patterns
        ble_patterns = {
            "UUIDs": re.compile(r'(2adb|2add|2ade|00002adb|00002add|00002ade)', re.IGNORECASE),
            "Commands": re.compile(r'(000501|3100|3101|3102|3103|3104|320119)'),
            "BLE Keywords": re.compile(r'(bluetooth|gatt|characteristic|mesh|provision|proxy)', re.IGNORECASE),
            "Crypto": re.compile(r'(aes|encrypt|decrypt|key|auth)', re.IGNORECASE),
        }
        
        findings = {category: [] for category in ble_patterns.keys()}
        
        for string in strings_list:
            if len(string) < 4:  # Skip very short strings
                continue
            
            for category, pattern in ble_patterns.items():
                if pattern.search(string):
                    findings[category].append(string)
        
        # Print findings
        for category, matches in findings.items():
            if matches:
                print(f"\n{category}:")
                for match in sorted(set(matches))[:20]:  # Top 20 unique
                    print(f"  {match}")
        
        # Look for function names
        print(f"\nPotential Function Names:")
        func_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]{3,}$')
        functions = [s for s in strings_list if func_pattern.match(s) and 'write' in s.lower() or 'send' in s.lower() or 'gatt' in s.lower()]
        for func in sorted(set(functions))[:15]:
            print(f"  {func}")
                
    except subprocess.TimeoutExpired:
        print("  Timeout - library too large")
    except Exception as e:
        print(f"  Error: {e}")

def analyze_with_objdump(lib_path):
    """Disassemble and find interesting functions"""
    print(f"\n{'='*80}")
    print(f"OBJDUMP ANALYSIS: {os.path.basename(lib_path)}")
    print(f"{'='*80}")
    
    # Check if objdump/readelf is available
    try:
        # Try to find exported symbols
        result = subprocess.run(
            ['readelf', '-s', lib_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            
            print("\nExported Functions:")
            func_count = 0
            for line in lines:
                if 'FUNC' in line and 'GLOBAL' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        func_name = parts[-1]
                        if any(keyword in func_name.lower() for keyword in ['write', 'send', 'gatt', 'char', 'ble', 'mesh', 'init']):
                            print(f"  {func_name}")
                            func_count += 1
                            if func_count >= 20:
                                break
        else:
            print("  readelf not available")
            
    except FileNotFoundError:
        print("  readelf not found - install with: sudo apt install binutils")
    except Exception as e:
        print(f"  Error: {e}")

def quick_analysis():
    """Quick analysis of all extracted libraries"""
    print("="*80)
    print("CYNC BLE NATIVE LIBRARY QUICK ANALYSIS")
    print("="*80)
    print("\nThis uses 'strings' and 'readelf' for immediate analysis")
    print("For full analysis, install Ghidra and run scripts/setup_ghidra_analysis.sh")
    
    libs = [
        "libBleLib.so",
        "libCHIPController.so",
        "libSetupPayloadParser.so"
    ]
    
    for lib in libs:
        lib_path = LIB_DIR / lib
        if lib_path.exists():
            size = lib_path.stat().st_size
            print(f"\n\n{'#'*80}")
            print(f"# {lib} ({size:,} bytes)")
            print(f"{'#'*80}")
            
            analyze_with_strings(str(lib_path))
            
            if size < 1_000_000:  # Only do objdump on smaller files
                analyze_with_objdump(str(lib_path))
            else:
                print(f"\n(Skipping objdump - file too large)")
        else:
            print(f"\n❌ Not found: {lib_path}")
    
    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print("\nKey findings to look for:")
    print("  - UUID strings (2adb, 2add, 2ade)")
    print("  - Command sequences (000501, 3100, 320119)")
    print("  - Function names containing: write, send, gatt, characteristic")
    print("  - Mesh/provisioning keywords")
    print("\nIf this analysis finds interesting strings, we can:")
    print("  1. Use Ghidra for full reverse engineering")
    print("  2. Search for those strings in the Smali code")
    print("  3. Hook these functions at runtime with Frida")
    print("")

if __name__ == "__main__":
    quick_analysis()
