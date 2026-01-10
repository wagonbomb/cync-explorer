#!/usr/bin/env python3
"""
Targeted search for Cync BLE protocol in decompiled Smali code
Focuses on known working UUIDs and command sequences
"""
import os
import re
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SMALI_DIR = REPO_ROOT / "artifacts" / "cync_smali_full" / "smali"
OUTPUT_DIR = REPO_ROOT / "artifacts" / "outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Known working UUIDs from HCI analysis
TARGET_UUIDS = {
    "Mesh Provisioning In": ["2adb", "0x2adb"],
    "Mesh Proxy In": ["2add", "0x2add"],
    "Mesh Proxy Out": ["2ade", "0x2ade"],
    "Mesh Proxy Data In": ["2add"],
    "Mesh Proxy Data Out": ["2ade"],
}

# Known command sequences from working protocol
COMMAND_SEQUENCES = {
    "Handshake Start": ["000501", "00 05 01"],
    "Key Exchange": ["000001", "00 00 01", "040000"],
    "Sync Sequence": ["3100", "3101", "3102", "3103", "3104", "31 00", "31 01"],
    "Finalize": ["320119", "32 01 19"],
    "Control Prefix": ["b0c0", "b1c0", "b2c0", "c0"],
}

def search_file(filepath, patterns):
    """Search for patterns in a file, return matches with line numbers"""
    matches = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for line_num, line in enumerate(lines, 1):
                line_lower = line.lower()
                for pattern in patterns:
                    if pattern.lower() in line_lower:
                        matches.append((line_num, line.strip(), pattern))
    except:
        pass
    return matches

def search_all_files(category, patterns):
    """Search all smali files for patterns"""
    print(f"\n{'='*80}")
    print(f"🔍 Searching for: {category}")
    print(f"{'='*80}")
    print(f"Patterns: {', '.join(patterns)}")
    
    results = defaultdict(list)
    file_count = 0
    
    for root, dirs, files in os.walk(SMALI_DIR):
        for filename in files:
            if not filename.endswith('.smali'):
                continue
            
            file_count += 1
            filepath = os.path.join(root, filename)
            matches = search_file(filepath, patterns)
            
            if matches:
                rel_path = os.path.relpath(filepath, str(SMALI_DIR))
                results[rel_path] = matches
    
    print(f"\n📊 Searched {file_count} files, found {len(results)} matches")
    
    if results:
        print(f"\n📁 Files containing {category}:")
        for filepath, matches in sorted(results.items(), key=lambda x: len(x[1]), reverse=True)[:15]:
            print(f"\n  {filepath} ({len(matches)} matches)")
            for line_num, line, pattern in matches[:3]:
                print(f"    Line {line_num}: {line[:80]}")
            if len(matches) > 3:
                print(f"    ... and {len(matches) - 3} more")
    
    return results

def analyze_promising_file(filepath):
    """Deep analysis of a promising file"""
    print(f"\n{'='*80}")
    print(f"📄 ANALYZING: {filepath}")
    print(f"{'='*80}")
    
    full_path = os.path.join(SMALI_DIR, filepath)
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Get class name
        for line in lines[:20]:
            if '.class' in line:
                print(f"\n{line.strip()}")
                break
        
        # Look for method signatures
        print("\n🔧 Methods:")
        for i, line in enumerate(lines):
            if '.method' in line and not line.strip().startswith('#'):
                method_name = line.strip()
                # Check if method contains BLE operations
                method_end = i
                for j in range(i+1, min(i+50, len(lines))):
                    if '.end method' in lines[j]:
                        method_end = j
                        break
                
                method_content = ''.join(lines[i:method_end+1])
                if any(term in method_content.lower() for term in [
                    'bluetooth', 'characteristic', 'uuid', 'write', 'notification',
                    '2adb', '2add', '2ade', '000501', '3100', '320119'
                ]):
                    print(f"  {method_name}")
                    # Show relevant lines
                    for k in range(i, min(method_end+1, i+30)):
                        if any(term in lines[k].lower() for term in [
                            'const', 'invoke', 'uuid', '2adb', '2add', '000501', '3100'
                        ]):
                            print(f"    {k+1}: {lines[k].rstrip()}")
        
    except Exception as e:
        print(f"Error: {e}")

def main():
    print("="*80)
    print("🔬 CYNC PROTOCOL CONFIRMATION SEARCH")
    print("="*80)
    print(f"\nSearching in: {SMALI_DIR}")
    
    if not SMALI_DIR.exists():
        print(f"❌ Directory not found: {SMALI_DIR}")
        return 1
    
    all_results = {}
    
    # Search for UUIDs
    print("\n" + "="*80)
    print("PHASE 1: UUID SEARCH")
    print("="*80)
    
    for category, patterns in TARGET_UUIDS.items():
        results = search_all_files(category, patterns)
        if results:
            all_results[category] = results
    
    # Search for command sequences
    print("\n" + "="*80)
    print("PHASE 2: COMMAND SEQUENCE SEARCH")
    print("="*80)
    
    for category, patterns in COMMAND_SEQUENCES.items():
        results = search_all_files(category, patterns)
        if results:
            all_results[category] = results
    
    # Summary
    print("\n" + "="*80)
    print("📋 SUMMARY")
    print("="*80)
    
    for category, results in all_results.items():
        print(f"✅ {category}: {len(results)} files")
    
    # Find most promising files (files that match multiple categories)
    file_scores = defaultdict(int)
    for category, results in all_results.items():
        for filepath in results.keys():
            file_scores[filepath] += 1
    
    if file_scores:
        print("\n" + "="*80)
        print("🎯 MOST PROMISING FILES (multiple matches)")
        print("="*80)
        
        top_files = sorted(file_scores.items(), key=lambda x: x[1], reverse=True)[:5]
        for filepath, score in top_files:
            print(f"\n  {filepath} (matches {score} categories)")
            analyze_promising_file(filepath)
    
    # Save detailed results
    output_file = OUTPUT_DIR / "ble_protocol_search_results.txt"
    with output_file.open('w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("CYNC BLE PROTOCOL SEARCH RESULTS\n")
        f.write("="*80 + "\n\n")
        
        for category, results in all_results.items():
            f.write(f"\n{category}:\n")
            f.write("-" * 40 + "\n")
            for filepath, matches in results.items():
                f.write(f"\n  {filepath}:\n")
                for line_num, line, pattern in matches:
                    f.write(f"    Line {line_num}: {line}\n")
    
    print(f"\n\n💾 Detailed results saved to: {output_file}")
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
