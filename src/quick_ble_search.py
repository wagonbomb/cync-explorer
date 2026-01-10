#!/usr/bin/env python3
"""
Quick search for BLE provisioning code in decompiled Cync APK
Searches all smali directories for specific BLE patterns
"""
import os
import sys
from pathlib import Path
import re

# Search in both old and new decompilation locations
REPO_ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIRS = [
    REPO_ROOT / "artifacts" / "cync_smali",
    REPO_ROOT / "artifacts" / "cync_smali_full"
]

# Critical UUIDs from our BLE tests
CRITICAL_PATTERNS = {
    "Mesh Prov In (2b11)": ["2b11", "0x2b11", "2B11"],
    "Mesh Prov Out (2b12)": ["2b12", "0x2b12", "2B12"],
    "Telink Command (1912)": ["1912", "0x1912"],
    "Telink Service": ["00010203-0405-0607", "0x00010203"],
}

def find_smali_dirs(base_dir: Path):
    """Find all smali* directories"""
    smali_dirs = []
    if base_dir.exists():
        for item in os.listdir(base_dir):
            if item.startswith('smali'):
                full_path = base_dir / item
                if os.path.isdir(full_path):
                    smali_dirs.append(full_path)
    return smali_dirs

def search_pattern_in_file(filepath, patterns):
    """Search for any of the patterns in a file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for pattern in patterns:
                if pattern.lower() in content.lower():
                    return True
    except:
        pass
    return False

def search_all_smali(pattern_name, patterns):
    """Search for patterns across all smali directories"""
    print(f"\n{'='*80}")
    print(f"🔍 Searching for: {pattern_name}")
    print(f"{'='*80}")
    
    results = []
    total_searched = 0
    
    for base_dir in SEARCH_DIRS:
        if not base_dir.exists():
            continue
            
        print(f"\nSearching in: {base_dir}")
        smali_dirs = find_smali_dirs(base_dir)
        
        if not smali_dirs:
            print(f"  No smali directories found")
            continue
            
        for smali_dir in smali_dirs:
            print(f"  Scanning {os.path.basename(smali_dir)}...", end='', flush=True)
            count = 0
            matches = 0
            
            for root, dirs, files in os.walk(smali_dir):
                for filename in files:
                    if not filename.endswith('.smali'):
                        continue
                    count += 1
                    filepath = os.path.join(root, filename)
                    
                    if search_pattern_in_file(filepath, patterns):
                        rel_path = os.path.relpath(filepath, smali_dir)
                        results.append((filepath, rel_path))
                        matches += 1
            
            print(f" {count} files, {matches} matches")
            total_searched += count
    
    print(f"\n📊 Results: {len(results)} files matched (searched {total_searched} total)")
    
    if results:
        print("\nMatching files:")
        for i, (full_path, rel_path) in enumerate(results[:20], 1):
            print(f"  {i:2d}. {rel_path}")
        
        if len(results) > 20:
            print(f"  ... and {len(results) - 20} more")
    
    return results

def show_file_context(filepath, patterns):
    """Show relevant lines from a file"""
    print(f"\n{'='*80}")
    print(f"📄 File: {filepath}")
    print(f"{'='*80}")
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Show class declaration
        for i, line in enumerate(lines[:20]):
            if '.class' in line:
                print(f"\n{line.rstrip()}")
                break
        
        # Show matching lines with context
        print("\nMatching sections:")
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if any(p.lower() in line_lower for p in patterns):
                # Show 2 lines before and after
                start = max(0, i-2)
                end = min(len(lines), i+3)
                print(f"\n  Lines {start+1}-{end}:")
                for j in range(start, end):
                    marker = " ➜ " if j == i else "   "
                    print(f"{marker}{j+1:4d}: {lines[j].rstrip()}")
                    
    except Exception as e:
        print(f"Error reading file: {e}")

def main():
    print("="*80)
    print("🔬 CYNC BLE QUICK SEARCH")
    print("="*80)
    
    # Check if any search directories exist
    found_any = False
    for search_dir in SEARCH_DIRS:
        if search_dir.exists():
            smali_dirs = find_smali_dirs(search_dir)
            if smali_dirs:
                found_any = True
                print(f"✅ Found: {search_dir} ({len(smali_dirs)} smali directories)")
    
    if not found_any:
        print("\n❌ No decompiled code found!")
        print("\nPlease run: .\\scripts\\complete_decompile.ps1")
        return 1
    
    print("\nSearching for critical BLE patterns...")
    
    all_results = {}
    for pattern_name, patterns in CRITICAL_PATTERNS.items():
        results = search_all_smali(pattern_name, patterns)
        all_results[pattern_name] = results
    
    # Summary
    print(f"\n{'='*80}")
    print("📋 SUMMARY")
    print(f"{'='*80}")
    
    for pattern_name, results in all_results.items():
        status = "✅" if results else "❌"
        print(f"{status} {pattern_name}: {len(results)} files")
    
    # Interactive exploration
    if any(all_results.values()):
        print("\n" + "="*80)
        while True:
            print("\nOptions:")
            print("  1-4: Show files for each pattern")
            print("  5: View specific file")
            print("  0: Exit")
            
            choice = input("\nChoice: ").strip()
            
            if choice == '0':
                break
            elif choice in ['1', '2', '3', '4']:
                idx = int(choice) - 1
                pattern_name = list(CRITICAL_PATTERNS.keys())[idx]
                results = all_results[pattern_name]
                
                if not results:
                    print(f"No files found for {pattern_name}")
                    continue
                
                print(f"\nFiles for {pattern_name}:")
                for i, (full_path, rel_path) in enumerate(results[:10], 1):
                    print(f"  {i}. {rel_path}")
                
                file_choice = input("\nView file (1-10, or Enter to skip): ").strip()
                if file_choice.isdigit() and 1 <= int(file_choice) <= len(results):
                    filepath, _ = results[int(file_choice)-1]
                    patterns = CRITICAL_PATTERNS[pattern_name]
                    show_file_context(filepath, patterns)
            elif choice == '5':
                filepath = input("Enter file path: ").strip()
                if os.path.exists(filepath):
                    show_file_context(filepath, list(CRITICAL_PATTERNS.values())[0])
                else:
                    print(f"File not found: {filepath}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
