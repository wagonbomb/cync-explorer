"""
Search decompiled Cync APK for BLE provisioning code.
Run this after decompiling APK with jadx.

Usage:
    python src/apk_search.py C:/Path/To/cync_decompiled
"""

import os
import sys
import re
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "artifacts" / "outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Key search patterns
SEARCH_PATTERNS = {
    "Telink References": [
        r"telink_mesh",
        r"00010203-0405-0607-0809",
        r"Telink",
    ],
    "Provisioning": [
        r"provision",
        r"\bpair\b",
        r"0x0[cC]",  # Pair command byte
    ],
    "Mesh Password": [
        r'password\s*=\s*"([^"]+)"',
        r'MESH_PASS',
        r'mesh.*password',
        r'"123"',
        r'0x313233',  # "123" in hex
    ],
    "BLE Commands": [
        r"writeCharacteristic",
        r"onCharacteristicWrite",
        r"GATT",
    ],
    "Encryption": [
        r"encrypt",
        r"decrypt", 
        r"AES",
        r"\bkey\b",
        r"crypto",
    ],
    "BLE UUIDs": [
        r"00002adb.*Provisioning",
        r"00002add.*Proxy",
        r"00010203-0405-0607",
    ],
}

class APKSearcher:
    def __init__(self, decompiled_path):
        self.decompiled_path = Path(decompiled_path)
        self.results = defaultdict(list)
        
    def search_file(self, file_path, pattern, pattern_name):
        """Search a single file for pattern"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Get context (3 lines before and after)
                lines = content[:match.start()].split('\n')
                line_num = len(lines)
                
                context_start = max(0, line_num - 3)
                context_end = min(len(content.split('\n')), line_num + 4)
                context_lines = content.split('\n')[context_start:context_end]
                
                rel_path = file_path.relative_to(self.decompiled_path)
                
                self.results[pattern_name].append({
                    'file': str(rel_path),
                    'line': line_num,
                    'match': match.group(0),
                    'context': '\n'.join(context_lines)
                })
        except Exception as e:
            pass  # Skip files we can't read
    
    def search_all(self):
        """Search all Java files"""
        print(f"Searching {self.decompiled_path}...")
        print("="*80)
        
        java_files = list(self.decompiled_path.rglob("*.java"))
        print(f"Found {len(java_files)} Java files\n")
        
        for category, patterns in SEARCH_PATTERNS.items():
            print(f"\nSearching for: {category}")
            print("-"*80)
            
            for pattern in patterns:
                for java_file in java_files:
                    self.search_file(java_file, pattern, category)
            
            if self.results[category]:
                print(f"✓ Found {len(self.results[category])} matches")
            else:
                print(f"✗ No matches")
    
    def print_results(self):
        """Print detailed results"""
        print("\n" + "="*80)
        print("DETAILED RESULTS")
        print("="*80)
        
        for category, matches in self.results.items():
            if not matches:
                continue
                
            print(f"\n{'='*80}")
            print(f"{category.upper()} ({len(matches)} matches)")
            print('='*80)
            
            # Group by file
            by_file = defaultdict(list)
            for match in matches:
                by_file[match['file']].append(match)
            
            for file_path, file_matches in list(by_file.items())[:5]:  # Top 5 files
                print(f"\n📁 {file_path}")
                for match in file_matches[:3]:  # Top 3 matches per file
                    print(f"\n  Line {match['line']}: {match['match']}")
                    print(f"  Context:")
                    for line in match['context'].split('\n'):
                        print(f"    {line}")
                    print()
    
    def save_results(self, output_file):
        """Save results to file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("CYNC APK SEARCH RESULTS\n")
            f.write("="*80 + "\n\n")
            
            for category, matches in self.results.items():
                if not matches:
                    continue
                
                f.write(f"\n{'='*80}\n")
                f.write(f"{category.upper()} ({len(matches)} matches)\n")
                f.write('='*80 + "\n\n")
                
                by_file = defaultdict(list)
                for match in matches:
                    by_file[match['file']].append(match)
                
                for file_path, file_matches in by_file.items():
                    f.write(f"\n📁 {file_path}\n")
                    for match in file_matches:
                        f.write(f"\n  Line {match['line']}: {match['match']}\n")
                        f.write(f"  Context:\n")
                        for line in match['context'].split('\n'):
                            f.write(f"    {line}\n")
                        f.write("\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python src/apk_search.py <path_to_decompiled_apk>")
        print("\nExample:")
        print(r"  python src\apk_search.py C:\Users\Meow\Documents\Projects\cync-explorer\artifacts\cync_decompiled")
        sys.exit(1)
    
    decompiled_path = sys.argv[1]
    
    if not os.path.exists(decompiled_path):
        print(f"Error: Path not found: {decompiled_path}")
        sys.exit(1)
    
    searcher = APKSearcher(decompiled_path)
    searcher.search_all()
    searcher.print_results()
    
    # Save to file
    output_file = OUTPUT_DIR / "apk_search_results.txt"
    searcher.save_results(output_file)
    print(f"\n\n✓ Full results saved to: {output_file}")
    
    # Print key files to investigate
    print("\n" + "="*80)
    print("KEY FILES TO INVESTIGATE MANUALLY:")
    print("="*80)
    
    key_files = set()
    for matches in searcher.results.values():
        for match in matches[:10]:  # Top 10 overall
            key_files.add(match['file'])
    
    for i, file_path in enumerate(sorted(key_files)[:10], 1):
        print(f"{i}. {file_path}")

if __name__ == "__main__":
    main()
