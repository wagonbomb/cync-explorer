import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
filepath = REPO_ROOT / "artifacts" / "outputs" / "apk_strings_analysis.txt"

try:
    with filepath.open('rb') as f:
        content = f.read()
   
    # Convert to string, ignoring errors
    text = content.decode('utf-8', errors='ignore')
   
    # Print first 5000 characters
    print(text[:5000])
   
    # Count files
    file_count = text.count("FILE:")
    print(f"\n\n{'='*80}")
    print(f"Total files with matches: {file_count}")
   
    # Extract file names
    import re
    files = re.findall(r'FILE: (.+)', text)
    print("\nFiles with matches:")
    for f in files[:20]:  # First 20
        print(f"  - {f}")
   
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
