# Search Guide - How to Navigate the Documentation

This guide helps you find specific information in the DEX analysis documentation.

---

## Quick References

- **[INDEX.md](INDEX.md)** - Master index with statistics and links
- **[BLE_REFERENCE.md](BLE_REFERENCE.md)** - Consolidated BLE findings
- **classes1.md - classes8.md** - Individual DEX file analysis

---

## Finding Specific Information

### Finding BLE Protocol Code
1. Start with [BLE_REFERENCE.md](BLE_REFERENCE.md) for consolidated findings
2. Check UUID Catalog section for specific UUIDs (2adb, 2add, 2ade, 1912)
3. Review Critical BLE Classes section for main implementation
4. Follow links to specific DEX files for full source code

### Finding Specific UUIDs
1. Go to [INDEX.md](INDEX.md) → UUID Directory
2. Search for UUID value (e.g., `2adb`)
3. Click DEX file links to see full context
4. Check BLE-Related Classes section in each DEX markdown

### Finding Command Sequences
1. Check [BLE_REFERENCE.md](BLE_REFERENCE.md) → Command Sequences
2. Look for known patterns: `000501`, `3100-3104`, `320119`
3. Review Command Sequences section in individual DEX markdowns
4. Check native library analysis (libBleLib.so) if not in DEX

### Finding Specific Classes
1. Open [INDEX.md](INDEX.md)
2. Check BLE Code Summary for BLE-related classes
3. Use browser search (Ctrl+F) for class name
4. Navigate to appropriate DEX file
5. Expand Full Class List section if needed

### Understanding Package Structure
1. Open any DEX markdown (e.g., classes1.md)
2. Go to Package Structure section
3. Review package hierarchy tree
4. Check Top 20 Packages table for most relevant packages

---

## Search Strategies

### Strategy 1: Known UUID Search
If you know a UUID (e.g., `00002adb`):
1. Search in [BLE_REFERENCE.md](BLE_REFERENCE.md)
2. If not found, check native library analysis
3. UUIDs might be in libBleLib.so instead of DEX

### Strategy 2: Keyword Search
To find classes related to a keyword (e.g., 'bluetooth', 'mesh', 'gatt'):
1. Open [INDEX.md](INDEX.md) → BLE Code Summary
2. Look for classes containing the keyword
3. Use browser search (Ctrl+F) across all DEX markdowns
4. Focus on classes1.md first (primary app code)

### Strategy 3: Method Search
To find a specific method (e.g., 'writeCharacteristic'):
1. Check [BLE_REFERENCE.md](BLE_REFERENCE.md) → Write Operations
2. Review Method Index in individual DEX markdowns
3. Use Full Class List to find all classes with the method

---

## File Organization

```
decomp/
├── INDEX.md                 # Start here - Master navigation
├── BLE_REFERENCE.md         # BLE protocol consolidated findings
├── SEARCH_GUIDE.md          # This file
├── classes1.md              # Primary app code (most important)
├── classes2.md - classes8.md # Additional libraries
└── raw/                     # Decompiled Java source (browseable)
    ├── classes1/
    ├── classes2/
    └── ...
```

---

## Tips for Effective Searching

1. **Start with classes1.md** - Contains primary GE Cync app code
2. **Use browser search** - Ctrl+F in markdown for quick keyword lookup
3. **Check cross-references** - Follow links between documents
4. **Review full source** - Navigate to `decomp/raw/classesN/` for complete files
5. **Compare with HCI logs** - Cross-reference with known working sequences
