# Cync DEX Analysis - Complete Summary

**Analysis Date**: 2026-01-10
**Tool**: JADX + Custom Python Analysis Pipeline
**Status**: ✅ COMPLETE

---

## Executive Summary

Successfully decompiled and analyzed all 8 DEX files from the GE Cync APK (v6.20.0) and generated comprehensive structured markdown documentation. The analysis identified **all critical BLE UUIDs** and extracted extensive protocol information.

---

## Key Achievements

### ✅ Critical UUIDs Found

All known UUIDs from HCI analysis were successfully located:

| UUID | Short | Purpose | Location |
| --- | --- | --- | --- |
| `00002adb-0000-1000-8000-00805f9b34fb` | 2adb | **Mesh Provisioning In** | classes4.md (bppbqbb.java) |
| `00002add-0000-1000-8000-00805f9b34fb` | 2add | **Mesh Proxy In** | classes4.md (bppbqbb.java) |
| `00002ade-0000-1000-8000-00805f9b34fb` | 2ade | **Mesh Proxy Out** | classes4.md (bppbqbb.java) |
| `00010203-0405-0607-0809-0a0b0c0d1912` | 1912 | **Telink Command** | classes2.md (Telink.java), classes4.md |

**Critical File**: `bppbqbb.java` in classes4.dex contains all mesh provisioning UUIDs!

### 📊 Analysis Statistics

| Metric | Count |
| --- | --- |
| **Total DEX Files Processed** | 8 |
| **Combined DEX Size** | 57.2 MB |
| **Java Files Decompiled** | 47,849 |
| **Classes Analyzed** | 47,475 |
| **BLE-Related Classes** | 22,867 |
| **Total Methods** | 358,113 |
| **UUIDs Discovered** | 138 unique |
| **BLE Write Operations** | 1,024 |

### 📁 Generated Documentation

**Individual DEX Analysis Files**:
- `classes1.md` (2.6 MB) - 17,483 classes - **Primary GE Cync app code**
- `classes2.md` (3.1 MB) - 9,282 classes - 20 UUIDs, **Telink protocol classes**
- `classes3.md` (3.3 MB) - 9,421 classes
- `classes4.md` (1.0 MB) - 2,652 classes - **86 UUIDs** - **KEY FILE FOR BLE**
- `classes5.md` (342 KB) - 1,114 classes - 14 UUIDs
- `classes6.md` (206 KB) - 813 classes
- `classes7.md` (194 KB) - 497 classes
- `classes8.md` (1.8 MB) - 6,213 classes - 17 UUIDs

**Index & Reference Files**:
- `INDEX.md` (8.6 KB) - Master navigation with statistics
- `BLE_REFERENCE.md` (17 KB) - Consolidated BLE protocol findings
- `SEARCH_GUIDE.md` (3.4 KB) - How to navigate documentation

**Raw Java Source**:
- `decomp/raw/classes1/` through `decomp/raw/classes8/` - Full decompiled source

---

## Key Findings

### 1. Obfuscated Class Names

The BLE protocol implementation uses heavily obfuscated class names:
- `bppbqbb.java` - **Contains all mesh UUIDs** (classes4.dex)
- `qpqqdbp.java` - Additional BLE characteristics (classes4.dex)
- `dpdpppb.java` - Custom UUIDs (classes4.dex)
- `Telink.java` - Telink protocol implementation (classes2.dex)

### 2. UUID Breakdown by DEX File

| DEX File | UUIDs | Key Findings |
| --- | --- | --- |
| classes.dex | 1 | Client characteristic config |
| **classes2.dex** | **20** | **All Telink service UUIDs** (1910-1914) |
| classes3.dex | 0 | No UUIDs (general libraries) |
| **classes4.dex** | **86** | **CRITICAL: All mesh UUIDs** (2adb, 2add, 2ade) |
| classes5.dex | 14 | CHIP/Matter protocol UUIDs |
| classes6.dex | 0 | No UUIDs |
| classes7.dex | 0 | No UUIDs |
| classes8.dex | 17 | Additional BLE manager UUIDs |

### 3. Write Operations Distribution

Total: 1,024 BLE write operations across all DEX files

- **classes.dex**: 499 operations (UI state management)
- **classes2.dex**: 126 operations (Protocol logic)
- **classes3.dex**: 293 operations (Commissioning)
- **classes4.dex**: 27 operations (Device control)
- **classes5.dex**: 2 operations (Utilities)
- **classes8.dex**: 77 operations (HTTP client)

### 4. Command Sequences

**Status**: No hardcoded command sequences found in DEX files

This confirms that command sequences are likely:
- Generated dynamically at runtime
- Stored in native code (libBleLib.so)
- Encrypted/obfuscated beyond pattern recognition

**Known sequences from HCI analysis** (to cross-reference with native code):
- `00 05 01` - Handshake start
- `31 00` through `31 04` - Sync sequence
- `32 01 19 00 00 00` - Finalize

---

## Critical Files to Review

### For BLE Protocol Implementation:

1. **classes4.dex: bppbqbb.java** (MOST IMPORTANT)
   - Contains all mesh provisioning UUIDs (2adb, 2add, 2ade)
   - Location: `decomp/raw/classes4/bppbqbb.java`

2. **classes2.dex: Telink.java**
   - Telink protocol service and characteristic UUIDs
   - All Telink service variants (1910-1914)
   - Location: `decomp/raw/classes2/Telink.java`

3. **classes4.dex: qpqqdbp.java**
   - Additional BLE characteristics
   - Command and status UUIDs
   - Location: `decomp/raw/classes4/qpqqdbp.java`

4. **classes5.dex: BluetoothHelper.java**
   - CHIP/Matter protocol integration
   - C3 and CHIP UUIDs
   - Location: `decomp/raw/classes5/BluetoothHelper.java`

### For Understanding Control Flow:

5. **classes1.md** - Search for "mesh", "bluetooth", "gatt"
6. **BLE_REFERENCE.md** - Consolidated findings with protocol reconstruction

---

## Next Steps for Protocol Implementation

### 1. Review Critical Java Files

Open and review these decompiled files in priority order:

```bash
# Most important
code "C:/Users/Meow/Documents/Projects/cync-explorer/decomp/raw/classes4/bppbqbb.java"

# Secondary importance
code "C:/Users/Meow/Documents/Projects/cync-explorer/decomp/raw/classes2/Telink.java"
code "C:/Users/Meow/Documents/Projects/cync-explorer/decomp/raw/classes4/qpqqdbp.java"
```

### 2. Search for Method Implementations

Use markdown files to find:
- `writeCharacteristic` implementations
- `onCharacteristicChanged` callbacks
- Session ID handling logic
- Command encoding functions

### 3. Cross-Reference with Native Code

Compare findings with libBleLib.so analysis:
- Check if `trsmitr_send_pkg_encode()` matches DEX implementations
- Look for session key generation logic
- Find command construction methods

### 4. Test Protocol Sequences

Use the web server (`src/cync_server.py`) to test:
- UUID connections to characteristics found
- Command sequences from HCI analysis
- Session ID transformations discovered

---

## How to Use the Documentation

### Quick Start

1. **Start here**: Open `decomp/INDEX.md`
2. **BLE Protocol**: Read `decomp/BLE_REFERENCE.md`
3. **Find specific code**: See `decomp/SEARCH_GUIDE.md`

### Finding Specific Information

**To find a UUID**:
1. Open `INDEX.md` → UUID Directory
2. Find your UUID (e.g., `2adb`)
3. Click the link to the DEX file
4. Navigate to the Java source in `decomp/raw/`

**To find BLE classes**:
1. Open `classes4.md` (most BLE code here)
2. Go to "BLE-Related Classes" section
3. Review classes marked CRITICAL or HIGH priority

**To search all code**:
1. Use your text editor/IDE to search `decomp/raw/`
2. Or use grep: `grep -r "2adb" decomp/raw/`

### Understanding Package Structure

Each DEX markdown has a "Package Structure" section showing:
- Package hierarchy
- Class counts per package
- Related packages grouped together

Example packages of interest:
- `com.thingclips.*` - Smart device APIs
- `chip.devicecontroller` - Matter/CHIP protocol
- Obfuscated packages in classes4.dex contain BLE core

---

## Pipeline Details

### Tools Used

1. **JADX** (v1.5.0) - DEX to Java decompiler
2. **Python 3.11** - Analysis scripts
3. **Custom extractors** - BLE-specific pattern matching

### Processing Time

- **Single DEX**: 1-7 minutes depending on size
- **Full pipeline**: ~25 minutes for all 8 DEX files
- **Parallel capable**: Can process multiple DEX files simultaneously

### Scripts Created

Located in `scripts/dex_analysis/`:
- `analyze_dex.py` - Main orchestrator
- `extract_ble_code.py` - BLE pattern extraction
- `generate_markdown.py` - Documentation formatting
- `create_index.py` - Index generation

User-facing entry point: `scripts/run_dex_analysis.bat`

### Rerunning Analysis

To update analysis (e.g., after APK updates):

```bash
cd C:\Users\Meow\Documents\Projects\cync-explorer
.\scripts\run_dex_analysis.bat
```

To process a single DEX file for testing:

```bash
python scripts\dex_analysis\analyze_dex.py --test  # Processes classes7.dex
python scripts\dex_analysis\analyze_dex.py --dex-file classes4.dex  # Specific file
```

---

## Success Metrics

### ✅ All Goals Achieved

- [x] All 8 DEX files successfully decompiled
- [x] 47,849 Java files generated
- [x] 138 unique UUIDs extracted
- [x] All 4 critical BLE UUIDs located (2adb, 2add, 2ade, 1912)
- [x] 22,867 BLE-related classes identified
- [x] Comprehensive markdown documentation generated
- [x] Master index with navigation created
- [x] BLE protocol reference document completed
- [x] Full source code browseable in `decomp/raw/`

### 🎯 Critical Discovery

**The file `bppbqbb.java` in classes4.dex contains all mesh provisioning UUIDs!**

This is the key file for understanding the GE Cync BLE mesh protocol implementation.

---

## Repository Structure

```
cync-explorer/
├── decomp/                          [NEW - 12 MB markdown + source]
│   ├── classes1.md - classes8.md   [Individual DEX analysis]
│   ├── INDEX.md                     [Master navigation]
│   ├── BLE_REFERENCE.md             [Protocol findings]
│   ├── SEARCH_GUIDE.md              [Navigation tips]
│   ├── ANALYSIS_SUMMARY.md          [This file]
│   └── raw/                         [~500 MB Java source]
│       ├── classes1/ - classes8/    [Decompiled Java files]
│
├── scripts/
│   ├── dex_analysis/                [NEW - Analysis pipeline]
│   │   ├── analyze_dex.py
│   │   ├── extract_ble_code.py
│   │   ├── generate_markdown.py
│   │   └── create_index.py
│   └── run_dex_analysis.bat         [NEW - Entry point]
│
├── artifacts/
│   └── apk_extracted/               [Original DEX files]
│       └── classes.dex - classes8.dex
│
└── md/                              [Existing project docs]
    ├── PROJECT_ARCHITECTURE.md
    ├── NATIVE_LIB_FINDINGS.md
    └── ...
```

---

## Conclusion

The DEX analysis pipeline successfully completed full decompilation and structured analysis of the GE Cync Android APK. All critical BLE protocol UUIDs were located, and comprehensive documentation was generated to support further reverse engineering efforts.

**Key Achievement**: Found all mesh provisioning UUIDs in `bppbqbb.java` (classes4.dex), providing the foundation for implementing direct BLE control of GE Cync smart bulbs.

**Next Steps**: Review the critical Java files, cross-reference with native library analysis (libBleLib.so), and implement the protocol in the web server for testing.

---

## References

- **Original Plan**: `C:\Users\Meow\.claude\plans\kind-yawning-rossum.md`
- **Project Docs**: `md/PROJECT_ARCHITECTURE.md`, `md/APK_ANALYSIS_SUMMARY.md`
- **HCI Analysis**: `md/NATIVE_LIB_FINDINGS.md`
- **Web Server**: `src/cync_server.py`
