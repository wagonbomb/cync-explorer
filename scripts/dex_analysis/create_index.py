#!/usr/bin/env python3
"""
Index and Reference Document Generator
Creates INDEX.md, BLE_REFERENCE.md, and SEARCH_GUIDE.md
"""
from pathlib import Path
from typing import List, Tuple, Dict
from collections import defaultdict
from datetime import datetime


def generate_master_index(all_results: List[Tuple[str, int, dict]], output_dir: Path) -> str:
    """
    Generate INDEX.md with master navigation and statistics

    Args:
        all_results: List of (dex_file, dex_index, analysis_result) tuples
        output_dir: Output directory

    Returns:
        Markdown content
    """
    lines = []

    lines.append("# Cync APK DEX Analysis - Master Index")
    lines.append("")
    lines.append(f"**Total DEX Files**: {len(all_results)}")

    # Calculate totals
    total_size = sum(r['stats'].file_size_mb for _, _, r in all_results)
    total_classes = sum(r['stats'].total_classes for _, _, r in all_results)
    total_methods = sum(r['stats'].total_methods for _, _, r in all_results)
    total_ble_classes = sum(r['stats'].ble_classes for _, _, r in all_results)
    total_uuids = sum(r['stats'].uuid_count for _, _, r in all_results)

    lines.append(f"**Combined Size**: {total_size:.1f} MB")
    lines.append(f"**Total Classes**: {total_classes:,}")
    lines.append(f"**Total Methods**: {total_methods:,}")
    lines.append(f"**BLE-Related Classes**: {total_ble_classes:,}")
    lines.append(f"**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Quick Navigation
    lines.append("## Quick Navigation")
    lines.append("")
    lines.append("### By Topic")
    lines.append("- [BLE Code Summary](#ble-code-summary)")
    lines.append("- [UUID Directory](#uuid-directory)")
    lines.append("- [Statistics by DEX](#statistics-by-dex)")
    lines.append("- [Search Guide](SEARCH_GUIDE.md)")
    lines.append("- [BLE Reference](BLE_REFERENCE.md)")
    lines.append("")

    lines.append("### By DEX File")
    for dex_file, dex_idx, result in all_results:
        stats = result['stats']
        purpose = "Primary app code" if dex_idx == 1 else "Libraries & dependencies"
        lines.append(f"{dex_idx}. [{dex_file}](classes{dex_idx}.md) - {stats.file_size_mb:.1f} MB - {stats.total_classes:,} classes - **{purpose}**")
    lines.append("")
    lines.append("---")
    lines.append("")

    # BLE Code Summary
    lines.append("## BLE Code Summary")
    lines.append("")

    # Collect all BLE classes across all DEX files
    all_ble_classes = []
    for dex_file, dex_idx, result in all_results:
        for cls in result['ble_classes']:
            all_ble_classes.append((cls, dex_idx))

    # Sort by priority
    all_ble_classes.sort(key=lambda x: x[0].ble_priority, reverse=True)

    lines.append(f"Found {len(all_ble_classes)} BLE-related classes across all DEX files:")
    lines.append("")

    lines.append("### Top 20 BLE Classes by Priority")
    lines.append("")
    lines.append("| Class | Priority | DEX File | Package |")
    lines.append("| --- | --- | --- | --- |")

    for cls, dex_idx in all_ble_classes[:20]:
        priority_label = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(cls.ble_priority, "")
        lines.append(f"| `{cls.class_name}` | {priority_label} | [classes{dex_idx}.md](classes{dex_idx}.md) | `{cls.package}` |")

    if len(all_ble_classes) > 20:
        lines.append(f"| ... | ... | ... | ... |")
        lines.append(f"| *{len(all_ble_classes) - 20} more classes* | | | |")

    lines.append("")
    lines.append("---")
    lines.append("")

    # UUID Directory
    lines.append("## UUID Directory")
    lines.append("")

    # Collect all UUIDs
    uuid_locations = defaultdict(list)
    for dex_file, dex_idx, result in all_results:
        for uuid_def in result['uuids']:
            uuid_locations[uuid_def.uuid].append((dex_idx, dex_file))

    if uuid_locations:
        lines.append("### All UUIDs Found")
        lines.append("")
        lines.append("| UUID | Purpose | Found In |")
        lines.append("| --- | --- | --- |")

        # Known UUIDs
        known_uuids = {
            "00002adb": "Mesh Provisioning In",
            "00002add": "Mesh Proxy In",
            "00002ade": "Mesh Proxy Out",
            "00010203-0405-0607-0809": "Telink Service",
            "1912": "Telink Command Characteristic"
        }

        for uuid_str in sorted(uuid_locations.keys()):
            # Determine purpose
            purpose = "Unknown"
            for key, desc in known_uuids.items():
                if key in uuid_str.lower():
                    purpose = desc
                    break

            # List DEX files
            dex_files = set((idx, name) for idx, name in uuid_locations[uuid_str])
            dex_list = ', '.join([f"[classes{idx}.md](classes{idx}.md)" for idx, _ in sorted(dex_files)])

            lines.append(f"| `{uuid_str}` | {purpose} | {dex_list} |")

        lines.append("")
    else:
        lines.append("*No UUIDs found in any DEX file.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    # Statistics by DEX
    lines.append("## Statistics by DEX")
    lines.append("")
    lines.append("| DEX | Size | Classes | Methods | BLE Classes | UUIDs | Key Findings |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")

    for dex_file, dex_idx, result in all_results:
        stats = result['stats']
        findings = f"{stats.write_op_count} write ops, {stats.command_count} commands" if stats.write_op_count > 0 or stats.command_count > 0 else "-"
        lines.append(f"| {dex_file} | {stats.file_size_mb:.1f}M | {stats.total_classes:,} | {stats.total_methods:,} | {stats.ble_classes} | {stats.uuid_count} | {findings} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Footer
    lines.append("## How to Use This Documentation")
    lines.append("")
    lines.append("1. **Finding BLE Protocol Code**: Start with [BLE_REFERENCE.md](BLE_REFERENCE.md) for consolidated findings")
    lines.append("2. **Exploring Specific DEX**: Click on DEX file links above to see detailed analysis")
    lines.append("3. **Searching for Keywords**: See [SEARCH_GUIDE.md](SEARCH_GUIDE.md) for tips")
    lines.append("4. **Understanding Classes**: Each DEX markdown has cross-references and code snippets")
    lines.append("")

    return '\n'.join(lines)


def generate_ble_reference(all_results: List[Tuple[str, int, dict]], output_dir: Path) -> str:
    """
    Generate BLE_REFERENCE.md with consolidated BLE findings
    """
    lines = []

    lines.append("# BLE Protocol Reference - Consolidated Findings")
    lines.append("")
    lines.append("This document consolidates all BLE-related discoveries across all 8 DEX files.")
    lines.append("")
    lines.append(f"**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Table of Contents
    lines.append("## Table of Contents")
    lines.append("")
    lines.append("1. [UUID Catalog](#uuid-catalog)")
    lines.append("2. [Critical BLE Classes](#critical-ble-classes)")
    lines.append("3. [Write Operations](#write-operations)")
    lines.append("4. [Command Sequences](#command-sequences)")
    lines.append("5. [Protocol Reconstruction](#protocol-reconstruction)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # UUID Catalog
    lines.append("## UUID Catalog")
    lines.append("")

    uuid_locations = defaultdict(list)
    for dex_file, dex_idx, result in all_results:
        for uuid_def in result['uuids']:
            uuid_locations[uuid_def.uuid].append((dex_idx, uuid_def))

    if uuid_locations:
        # Known UUIDs from HCI analysis
        lines.append("### Known UUIDs (from HCI Analysis)")
        lines.append("")
        lines.append("| UUID | Short | Purpose | Status |")
        lines.append("| --- | --- | --- | --- |")
        lines.append("| `00002adb-0000-1000-8000-00805f9b34fb` | 2adb | Mesh Provisioning In | ✅ Found |" if any("2adb" in u.lower() for u in uuid_locations.keys()) else "| `00002adb-0000-1000-8000-00805f9b34fb` | 2adb | Mesh Provisioning In | ❌ Not found |")
        lines.append("| `00002add-0000-1000-8000-00805f9b34fb` | 2add | Mesh Proxy In | ✅ Found |" if any("2add" in u.lower() for u in uuid_locations.keys()) else "| `00002add-0000-1000-8000-00805f9b34fb` | 2add | Mesh Proxy In | ❌ Not found |")
        lines.append("| `00002ade-0000-1000-8000-00805f9b34fb` | 2ade | Mesh Proxy Out | ✅ Found |" if any("2ade" in u.lower() for u in uuid_locations.keys()) else "| `00002ade-0000-1000-8000-00805f9b34fb` | 2ade | Mesh Proxy Out | ❌ Not found |")
        lines.append("| `00010203-0405-0607-0809-0a0b0c0d1912` | 1912 | Telink Command | ✅ Found |" if any("1912" in u.lower() or "00010203" in u.lower() for u in uuid_locations.keys()) else "| `00010203-0405-0607-0809-0a0b0c0d1912` | 1912 | Telink Command | ❌ Not found |")
        lines.append("")

        lines.append("### All Discovered UUIDs")
        lines.append("")
        for uuid_str in sorted(uuid_locations.keys()):
            locations = uuid_locations[uuid_str]
            lines.append(f"#### `{uuid_str}`")
            lines.append("")
            lines.append(f"- **Occurrences**: {len(locations)}")
            lines.append(f"- **Found in**: {', '.join(sorted(set(f'classes{idx}.md' for idx, _ in locations)))}")
            lines.append("")

            # Show first 3 occurrences with context
            for idx, uuid_def in locations[:3]:
                if uuid_def.file_path:
                    file_name = Path(uuid_def.file_path).name
                    lines.append(f"- `{file_name}:{uuid_def.line_number}` - Variable: `{uuid_def.variable_name or 'N/A'}`")

            if len(locations) > 3:
                lines.append(f"- *(... and {len(locations) - 3} more occurrences)*")

            lines.append("")
    else:
        lines.append("**WARNING**: No UUIDs found in any DEX file.")
        lines.append("")
        lines.append("This likely means:")
        lines.append("- UUIDs are defined in native code (libBleLib.so)")
        lines.append("- UUIDs are constructed at runtime")
        lines.append("- Code is heavily obfuscated")
        lines.append("")

    lines.append("---")
    lines.append("")

    # Critical BLE Classes
    lines.append("## Critical BLE Classes")
    lines.append("")

    all_ble_classes = []
    for dex_file, dex_idx, result in all_results:
        for cls in result['ble_classes']:
            if cls.ble_priority >= 3:  # High or Critical
                all_ble_classes.append((cls, dex_idx))

    all_ble_classes.sort(key=lambda x: x[0].ble_priority, reverse=True)

    if all_ble_classes:
        for cls, dex_idx in all_ble_classes[:10]:  # Top 10
            lines.append(f"### {cls.full_name}")
            lines.append("")
            lines.append(f"- **Priority**: {'CRITICAL' if cls.ble_priority == 4 else 'HIGH'}")
            lines.append(f"- **Found in**: [classes{dex_idx}.md](classes{dex_idx}.md)")
            if cls.superclass:
                lines.append(f"- **Extends**: `{cls.superclass}`")
            if cls.interfaces:
                lines.append(f"- **Implements**: `{', '.join(cls.interfaces)}`")
            lines.append("")

            # Key methods
            if cls.methods:
                lines.append("**Key Methods**:")
                for method in cls.methods[:5]:
                    lines.append(f"- `{method}()`")
                if len(cls.methods) > 5:
                    lines.append(f"- *(... and {len(cls.methods) - 5} more)*")
                lines.append("")

            lines.append("---")
            lines.append("")
    else:
        lines.append("*No critical BLE classes found.*")
        lines.append("")

    # Write Operations
    lines.append("## Write Operations")
    lines.append("")

    total_write_ops = sum(len(result['write_ops']) for _, _, result in all_results)
    lines.append(f"Total write operations found: {total_write_ops}")
    lines.append("")

    if total_write_ops > 0:
        # Group by DEX
        for dex_file, dex_idx, result in all_results:
            if result['write_ops']:
                lines.append(f"### From {dex_file}")
                lines.append("")
                for op in result['write_ops'][:5]:
                    file_name = Path(op.file_path).name if op.file_path else "Unknown"
                    lines.append(f"- `{file_name}:{op.line_number}` - `{op.method_name}({op.characteristic_var})`")
                if len(result['write_ops']) > 5:
                    lines.append(f"- *(... and {len(result['write_ops']) - 5} more)*")
                lines.append("")
    else:
        lines.append("*No write operations found.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    # Command Sequences
    lines.append("## Command Sequences")
    lines.append("")

    # Known patterns from HCI analysis
    lines.append("### Known Command Patterns (from HCI Analysis)")
    lines.append("")
    lines.append("| Bytes | Purpose |")
    lines.append("| --- | --- |")
    lines.append("| `00 05 01` | Handshake Start |")
    lines.append("| `00 00 01 ... 04 00 00` | Key Exchange |")
    lines.append("| `04 00 00 [session]` | Session ID Response |")
    lines.append("| `31 00` - `31 04` | Sync Sequence |")
    lines.append("| `32 01 19 00 00 00` | Finalize |")
    lines.append("")

    total_commands = sum(len(result['commands']) for _, _, result in all_results)
    lines.append(f"### Discovered Command Sequences: {total_commands}")
    lines.append("")

    if total_commands > 0:
        all_commands = []
        for dex_file, dex_idx, result in all_results:
            for cmd in result['commands']:
                all_commands.append((cmd, dex_idx))

        # Show first 20
        for cmd, dex_idx in all_commands[:20]:
            hex_display = ' '.join([cmd.bytes_hex[i:i+2] for i in range(0, len(cmd.bytes_hex), 2)])
            file_name = Path(cmd.file_path).name if cmd.file_path else "Unknown"
            lines.append(f"- `{hex_display}` - {file_name} (classes{dex_idx}.md)")

        if len(all_commands) > 20:
            lines.append(f"- *(... and {len(all_commands) - 20} more sequences)*")
        lines.append("")
    else:
        lines.append("*No command sequences found in DEX files.*")
        lines.append("")
        lines.append("Commands may be:")
        lines.append("- Defined in native code (libBleLib.so)")
        lines.append("- Generated dynamically")
        lines.append("- Encrypted/encoded")
        lines.append("")

    lines.append("---")
    lines.append("")

    # Protocol Reconstruction
    lines.append("## Protocol Reconstruction")
    lines.append("")
    lines.append("Based on HCI analysis and code findings:")
    lines.append("")
    lines.append("### Provisioning Sequence")
    lines.append("```")
    lines.append("1. Connect to device (telink_mesh1)")
    lines.append("2. Write to 2adb (Mesh Prov In): 00 05 01 00 00 00 00 00 00 00 00 00")
    lines.append("3. Write to 2adb: 00 00 01 00 00 00 00 00 00 00 04 00 00")
    lines.append("4. Read from 2ade (Mesh Prov Out): 04 00 00 [session_id]")
    lines.append("5. Write sync sequence to 2adb:")
    lines.append("   - 31 00")
    lines.append("   - 31 01")
    lines.append("   - 31 02")
    lines.append("   - 31 03")
    lines.append("   - 31 04")
    lines.append("6. Write to 2adb: 32 01 19 00 00 00")
    lines.append("```")
    lines.append("")
    lines.append("### Control Commands")
    lines.append("```")
    lines.append("Command Header: [transformed_id][C0][payload]")
    lines.append("transformed_id = (((session_id & 0x0F) + 0x0A) << 4) & 0xFF")
    lines.append("```")
    lines.append("")

    return '\n'.join(lines)


def generate_search_guide(output_dir: Path) -> str:
    """
    Generate SEARCH_GUIDE.md with navigation tips
    """
    lines = []

    lines.append("# Search Guide - How to Navigate the Documentation")
    lines.append("")
    lines.append("This guide helps you find specific information in the DEX analysis documentation.")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Quick References")
    lines.append("")
    lines.append("- **[INDEX.md](INDEX.md)** - Master index with statistics and links")
    lines.append("- **[BLE_REFERENCE.md](BLE_REFERENCE.md)** - Consolidated BLE findings")
    lines.append("- **classes1.md - classes8.md** - Individual DEX file analysis")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Finding Specific Information")
    lines.append("")

    lines.append("### Finding BLE Protocol Code")
    lines.append("1. Start with [BLE_REFERENCE.md](BLE_REFERENCE.md) for consolidated findings")
    lines.append("2. Check UUID Catalog section for specific UUIDs (2adb, 2add, 2ade, 1912)")
    lines.append("3. Review Critical BLE Classes section for main implementation")
    lines.append("4. Follow links to specific DEX files for full source code")
    lines.append("")

    lines.append("### Finding Specific UUIDs")
    lines.append("1. Go to [INDEX.md](INDEX.md) → UUID Directory")
    lines.append("2. Search for UUID value (e.g., `2adb`)")
    lines.append("3. Click DEX file links to see full context")
    lines.append("4. Check BLE-Related Classes section in each DEX markdown")
    lines.append("")

    lines.append("### Finding Command Sequences")
    lines.append("1. Check [BLE_REFERENCE.md](BLE_REFERENCE.md) → Command Sequences")
    lines.append("2. Look for known patterns: `000501`, `3100-3104`, `320119`")
    lines.append("3. Review Command Sequences section in individual DEX markdowns")
    lines.append("4. Check native library analysis (libBleLib.so) if not in DEX")
    lines.append("")

    lines.append("### Finding Specific Classes")
    lines.append("1. Open [INDEX.md](INDEX.md)")
    lines.append("2. Check BLE Code Summary for BLE-related classes")
    lines.append("3. Use browser search (Ctrl+F) for class name")
    lines.append("4. Navigate to appropriate DEX file")
    lines.append("5. Expand Full Class List section if needed")
    lines.append("")

    lines.append("### Understanding Package Structure")
    lines.append("1. Open any DEX markdown (e.g., classes1.md)")
    lines.append("2. Go to Package Structure section")
    lines.append("3. Review package hierarchy tree")
    lines.append("4. Check Top 20 Packages table for most relevant packages")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Search Strategies")
    lines.append("")

    lines.append("### Strategy 1: Known UUID Search")
    lines.append("If you know a UUID (e.g., `00002adb`):")
    lines.append("1. Search in [BLE_REFERENCE.md](BLE_REFERENCE.md)")
    lines.append("2. If not found, check native library analysis")
    lines.append("3. UUIDs might be in libBleLib.so instead of DEX")
    lines.append("")

    lines.append("### Strategy 2: Keyword Search")
    lines.append("To find classes related to a keyword (e.g., 'bluetooth', 'mesh', 'gatt'):")
    lines.append("1. Open [INDEX.md](INDEX.md) → BLE Code Summary")
    lines.append("2. Look for classes containing the keyword")
    lines.append("3. Use browser search (Ctrl+F) across all DEX markdowns")
    lines.append("4. Focus on classes1.md first (primary app code)")
    lines.append("")

    lines.append("### Strategy 3: Method Search")
    lines.append("To find a specific method (e.g., 'writeCharacteristic'):")
    lines.append("1. Check [BLE_REFERENCE.md](BLE_REFERENCE.md) → Write Operations")
    lines.append("2. Review Method Index in individual DEX markdowns")
    lines.append("3. Use Full Class List to find all classes with the method")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## File Organization")
    lines.append("")

    lines.append("```")
    lines.append("decomp/")
    lines.append("├── INDEX.md                 # Start here - Master navigation")
    lines.append("├── BLE_REFERENCE.md         # BLE protocol consolidated findings")
    lines.append("├── SEARCH_GUIDE.md          # This file")
    lines.append("├── classes1.md              # Primary app code (most important)")
    lines.append("├── classes2.md - classes8.md # Additional libraries")
    lines.append("└── raw/                     # Decompiled Java source (browseable)")
    lines.append("    ├── classes1/")
    lines.append("    ├── classes2/")
    lines.append("    └── ...")
    lines.append("```")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Tips for Effective Searching")
    lines.append("")
    lines.append("1. **Start with classes1.md** - Contains primary GE Cync app code")
    lines.append("2. **Use browser search** - Ctrl+F in markdown for quick keyword lookup")
    lines.append("3. **Check cross-references** - Follow links between documents")
    lines.append("4. **Review full source** - Navigate to `decomp/raw/classesN/` for complete files")
    lines.append("5. **Compare with HCI logs** - Cross-reference with known working sequences")
    lines.append("")

    return '\n'.join(lines)


def generate_all_index_files(all_results: List[Tuple[str, int, dict]], output_dir: Path):
    """
    Generate all index and reference documents

    Args:
        all_results: List of (dex_file, dex_index, analysis_result) tuples
        output_dir: Output directory
    """
    # Generate INDEX.md
    index_content = generate_master_index(all_results, output_dir)
    (output_dir / "INDEX.md").write_text(index_content, encoding='utf-8')

    # Generate BLE_REFERENCE.md
    ble_ref_content = generate_ble_reference(all_results, output_dir)
    (output_dir / "BLE_REFERENCE.md").write_text(ble_ref_content, encoding='utf-8')

    # Generate SEARCH_GUIDE.md
    search_guide_content = generate_search_guide(output_dir)
    (output_dir / "SEARCH_GUIDE.md").write_text(search_guide_content, encoding='utf-8')


if __name__ == "__main__":
    # Test
    print("This module is meant to be imported, not run directly.")
    print("It will be called by analyze_dex.py after processing all DEX files.")
