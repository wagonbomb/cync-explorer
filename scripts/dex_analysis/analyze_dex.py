#!/usr/bin/env python3
"""
Main DEX Analysis Orchestrator
Coordinates JADX decompilation, Java analysis, and markdown generation
"""
import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Optional
from collections import defaultdict
import json

# Import our modules
try:
    from extract_ble_code import (
        extract_all_from_class,
        ClassInfo,
        UUIDDefinition,
        WriteOperation,
        CommandSequence
    )
    from generate_markdown import generate_dex_markdown, AnalysisStats
except ImportError:
    # Try to import from same directory
    sys.path.insert(0, str(Path(__file__).parent))
    from extract_ble_code import (
        extract_all_from_class,
        ClassInfo,
        UUIDDefinition,
        WriteOperation,
        CommandSequence
    )
    from generate_markdown import generate_dex_markdown, AnalysisStats


# Configuration
REPO_ROOT = Path(__file__).resolve().parents[2]
DEX_DIR = REPO_ROOT / "artifacts" / "apk_extracted"
OUTPUT_DIR = REPO_ROOT / "decomp"
RAW_DIR = OUTPUT_DIR / "raw"
JADX_PATH = REPO_ROOT / "tools-local" / "jadx" / "bin" / "jadx.bat"

# DEX files to process
DEX_FILES = [
    "classes.dex",
    "classes2.dex",
    "classes3.dex",
    "classes4.dex",
    "classes5.dex",
    "classes6.dex",
    "classes7.dex",
    "classes8.dex"
]


def run_jadx_decompile(dex_path: Path, output_dir: Path, verbose: bool = False) -> bool:
    """
    Run JADX decompiler on a DEX file

    Args:
        dex_path: Path to DEX file
        output_dir: Output directory for decompiled Java
        verbose: Print JADX output

    Returns:
        True if successful, False otherwise
    """
    if not JADX_PATH.exists():
        print(f"ERROR: JADX not found at {JADX_PATH}")
        return False

    if not dex_path.exists():
        print(f"ERROR: DEX file not found: {dex_path}")
        return False

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # JADX command
    cmd = [
        str(JADX_PATH),
        "-d", str(output_dir),
        "--no-res",  # Skip resources - we only want code
        "--show-bad-code",  # Show even poorly decompiled code
        "--threads-count", "8",  # Use 8 threads for speed
        "--deobf",  # Enable deobfuscation
        str(dex_path)
    ]

    print(f"  Running JADX: {dex_path.name} -> {output_dir.name}/")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )

        if verbose:
            print(result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)

        if result.returncode != 0:
            print(f"  JADX failed with return code {result.returncode}")
            return False

        # Verify output exists
        java_files = list(output_dir.rglob("*.java"))
        if not java_files:
            print(f"  WARNING: No Java files found in output")
            return False

        print(f"  OK Decompiled {len(java_files)} Java files")
        return True

    except subprocess.TimeoutExpired:
        print(f"  ERROR: JADX timed out after 10 minutes")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def analyze_java_directory(java_dir: Path, verbose: bool = False) -> dict:
    """
    Walk through decompiled Java files and extract all information

    Returns:
        dict with:
            - stats: AnalysisStats
            - all_classes: List[ClassInfo]
            - ble_classes: List[ClassInfo]
            - packages: Dict[package_name, List[ClassInfo]]
            - uuids: List[UUIDDefinition]
            - write_ops: List[WriteOperation]
            - commands: List[CommandSequence]
    """
    print(f"  Analyzing Java files in {java_dir.name}/...")

    all_classes = []
    ble_classes = []
    packages = defaultdict(list)
    all_uuids = []
    all_write_ops = []
    all_commands = []

    # Find all Java files
    java_files = list(java_dir.rglob("*.java"))

    if not java_files:
        print(f"  WARNING: No Java files found")
        return None

    print(f"  Found {len(java_files)} Java files to analyze...")

    # Process each file
    for i, java_file in enumerate(java_files):
        if verbose and i % 100 == 0:
            print(f"    Processed {i}/{len(java_files)} files...")

        try:
            result = extract_all_from_class(java_file)

            if not result:
                continue

            class_info = result['class_info']
            all_classes.append(class_info)

            # Add to package index
            packages[class_info.package].append(class_info)

            # Track BLE classes separately
            if class_info.is_ble_related:
                ble_classes.append(class_info)

            # Collect BLE artifacts
            all_uuids.extend(result['uuids'])
            all_write_ops.extend(result['write_ops'])
            all_commands.extend(result['commands'])

        except Exception as e:
            if verbose:
                print(f"    ERROR processing {java_file.name}: {e}")
            continue

    # Calculate statistics
    total_methods = sum(len(c.methods) for c in all_classes)
    total_fields = sum(len(c.fields) for c in all_classes)

    stats = AnalysisStats(
        total_classes=len(all_classes),
        total_methods=total_methods,
        total_fields=total_fields,
        total_packages=len(packages),
        ble_classes=len(ble_classes),
        uuid_count=len(all_uuids),
        write_op_count=len(all_write_ops),
        command_count=len(all_commands),
        file_size_mb=0.0  # Will be filled in later
    )

    print(f"  OK Analysis complete:")
    print(f"    - {stats.total_classes:,} classes")
    print(f"    - {stats.ble_classes:,} BLE-related classes")
    print(f"    - {stats.uuid_count:,} UUIDs")
    print(f"    - {stats.write_op_count:,} write operations")

    return {
        'stats': stats,
        'all_classes': all_classes,
        'ble_classes': ble_classes,
        'packages': dict(packages),
        'uuids': all_uuids,
        'write_ops': all_write_ops,
        'commands': all_commands,
    }


def process_single_dex(dex_file: str, dex_index: int, dex_dir: Path, output_dir: Path, raw_dir: Path,
                        skip_jadx: bool = False, verbose: bool = False) -> Optional[dict]:
    """
    Process a single DEX file through the entire pipeline

    Args:
        dex_file: DEX filename (e.g., "classes.dex")
        dex_index: Index number (1-8)
        dex_dir: Directory containing DEX files
        output_dir: Output directory for markdown
        raw_dir: Output directory for raw Java files
        skip_jadx: Skip JADX decompilation (use existing)
        verbose: Print detailed output

    Returns:
        Analysis result dict or None if failed
    """
    print(f"\n{'='*70}")
    print(f"Processing {dex_file} ({dex_index}/8)")
    print(f"{'='*70}")

    dex_path = dex_dir / dex_file
    raw_output = raw_dir / f"classes{dex_index}"
    md_output = output_dir / f"classes{dex_index}.md"

    # Get file size
    file_size_mb = dex_path.stat().st_size / (1024 * 1024) if dex_path.exists() else 0

    # Step 1: JADX Decompilation
    if not skip_jadx:
        print("\n[1/3] JADX Decompilation")
        success = run_jadx_decompile(dex_path, raw_output, verbose)
        if not success:
            print(f"  Skipping {dex_file} due to decompilation failure")
            return None
    else:
        print("\n[1/3] JADX Decompilation (SKIPPED - using existing)")
        if not raw_output.exists():
            print(f"  ERROR: Raw output directory not found: {raw_output}")
            return None

    # Step 2: Analyze Java Code
    print("\n[2/3] Java Code Analysis")
    analysis_result = analyze_java_directory(raw_output, verbose)

    if not analysis_result:
        print(f"  Skipping {dex_file} due to analysis failure")
        return None

    # Update file size in stats
    analysis_result['stats'].file_size_mb = file_size_mb

    # Step 3: Generate Markdown
    print("\n[3/3] Markdown Generation")
    print(f"  Generating {md_output.name}...")

    markdown_content = generate_dex_markdown(analysis_result, dex_file, dex_index)

    # Write markdown file
    md_output.write_text(markdown_content, encoding='utf-8')

    print(f"  OK Written to {md_output}")

    return analysis_result


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Analyze DEX files with JADX and generate markdown documentation"
    )
    parser.add_argument(
        '--dex-file',
        help="Process only this DEX file (e.g., 'classes.dex')",
        default=None
    )
    parser.add_argument(
        '--dex-dir',
        type=Path,
        help=f"DEX files directory (default: {DEX_DIR})",
        default=DEX_DIR
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        help=f"Output directory (default: {OUTPUT_DIR})",
        default=OUTPUT_DIR
    )
    parser.add_argument(
        '--skip-jadx',
        action='store_true',
        help="Skip JADX decompilation (use existing Java files)"
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help="Verbose output"
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help="Test mode: process only classes7.dex (smallest file)"
    )

    args = parser.parse_args()

    # Use local variables for paths (override module defaults)
    dex_dir = args.dex_dir
    output_dir = args.output_dir
    raw_dir = output_dir / "raw"

    # Create output directories
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    print("="*70)
    print("  Cync DEX Analysis Pipeline")
    print("="*70)
    print(f"DEX Directory: {dex_dir}")
    print(f"Output Directory: {output_dir}")
    print(f"JADX Path: {JADX_PATH}")
    print()

    # Determine which files to process
    if args.test:
        files_to_process = [("classes7.dex", 7)]
        print("TEST MODE: Processing only classes7.dex")
    elif args.dex_file:
        # Find index
        try:
            idx = DEX_FILES.index(args.dex_file) + 1
            files_to_process = [(args.dex_file, idx)]
        except ValueError:
            print(f"ERROR: Unknown DEX file: {args.dex_file}")
            print(f"Valid files: {', '.join(DEX_FILES)}")
            return 1
    else:
        files_to_process = [(f, i+1) for i, f in enumerate(DEX_FILES)]

    # Process each DEX file
    all_results = []
    failed_files = []

    for dex_file, dex_index in files_to_process:
        result = process_single_dex(
            dex_file,
            dex_index,
            dex_dir,
            output_dir,
            raw_dir,
            skip_jadx=args.skip_jadx,
            verbose=args.verbose
        )

        if result:
            all_results.append((dex_file, dex_index, result))
        else:
            failed_files.append(dex_file)

    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Successfully processed: {len(all_results)}/{len(files_to_process)} DEX files")

    if failed_files:
        print(f"\nFailed files:")
        for f in failed_files:
            print(f"  - {f}")

    if all_results:
        print(f"\nGenerated markdown files:")
        for dex_file, dex_idx, _ in all_results:
            md_file = output_dir / f"classes{dex_idx}.md"
            print(f"  - {md_file}")

        # Generate index files if processing multiple DEX files
        if len(all_results) > 1:
            print(f"\nGenerating index files...")
            try:
                from create_index import generate_all_index_files
                generate_all_index_files(all_results, output_dir)
                print(f"  OK INDEX.md")
                print(f"  OK BLE_REFERENCE.md")
                print(f"  OK SEARCH_GUIDE.md")
            except Exception as e:
                print(f"  WARNING: Could not generate index files: {e}")

    print(f"\n{'='*70}")
    print(f"Output directory: {output_dir}")
    print(f"{'='*70}\n")

    return 0 if not failed_files else 1


if __name__ == "__main__":
    sys.exit(main())
