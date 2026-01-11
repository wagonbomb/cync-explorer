#!/usr/bin/env python3
"""
Markdown Generation Module
Converts analysis results to structured markdown documentation
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path
from collections import defaultdict
from datetime import datetime


@dataclass
class AnalysisStats:
    """Statistics about the DEX analysis"""
    total_classes: int = 0
    total_methods: int = 0
    total_fields: int = 0
    total_packages: int = 0
    ble_classes: int = 0
    ble_methods: int = 0
    uuid_count: int = 0
    write_op_count: int = 0
    command_count: int = 0
    file_size_mb: float = 0.0


class MarkdownGenerator:
    """Generate structured markdown documentation from analysis results"""

    def __init__(self):
        self.content = []

    def add(self, text: str = ""):
        """Add text to markdown content"""
        self.content.append(text)

    def add_header(self, text: str, level: int = 1):
        """Add a header"""
        self.add(f"{'#' * level} {text}")
        self.add()

    def add_section(self, title: str, content: str = "", level: int = 2):
        """Add a section with title and optional content"""
        self.add_header(title, level)
        if content:
            self.add(content)
            self.add()

    def add_toc(self, sections: List[str]):
        """Add table of contents"""
        self.add_header("Table of Contents", 2)
        for i, section in enumerate(sections, 1):
            anchor = section.lower().replace(' ', '-').replace('/', '')
            self.add(f"{i}. [{section}](#{anchor})")
        self.add()

    def add_table(self, headers: List[str], rows: List[List[str]]):
        """Add a markdown table"""
        if not rows:
            self.add("*No data available*")
            self.add()
            return

        # Header row
        self.add("| " + " | ".join(headers) + " |")

        # Separator row
        self.add("| " + " | ".join(["---"] * len(headers)) + " |")

        # Data rows
        for row in rows:
            self.add("| " + " | ".join(str(cell) for cell in row) + " |")

        self.add()

    def add_code_block(self, code: str, language: str = ""):
        """Add a code block"""
        self.add(f"```{language}")
        self.add(code.strip())
        self.add("```")
        self.add()

    def add_collapsible(self, title: str, content: str):
        """Add a collapsible section"""
        self.add("<details>")
        self.add(f"<summary>{title}</summary>")
        self.add()
        self.add(content)
        self.add()
        self.add("</details>")
        self.add()

    def to_string(self) -> str:
        """Convert to markdown string"""
        return '\n'.join(self.content)


def generate_dex_markdown(analysis_result: dict, dex_name: str, dex_index: int) -> str:
    """
    Generate comprehensive markdown documentation for a DEX file

    Args:
        analysis_result: Dict containing:
            - stats: AnalysisStats
            - all_classes: List[ClassInfo]
            - ble_classes: List[ClassInfo]
            - packages: Dict[package_name, List[ClassInfo]]
            - uuids: List[UUIDDefinition]
            - write_ops: List[WriteOperation]
            - commands: List[CommandSequence]
        dex_name: Name of DEX file (e.g., "classes.dex")
        dex_index: Index number (1-8)

    Returns:
        Markdown string
    """
    md = MarkdownGenerator()

    stats = analysis_result['stats']
    all_classes = analysis_result['all_classes']
    ble_classes = analysis_result['ble_classes']
    packages = analysis_result['packages']
    uuids = analysis_result['uuids']
    write_ops = analysis_result['write_ops']
    commands = analysis_result['commands']

    # Header
    md.add_header(f"DEX Analysis: {dex_name}", 1)
    md.add()
    md.add(f"**File Size**: {stats.file_size_mb:.1f} MB")
    md.add(f"**Total Classes**: {stats.total_classes:,}")
    md.add(f"**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    md.add(f"**Tool**: JADX + Custom Python Analyzer")
    md.add()
    md.add("---")
    md.add()

    # Table of Contents
    toc_sections = [
        "Overview Statistics",
        "BLE-Related Classes",
        "Package Structure",
        "String Constants & UUIDs",
        "BLE Write Operations",
        "Command Sequences",
        "Method Index",
        "Full Class List"
    ]
    md.add_toc(toc_sections)
    md.add("---")
    md.add()

    # Overview Statistics
    md.add_section("Overview Statistics")
    stats_rows = [
        ["Total Classes", f"{stats.total_classes:,}"],
        ["Total Methods", f"{stats.total_methods:,}"],
        ["Total Fields", f"{stats.total_fields:,}"],
        ["Total Packages", f"{stats.total_packages:,}"],
        ["BLE-Related Classes", f"{stats.ble_classes:,}"],
        ["UUIDs Found", f"{stats.uuid_count:,}"],
        ["BLE Write Operations", f"{stats.write_op_count:,}"],
        ["Command Sequences", f"{stats.command_count:,}"],
    ]
    md.add_table(["Metric", "Count"], stats_rows)

    # BLE-Related Classes
    md.add_section("BLE-Related Classes")

    if not ble_classes:
        md.add("*No BLE-related classes found in this DEX file.*")
        md.add()
    else:
        # Sort by priority (highest first)
        sorted_ble = sorted(ble_classes, key=lambda c: c.ble_priority, reverse=True)

        md.add(f"Found {len(sorted_ble)} BLE-related classes:")
        md.add()

        for cls in sorted_ble:
            priority_label = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(cls.ble_priority, "")

            md.add_header(f"{cls.class_name} [{priority_label}]", 3)
            md.add()

            # Basic info
            md.add(f"- **Full Name**: `{cls.full_name}`")
            md.add(f"- **Package**: `{cls.package}`")
            if cls.superclass:
                md.add(f"- **Extends**: `{cls.superclass}`")
            if cls.interfaces:
                md.add(f"- **Implements**: `{', '.join(cls.interfaces)}`")
            md.add(f"- **Methods**: {len(cls.methods)}")
            md.add(f"- **Fields**: {len(cls.fields)}")
            md.add(f"- **Source**: `{Path(cls.file_path).relative_to(Path(cls.file_path).parents[3])}`")
            md.add()

            # Key methods (first 10)
            if cls.methods:
                md.add("**Key Methods**:")
                for method in cls.methods[:10]:
                    md.add(f"  - `{method}()`")
                if len(cls.methods) > 10:
                    md.add(f"  - *(... and {len(cls.methods) - 10} more)*")
                md.add()

            # Notable strings (UUIDs, BLE keywords)
            notable_strings = [s for s in cls.strings if any(
                kw in s.lower() for kw in ['bluetooth', 'gatt', 'mesh', 'uuid', '2adb', '2add', '2ade', '1912']
            )]

            if notable_strings:
                md.add("**Notable Strings**:")
                for s in notable_strings[:5]:
                    md.add(f'  - `"{s}"`')
                if len(notable_strings) > 5:
                    md.add(f"  - *(... and {len(notable_strings) - 5} more)*")
                md.add()

            md.add("---")
            md.add()

    # Package Structure
    md.add_section("Package Structure")

    if packages:
        # Group packages by root
        root_packages = defaultdict(list)
        for pkg_name in packages.keys():
            root = pkg_name.split('.')[0] if '.' in pkg_name else pkg_name
            root_packages[root].append(pkg_name)

        md.add("### Package Hierarchy")
        md.add()
        md.add("```")

        for root in sorted(root_packages.keys()):
            pkg_list = sorted(root_packages[root])
            class_count_total = sum(len(packages[p]) for p in pkg_list)

            md.add(f"{root}/ ({class_count_total} classes)")

            # Show sub-packages (limit to top 10 per root)
            for pkg in pkg_list[:10]:
                indent = "  " * (pkg.count('.'))
                class_count = len(packages[pkg])
                short_name = pkg.split('.')[-1]
                md.add(f"{indent}├── {short_name}/ ({class_count} classes)")

            if len(pkg_list) > 10:
                md.add(f"  └── ... and {len(pkg_list) - 10} more packages")

            md.add()

        md.add("```")
        md.add()

        # Top packages table
        md.add("### Top 20 Packages by Class Count")
        md.add()

        pkg_counts = [(pkg, len(classes)) for pkg, classes in packages.items()]
        pkg_counts.sort(key=lambda x: x[1], reverse=True)

        pkg_rows = [[pkg, count] for pkg, count in pkg_counts[:20]]
        md.add_table(["Package", "Classes"], pkg_rows)

    # String Constants & UUIDs
    md.add_section("String Constants & UUIDs")

    if uuids:
        md.add("### UUID Definitions Found")
        md.add()

        # Group UUIDs by value (show where each UUID appears)
        uuid_locations = defaultdict(list)
        for uuid_def in uuids:
            uuid_locations[uuid_def.uuid].append(uuid_def)

        uuid_rows = []
        for uuid_str, locations in sorted(uuid_locations.items()):
            # Get file names
            files = set(Path(loc.file_path).name for loc in locations if loc.file_path)
            files_str = ', '.join(sorted(files)[:3])
            if len(files) > 3:
                files_str += f", ... (+{len(files) - 3} more)"

            # Determine purpose (based on known UUIDs)
            purpose = "Unknown"
            if "2adb" in uuid_str:
                purpose = "Mesh Provisioning In"
            elif "2add" in uuid_str:
                purpose = "Mesh Proxy In"
            elif "2ade" in uuid_str:
                purpose = "Mesh Proxy Out"
            elif "1912" in uuid_str:
                purpose = "Telink Command"
            elif "00010203-0405-0607-0809" in uuid_str:
                purpose = "Telink Service"

            uuid_rows.append([uuid_str, purpose, len(locations), files_str])

        md.add_table(["UUID", "Purpose", "Occurrences", "Files"], uuid_rows)
    else:
        md.add("*No UUIDs found in this DEX file.*")
        md.add()

    # BLE Write Operations
    md.add_section("BLE Write Operations")

    if write_ops:
        md.add(f"Found {len(write_ops)} BLE write operations:")
        md.add()

        # Group by file
        ops_by_file = defaultdict(list)
        for op in write_ops:
            file_name = Path(op.file_path).name if op.file_path else "Unknown"
            ops_by_file[file_name].append(op)

        for file_name in sorted(ops_by_file.keys())[:10]:  # Limit to top 10 files
            ops = ops_by_file[file_name]
            md.add_header(file_name, 4)

            for op in ops[:5]:  # Limit to 5 ops per file
                md.add(f"- **Line {op.line_number}**: `{op.method_name}({op.characteristic_var})`")

                if op.code_snippet:
                    # Show snippet in collapsible
                    md.add()
                    md.add_collapsible("Show code snippet", md_code_block(op.code_snippet, "java"))

            if len(ops) > 5:
                md.add(f"- *(... and {len(ops) - 5} more operations)*")
            md.add()
    else:
        md.add("*No BLE write operations found in this DEX file.*")
        md.add()

    # Command Sequences
    md.add_section("Command Sequences")

    if commands:
        md.add(f"Found {len(commands)} potential command byte sequences:")
        md.add()

        # Known command patterns from HCI analysis
        known_patterns = {
            "000501": "Handshake Start",
            "000001": "Key Exchange",
            "040000": "Session ID",
            "3100": "Sync 1",
            "3101": "Sync 2",
            "3102": "Sync 3",
            "3103": "Sync 4",
            "3104": "Sync 5",
            "320119": "Finalize",
        }

        cmd_rows = []
        for cmd in commands[:20]:  # Limit to top 20
            hex_display = ' '.join([cmd.bytes_hex[i:i+2] for i in range(0, len(cmd.bytes_hex), 2)])
            file_name = Path(cmd.file_path).name if cmd.file_path else "Unknown"

            # Check if matches known pattern
            purpose = "Unknown"
            for pattern, desc in known_patterns.items():
                if pattern.upper() in cmd.bytes_hex:
                    purpose = desc
                    break

            var_name = cmd.variable_name if cmd.variable_name else "-"

            cmd_rows.append([hex_display, purpose, var_name, f"{file_name}:{cmd.line_number}"])

        md.add_table(["Bytes (Hex)", "Possible Purpose", "Variable", "Location"], cmd_rows)

        if len(commands) > 20:
            md.add(f"*... and {len(commands) - 20} more command sequences*")
            md.add()
    else:
        md.add("*No command sequences found in this DEX file.*")
        md.add()

    # Method Index
    md.add_section("Method Index")

    if ble_classes:
        # Categorize methods
        write_methods = []
        read_methods = []
        callback_methods = []
        other_methods = []

        for cls in ble_classes:
            for method in cls.methods:
                method_lower = method.lower()
                if 'write' in method_lower or 'send' in method_lower:
                    write_methods.append((method, cls.class_name))
                elif 'read' in method_lower or 'get' in method_lower:
                    read_methods.append((method, cls.class_name))
                elif 'callback' in method_lower or 'on' in method_lower[:2]:
                    callback_methods.append((method, cls.class_name))
                else:
                    other_methods.append((method, cls.class_name))

        if write_methods:
            md.add("### Write/Send Methods")
            md.add()
            for method, cls_name in write_methods[:15]:
                md.add(f"- `{method}()` in `{cls_name}`")
            if len(write_methods) > 15:
                md.add(f"- *(... and {len(write_methods) - 15} more)*")
            md.add()

        if callback_methods:
            md.add("### Callback/Event Methods")
            md.add()
            for method, cls_name in callback_methods[:15]:
                md.add(f"- `{method}()` in `{cls_name}`")
            if len(callback_methods) > 15:
                md.add(f"- *(... and {len(callback_methods) - 15} more)*")
            md.add()
    else:
        md.add("*No methods to index (no BLE classes found)*")
        md.add()

    # Full Class List
    md.add_section("Full Class List")

    if all_classes:
        # Build full class list string
        class_list_content = []
        class_list_content.append(f"Total: {len(all_classes)} classes")
        class_list_content.append("")

        # Group by package
        for pkg_name in sorted(packages.keys())[:100]:  # Limit to top 100 packages
            classes_in_pkg = packages[pkg_name]
            class_list_content.append(f"### {pkg_name}")
            class_list_content.append("")
            for cls in sorted(classes_in_pkg, key=lambda c: c.class_name):
                class_list_content.append(f"- `{cls.full_name}`")
            class_list_content.append("")

        if len(packages) > 100:
            class_list_content.append(f"*(... and {len(packages) - 100} more packages)*")

        md.add_collapsible(
            f"Click to expand full class list ({len(all_classes)} classes)",
            '\n'.join(class_list_content)
        )
    else:
        md.add("*No classes found*")
        md.add()

    return md.to_string()


def md_code_block(code: str, language: str = "") -> str:
    """Helper to create a code block string"""
    return f"```{language}\n{code.strip()}\n```"


if __name__ == "__main__":
    # Test with dummy data
    from extract_ble_code import AnalysisStats, ClassInfo

    dummy_stats = AnalysisStats(
        total_classes=1000,
        total_methods=5000,
        ble_classes=10,
        uuid_count=4,
        file_size_mb=10.5
    )

    dummy_class = ClassInfo(
        class_name="BleManager",
        package="com.ge.cync.bluetooth",
        full_name="com.ge.cync.bluetooth.BleManager",
        file_path="/test/BleManager.java",
        superclass="Object",
        interfaces=["BluetoothGattCallback"],
        methods=["connectToDevice", "writeCharacteristic"],
        is_ble_related=True,
        ble_priority=4
    )

    dummy_result = {
        'stats': dummy_stats,
        'all_classes': [dummy_class],
        'ble_classes': [dummy_class],
        'packages': {"com.ge.cync.bluetooth": [dummy_class]},
        'uuids': [],
        'write_ops': [],
        'commands': []
    }

    md = generate_dex_markdown(dummy_result, "classes.dex", 1)
    print(md)
