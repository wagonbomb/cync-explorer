#!/usr/bin/env python3
"""
BLE-Specific Code Extraction Module
Extracts BLE protocol details from decompiled Java source
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from pathlib import Path


@dataclass
class UUIDDefinition:
    """Represents a UUID found in code"""
    uuid: str
    variable_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    context: Optional[str] = None  # Surrounding code context


@dataclass
class WriteOperation:
    """Represents a BLE write operation"""
    method_name: str
    characteristic_var: str
    data_var: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None


@dataclass
class CommandSequence:
    """Represents a byte array that looks like a command"""
    bytes_hex: str  # Hex representation of bytes
    variable_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    context: Optional[str] = None


@dataclass
class ClassInfo:
    """Information about a Java class"""
    class_name: str
    package: str
    full_name: str
    file_path: str
    superclass: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    is_ble_related: bool = False
    ble_priority: int = 0  # Higher = more relevant
    content: Optional[str] = None  # Full source code


# BLE-related keywords for classification
BLE_KEYWORDS = {
    'critical': [  # Highest priority
        'BluetoothGatt', 'BluetoothGattCallback', 'BluetoothGattCharacteristic',
        'BluetoothGattService', 'mesh', 'provision', 'telink'
    ],
    'high': [  # High priority
        'bluetooth', 'gatt', 'ble', 'characteristic', 'service',
        '2adb', '2add', '2ade', '1912', '00010203-0405-0607-0809'
    ],
    'medium': [  # Medium priority
        'scan', 'connect', 'notify', 'write', 'read'
    ]
}

# UUID patterns
UUID_PATTERNS = [
    # Full UUID format: "00002adb-0000-1000-8000-00805f9b34fb"
    r'"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"',
    # UUID.fromString()
    r'UUID\.fromString\(["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']\)',
    # Short format: 0x2adb
    r'0x([0-9a-fA-F]{4})\b',
]


def extract_uuid_definitions(java_content: str, file_path: str = "") -> List[UUIDDefinition]:
    """
    Extract UUID definitions from Java source code

    Looks for:
    - String literals containing UUIDs
    - UUID.fromString() calls
    - Hex constants that might be UUIDs
    """
    uuids = []
    lines = java_content.split('\n')

    for line_num, line in enumerate(lines, 1):
        # Full UUID strings
        for pattern in UUID_PATTERNS[:2]:  # Full UUID patterns
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                uuid_str = match.group(1).lower()

                # Try to find variable name
                var_match = re.search(r'(\w+)\s*=', line)
                var_name = var_match.group(1) if var_match else None

                # Get context (surrounding lines)
                context_start = max(0, line_num - 2)
                context_end = min(len(lines), line_num + 2)
                context = '\n'.join(lines[context_start:context_end])

                uuids.append(UUIDDefinition(
                    uuid=uuid_str,
                    variable_name=var_name,
                    file_path=file_path,
                    line_number=line_num,
                    context=context
                ))

    return uuids


def extract_write_operations(java_content: str, file_path: str = "") -> List[WriteOperation]:
    """
    Find all BluetoothGatt.writeCharacteristic() calls

    Patterns to match:
    - gatt.writeCharacteristic(characteristic)
    - characteristic.setValue(bytes)
    """
    operations = []
    lines = java_content.split('\n')

    # Pattern for writeCharacteristic calls
    write_pattern = r'(\w+)\.writeCharacteristic\s*\(([^)]+)\)'

    for line_num, line in enumerate(lines, 1):
        matches = re.finditer(write_pattern, line)
        for match in matches:
            gatt_var = match.group(1)
            char_var = match.group(2).strip()

            # Extract code snippet (5 lines before and after)
            snippet_start = max(0, line_num - 5)
            snippet_end = min(len(lines), line_num + 5)
            snippet = '\n'.join(lines[snippet_start:snippet_end])

            operations.append(WriteOperation(
                method_name='writeCharacteristic',
                characteristic_var=char_var,
                file_path=file_path,
                line_number=line_num,
                code_snippet=snippet
            ))

    # Pattern for setValue calls
    setvalue_pattern = r'(\w+)\.setValue\s*\(([^)]+)\)'

    for line_num, line in enumerate(lines, 1):
        matches = re.finditer(setvalue_pattern, line)
        for match in matches:
            char_var = match.group(1)
            data_var = match.group(2).strip()

            snippet_start = max(0, line_num - 5)
            snippet_end = min(len(lines), line_num + 5)
            snippet = '\n'.join(lines[snippet_start:snippet_end])

            operations.append(WriteOperation(
                method_name='setValue',
                characteristic_var=char_var,
                data_var=data_var,
                file_path=file_path,
                line_number=line_num,
                code_snippet=snippet
            ))

    return operations


def extract_command_sequences(java_content: str, file_path: str = "") -> List[CommandSequence]:
    """
    Find byte array constants that look like BLE commands

    Pattern: new byte[]{0x00, 0x05, 0x01, ...}
    Pattern: {(byte) 0, (byte) 5, (byte) 1, ...}
    """
    commands = []
    lines = java_content.split('\n')

    # Pattern for byte array initialization
    # Matches: new byte[]{0x00, 0x01, ...} or {0x00, 0x01, ...}
    byte_array_pattern = r'(?:new\s+byte\s*\[\s*\]\s*)?\{([0x0-9a-fA-F,\s\(\)bytecastBYTECAST]+)\}'

    for line_num, line in enumerate(lines, 1):
        matches = re.finditer(byte_array_pattern, line)
        for match in matches:
            byte_content = match.group(1)

            # Extract hex values
            hex_values = re.findall(r'0x([0-9a-fA-F]{2})', byte_content)

            # Skip if too short (less than 3 bytes) or too long (more than 50 bytes)
            if len(hex_values) < 3 or len(hex_values) > 50:
                continue

            bytes_hex = ''.join(hex_values).upper()

            # Try to find variable name
            var_match = re.search(r'(\w+)\s*=', line)
            var_name = var_match.group(1) if var_match else None

            # Get context
            context_start = max(0, line_num - 2)
            context_end = min(len(lines), line_num + 2)
            context = '\n'.join(lines[context_start:context_end])

            commands.append(CommandSequence(
                bytes_hex=bytes_hex,
                variable_name=var_name,
                file_path=file_path,
                line_number=line_num,
                context=context
            ))

    return commands


def analyze_java_class(file_path: Path) -> ClassInfo:
    """
    Analyze a single Java file and extract class information
    """
    content = file_path.read_text(encoding='utf-8', errors='ignore')

    # Extract package
    package_match = re.search(r'package\s+([\w.]+)\s*;', content)
    package = package_match.group(1) if package_match else ""

    # Extract class name
    class_match = re.search(r'(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)', content)
    if not class_match:
        # Try interface
        class_match = re.search(r'(?:public\s+)?interface\s+(\w+)', content)

    if not class_match:
        # Not a valid class file
        return None

    class_name = class_match.group(1)
    full_name = f"{package}.{class_name}" if package else class_name

    # Extract superclass
    extends_match = re.search(r'extends\s+([\w.<>]+)', content)
    superclass = extends_match.group(1) if extends_match else None

    # Extract interfaces
    implements_match = re.search(r'implements\s+([\w.<>,\s]+)', content)
    interfaces = []
    if implements_match:
        interfaces = [i.strip() for i in implements_match.group(1).split(',')]

    # Extract methods (simplified - just names)
    methods = re.findall(r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)', content)

    # Extract fields
    fields = re.findall(r'(?:public|private|protected|static|final|\s)+[\w<>\[\]]+\s+(\w+)\s*[;=]', content)

    # Extract string literals
    strings = re.findall(r'"([^"]*)"', content)

    # Determine if BLE-related and priority
    is_ble, priority = classify_ble_relevance(full_name, content)

    class_info = ClassInfo(
        class_name=class_name,
        package=package,
        full_name=full_name,
        file_path=str(file_path),
        superclass=superclass,
        interfaces=interfaces,
        methods=methods,
        fields=fields,
        strings=strings,
        is_ble_related=is_ble,
        ble_priority=priority,
        content=content
    )

    return class_info


def classify_ble_relevance(full_name: str, content: str) -> Tuple[bool, int]:
    """
    Classify if a class is BLE-related and assign priority

    Returns: (is_ble_related, priority_score)
    Priority: 0 = not BLE, 1 = low, 2 = medium, 3 = high, 4 = critical
    """
    content_lower = content.lower()
    name_lower = full_name.lower()

    # Check critical keywords (priority 4)
    for keyword in BLE_KEYWORDS['critical']:
        if keyword.lower() in name_lower or keyword.lower() in content_lower:
            return (True, 4)

    # Check high keywords (priority 3)
    high_count = sum(1 for kw in BLE_KEYWORDS['high'] if kw.lower() in content_lower)
    if high_count >= 2:
        return (True, 3)
    elif high_count == 1:
        return (True, 2)

    # Check medium keywords (priority 1)
    medium_count = sum(1 for kw in BLE_KEYWORDS['medium'] if kw.lower() in content_lower)
    if medium_count >= 3:
        return (True, 1)

    return (False, 0)


def extract_all_from_class(file_path: Path) -> dict:
    """
    Extract all BLE-related information from a single Java file

    Returns dict with:
    - class_info: ClassInfo object
    - uuids: List[UUIDDefinition]
    - write_ops: List[WriteOperation]
    - commands: List[CommandSequence]
    """
    class_info = analyze_java_class(file_path)

    if not class_info:
        return None

    content = class_info.content
    file_path_str = str(file_path)

    result = {
        'class_info': class_info,
        'uuids': extract_uuid_definitions(content, file_path_str),
        'write_ops': extract_write_operations(content, file_path_str),
        'commands': extract_command_sequences(content, file_path_str),
    }

    return result


if __name__ == "__main__":
    # Test with a sample file
    import sys
    if len(sys.argv) > 1:
        test_file = Path(sys.argv[1])
        if test_file.exists():
            result = extract_all_from_class(test_file)
            if result:
                print(f"\nClass: {result['class_info'].full_name}")
                print(f"BLE Related: {result['class_info'].is_ble_related} (priority: {result['class_info'].ble_priority})")
                print(f"UUIDs found: {len(result['uuids'])}")
                print(f"Write operations: {len(result['write_ops'])}")
                print(f"Command sequences: {len(result['commands'])}")

                if result['uuids']:
                    print("\nUUIDs:")
                    for uuid in result['uuids']:
                        print(f"  {uuid.uuid} (line {uuid.line_number})")
        else:
            print(f"File not found: {test_file}")
    else:
        print("Usage: python extract_ble_code.py <java_file>")
