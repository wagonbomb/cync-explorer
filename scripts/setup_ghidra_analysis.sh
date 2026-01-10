#!/bin/bash
# Setup Ghidra analysis for Cync BLE native libraries

echo "=============================================================================="
echo "CYNC BLE NATIVE LIBRARY ANALYSIS SETUP"
echo "=============================================================================="

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
GHIDRA_DIR="$ROOT_DIR/artifacts/ghidra_analysis"
LIBS_DIR="$ROOT_DIR/artifacts/apk_extracted/lib/arm64-v8a"
SCRIPT_DIR="$ROOT_DIR/scripts/ghidra"

# Target libraries
TARGET_LIBS=(
    "libBleLib.so"            # 16KB - Primary BLE library
    "libCHIPController.so"    # 27MB - Matter/CHIP protocol
    "libSetupPayloadParser.so" # 225KB - Setup/provisioning parser
)

echo ""
echo "Step 1: Extract target libraries"
echo "=============================================================================="

mkdir -p "$GHIDRA_DIR/libraries"
mkdir -p "$SCRIPT_DIR"

for lib in "${TARGET_LIBS[@]}"; do
    if [ -f "$LIBS_DIR/$lib" ]; then
        cp "$LIBS_DIR/$lib" "$GHIDRA_DIR/libraries/"
        size=$(ls -lh "$LIBS_DIR/$lib" | awk '{print $5}')
        echo "OK Copied: $lib ($size)"
    else
        echo "WARN Not found: $lib"
    fi
done

echo ""
echo "Step 2: Install Ghidra (if needed)"
echo "=============================================================================="

if ! command -v ghidraRun &> /dev/null; then
    echo "Ghidra not found in PATH"
    echo ""
    echo "To install Ghidra:"
    echo "  1. Download from: https://ghidra-sre.org/"
    echo "  2. Extract to a directory"
    echo "  3. Add to PATH or run directly"
    echo ""
    echo "For MCP server, use Ghidra's headless analyzer"
else
    echo "OK Ghidra found: $(which ghidraRun)"
fi

echo ""
echo "Step 3: Create Ghidra project runner"
echo "=============================================================================="

cat > "$GHIDRA_DIR/analyze_libs.sh" << 'EOF'
#!/bin/bash
# Ghidra headless analysis script

GHIDRA_HOME=${GHIDRA_HOME:-"/opt/ghidra"}
PROJECT_DIR="$(pwd)/cync_project"
PROJECT_NAME="CyncBLE"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$ROOT_DIR/scripts/ghidra"

if [ ! -d "$GHIDRA_HOME" ]; then
    echo "Error: GHIDRA_HOME not set or directory doesn't exist"
    echo "Set it with: export GHIDRA_HOME=/path/to/ghidra"
    exit 1
fi

mkdir -p "$PROJECT_DIR"

# Analyze each library
for lib in libraries/*.so; do
    libname=$(basename "$lib")
    echo "Analyzing: $libname"
    
    "$GHIDRA_HOME/support/analyzeHeadless" \
        "$PROJECT_DIR" \
        "$PROJECT_NAME" \
        -import "$lib" \
        -scriptPath "$SCRIPT_DIR" \
        -postScript FindBLEFunctions.py \
        -overwrite \
        -deleteProject
done
EOF

chmod +x "$GHIDRA_DIR/analyze_libs.sh"

echo ""
echo "Step 4: Ensure BLE search script exists"
echo "=============================================================================="

cat > "$SCRIPT_DIR/FindBLEFunctions.py" << 'EOF'
# Ghidra script to find BLE-related functions
# @category BLE

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import Function

def find_ble_strings():
    """Find BLE-related strings"""
    print("\n=== BLE-RELATED STRINGS ===")
    
    strings_to_find = [
        "2adb", "2add", "2ade",  # Mesh UUIDs
        "bluetooth", "gatt", "characteristic",
        "000501", "3100", "3101", "320119",  # Command sequences
        "mesh", "provisioning", "proxy"
    ]
    
    for s in strings_to_find:
        addresses = findBytes(None, s, 100)  # Find up to 100 occurrences
        if addresses:
            print(f"\nFound '{s}' at {len(addresses)} locations:")
            for addr in addresses[:5]:  # Show first 5
                print(f"  {addr}")

def find_write_functions():
    """Find functions that might write to BLE characteristics"""
    print("\n=== POTENTIAL BLE WRITE FUNCTIONS ===")
    
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)
    
    for func in functions:
        name = func.getName().lower()
        if any(keyword in name for keyword in ["write", "send", "transmit", "char"]):
            print(f"  {func.getName()} @ {func.getEntryPoint()}")
            
            # Check for references to our UUIDs
            body = func.getBody()
            # Would need to check instructions here

def main():
    print("=" * 80)
    print("CYNC BLE LIBRARY ANALYSIS")
    print("=" * 80)
    print(f"Program: {currentProgram.getName()}")
    print(f"Architecture: {currentProgram.getLanguage().getProcessor()}")
    
    find_ble_strings()
    find_write_functions()
    
    print("\n" + "=" * 80)
    print("Analysis complete. Check output above for BLE-related code.")
    print("=" * 80)

if __name__ == "__main__":
    main()
EOF

echo "OK Created Ghidra analysis script"

echo ""
echo "=============================================================================="
echo "SETUP COMPLETE"
echo "=============================================================================="
echo ""
echo "Extracted libraries:"
ls -lh "$GHIDRA_DIR/libraries/" 2>/dev/null || echo "  (none yet - run extraction first)"
echo ""
echo "Next steps:"
echo ""
echo "  1. Install Ghidra from https://ghidra-sre.org/"
echo "  2. Set GHIDRA_HOME: export GHIDRA_HOME=/path/to/ghidra"
echo "  3. Run analysis: cd $GHIDRA_DIR && ./analyze_libs.sh"
echo ""
echo "For quick manual analysis:"
echo "  ghidraRun"
echo "  File -> New Project -> cync_ble_analysis"
echo "  Import -> $GHIDRA_DIR/libraries/libBleLib.so"
echo "  Analyze (accept defaults)"
echo "  Window -> Functions -> Search for 'write', 'gatt', etc."
echo ""
echo "For MCP server:"
echo "  .\\scripts\\run_ghidra_mcp.bat"
echo ""
