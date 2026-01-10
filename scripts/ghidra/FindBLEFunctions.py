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
