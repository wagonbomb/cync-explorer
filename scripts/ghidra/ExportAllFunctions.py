# Ghidra Script: Export all decompiled functions to a file
# Run this in Ghidra: Script Manager → Run
# @category Analysis

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os

OUTPUT_FILE = "C:/Users/Meow/Documents/Projects/cync-explorer/artifacts/ghidra_decompiled.txt"

def main():
    print("Starting decompilation export...")

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    output = []
    output.append("=" * 70)
    output.append("LIBBLELIB.SO DECOMPILED FUNCTIONS")
    output.append("=" * 70)
    output.append("")

    # Get all functions
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)

    for func in functions:
        name = func.getName()
        entry = func.getEntryPoint()

        output.append("-" * 70)
        output.append("FUNCTION: {}".format(name))
        output.append("Address: {}".format(entry))
        output.append("-" * 70)

        # Decompile
        results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())

        if results.decompileCompleted():
            decomp = results.getDecompiledFunction()
            if decomp:
                c_code = decomp.getC()
                output.append(c_code)
            else:
                output.append("(no decompilation available)")
        else:
            output.append("(decompilation failed: {})".format(results.getErrorMessage()))

        output.append("")

    # Write to file
    with open(OUTPUT_FILE, 'w') as f:
        f.write('\n'.join(output))

    print("Exported to: " + OUTPUT_FILE)
    print("Done!")

main()
