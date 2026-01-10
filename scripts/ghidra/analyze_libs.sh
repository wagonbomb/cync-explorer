#!/bin/bash
# Ghidra headless analysis helper (wrapper)

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_DIR="$ROOT_DIR/artifacts/ghidra_analysis"
SCRIPT_DIR="$ROOT_DIR/scripts/ghidra"

GHIDRA_HOME=${GHIDRA_HOME:-"/opt/ghidra"}
PROJECT_DIR="$WORK_DIR/cync_project"
PROJECT_NAME="CyncBLE"

if [ ! -d "$GHIDRA_HOME" ]; then
    echo "Error: GHIDRA_HOME not set or directory doesn't exist"
    echo "Set it with: export GHIDRA_HOME=/path/to/ghidra"
    exit 1
fi

mkdir -p "$PROJECT_DIR"

# Analyze each library
for lib in "$WORK_DIR"/libraries/*.so; do
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
