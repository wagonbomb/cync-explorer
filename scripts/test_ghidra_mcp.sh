#!/bin/bash
# Test Ghidra MCP Server

echo "============================================================================"
echo "TESTING GHIDRA MCP SERVER"
echo "============================================================================"
echo ""

cd "$(dirname "$0")/.."

# Create venv if needed
if [ ! -f ".venv/bin/python" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Install MCP
echo "Installing MCP SDK..."
.venv/bin/pip install -q mcp

echo ""
echo "Testing MCP server tools..."
echo ""

# Test: List libraries
echo "1. Testing list_libraries..."
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | .venv/bin/python src/ghidra_mcp_server.py 2>&1 | head -20

echo ""
echo "============================================================================"
echo "Server is ready! Use it with:"
echo "  - VS Code MCP extension"
echo "  - Or call tools directly via JSON-RPC"
echo "============================================================================"
