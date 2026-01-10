#!/usr/bin/env python3
"""
Ghidra MCP Server for Cync BLE Native Library Analysis
"""
import asyncio
import json
import subprocess
import os
import sys
from pathlib import Path
from typing import Any, Sequence

# Add MCP SDK to path
try:
    from mcp.server import Server, NotificationOptions
    from mcp.server.models import InitializationOptions
    import mcp.server.stdio
    import mcp.types as types
except ImportError:
    print("Error: MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

# Configuration
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GHIDRA_HOME = REPO_ROOT / "tools-local" / "ghidra-master"
GHIDRA_HOME = Path(os.environ.get("GHIDRA_INSTALL_DIR", str(DEFAULT_GHIDRA_HOME)))
PROJECT_DIR = REPO_ROOT / "artifacts" / "ghidra_analysis" / "cync_project"
LIBS_DIR = REPO_ROOT / "artifacts" / "ghidra_analysis" / "libraries"
SCRIPTS_DIR = REPO_ROOT / "scripts" / "ghidra"
DEFAULT_LOG_FILE = REPO_ROOT / "artifacts" / "logs" / "ghidra_mcp_server.runtime.log"
LOG_FILE = Path(os.environ.get("GHIDRA_MCP_LOG", str(DEFAULT_LOG_FILE)))

server = Server("ghidra-cync-ble")

def log_runtime(message: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(message.rstrip() + "\n")
    except Exception:
        pass

def run_ghidra_headless(command_args: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Run Ghidra headless analyzer"""
    ghidra_script = GHIDRA_HOME / "support" / "analyzeHeadless"
    if not ghidra_script.exists():
        ghidra_script = GHIDRA_HOME / "support" / "analyzeHeadless.bat"
    
    if not ghidra_script.exists():
        return "", "Ghidra analyzeHeadless not found", 1
    
    cmd = [str(ghidra_script)] + command_args
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(REPO_ROOT)
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1

def extract_ascii_strings(path: Path, min_len: int = 4) -> list[str]:
    data = path.read_bytes()
    results = []
    buf = bytearray()
    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                results.append(buf.decode("ascii", errors="ignore"))
            buf.clear()
    if len(buf) >= min_len:
        results.append(buf.decode("ascii", errors="ignore"))
    return results

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available Ghidra analysis tools"""
    return [
        types.Tool(
            name="analyze_library",
            description="Analyze a native library with Ghidra and import it into the project",
            inputSchema={
                "type": "object",
                "properties": {
                    "library_name": {
                        "type": "string",
                        "description": "Name of the library file (e.g., libBleLib.so)",
                    },
                },
                "required": ["library_name"],
            },
        ),
        types.Tool(
            name="find_functions",
            description="Search for functions by name pattern in analyzed libraries",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Pattern to search for (e.g., 'send', 'write', 'gatt')",
                    },
                },
                "required": ["pattern"],
            },
        ),
        types.Tool(
            name="get_function_decompile",
            description="Get decompiled C code for a specific function",
            inputSchema={
                "type": "object",
                "properties": {
                    "library_name": {
                        "type": "string",
                        "description": "Library name (e.g., libBleLib.so)",
                    },
                    "function_name": {
                        "type": "string",
                        "description": "Function name (e.g., trsmitr_send_pkg_encode)",
                    },
                },
                "required": ["library_name", "function_name"],
            },
        ),
        types.Tool(
            name="search_strings",
            description="Search for strings in a library",
            inputSchema={
                "type": "object",
                "properties": {
                    "library_name": {
                        "type": "string",
                        "description": "Library name",
                    },
                    "pattern": {
                        "type": "string",
                        "description": "String pattern to search for",
                    },
                },
                "required": ["library_name", "pattern"],
            },
        ),
        types.Tool(
            name="list_libraries",
            description="List all available libraries for analysis",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict[str, Any] | None
) -> Sequence[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution"""
    
    if name == "list_libraries":
        if not LIBS_DIR.exists():
            return [types.TextContent(type="text", text="No libraries found. Run scripts/setup_ghidra_analysis.sh first.")]
        
        libs = list(LIBS_DIR.glob("*.so"))
        if not libs:
            return [types.TextContent(type="text", text="No .so files in libraries directory.")]
        
        result = "Available libraries:\n\n"
        for lib in libs:
            size = lib.stat().st_size
            result += f"- {lib.name} ({size:,} bytes)\n"
        
        return [types.TextContent(type="text", text=result)]
    
    elif name == "analyze_library":
        lib_name = arguments.get("library_name")
        lib_path = LIBS_DIR / lib_name
        
        if not lib_path.exists():
            return [types.TextContent(type="text", text=f"Library not found: {lib_name}")]
        
        # Create project directory
        PROJECT_DIR.mkdir(parents=True, exist_ok=True)
        
        # Run Ghidra analysis
        result_text = f"Analyzing {lib_name} with Ghidra...\n\n"
        
        stdout, stderr, code = run_ghidra_headless([
            str(PROJECT_DIR),
            "CyncBLE",
            "-import", str(lib_path),
            "-overwrite",
            "-scriptPath", str(SCRIPTS_DIR),
        ])
        
        if code == 0:
            result_text += "✅ Analysis complete!\n\n"
            result_text += "Summary:\n" + stdout[-500:] if len(stdout) > 500 else stdout
        else:
            result_text += f"❌ Analysis failed (code {code})\n\n"
            result_text += stderr[-500:] if stderr else "No error output"
        
        return [types.TextContent(type="text", text=result_text)]
    
    elif name == "find_functions":
        pattern = arguments.get("pattern", "").lower()
        lib_path = LIBS_DIR / "libBleLib.so"
        
        if not lib_path.exists():
            return [types.TextContent(type="text", text="libBleLib.so not found")]
        
        # Use readelf to get symbols
        try:
            result = subprocess.run(
                ["readelf", "-s", str(lib_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return [types.TextContent(type="text", text="readelf not available")]
            
            functions = []
            for line in result.stdout.split('\n'):
                if 'FUNC' in line and pattern in line.lower():
                    parts = line.split()
                    if len(parts) >= 8:
                        func_name = parts[-1]
                        functions.append(func_name)
            
            if functions:
                result_text = f"Functions matching '{pattern}':\n\n"
                for func in functions:
                    result_text += f"- {func}\n"
            else:
                result_text = f"No functions found matching '{pattern}'"
            
            return [types.TextContent(type="text", text=result_text)]
            
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]
    
    elif name == "get_function_decompile":
        lib_name = arguments.get("library_name")
        func_name = arguments.get("function_name")
        
        # Create a Ghidra script to decompile the function
        script_content = f'''# Decompile function
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def decompile_function(func_name):
    func = getGlobalFunctions(func_name)
    if not func:
        print("Function not found: " + func_name)
        return
    
    func = func[0] if func else None
    if not func:
        print("Function not found: " + func_name)
        return
    
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
    
    if results.decompileCompleted():
        print("=== DECOMPILED CODE ===")
        print(results.getDecompiledFunction().getC())
    else:
        print("Decompilation failed: " + results.getErrorMessage())

decompile_function("{func_name}")
'''
        
        script_path = SCRIPTS_DIR / "DecompileFunction.py"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(script_content)
        
        lib_path = LIBS_DIR / lib_name
        if not lib_path.exists():
            return [types.TextContent(type="text", text=f"Library not found: {lib_name}")]
        
        stdout, stderr, code = run_ghidra_headless([
            str(PROJECT_DIR),
            "CyncBLE",
            "-import", str(lib_path),
            "-postScript", "DecompileFunction.py",
            "-overwrite",
        ], timeout=180)
        
        # Extract decompiled code from output
        if "=== DECOMPILED CODE ===" in stdout:
            decompiled = stdout.split("=== DECOMPILED CODE ===")[1]
            result_text = f"Decompiled {func_name} from {lib_name}:\n\n```c\n{decompiled.strip()}\n```"
        else:
            result_text = f"Could not decompile {func_name}\n\nOutput:\n{stdout[-1000:]}"
        
        return [types.TextContent(type="text", text=result_text)]
    
    elif name == "search_strings":
        lib_name = arguments.get("library_name")
        pattern = arguments.get("pattern", "").lower()
        
        lib_path = LIBS_DIR / lib_name
        if not lib_path.exists():
            return [types.TextContent(type="text", text=f"Library not found: {lib_name}")]
        
        try:
            result = subprocess.run(
                ["strings", str(lib_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise RuntimeError("strings command failed")
            source_lines = result.stdout.split("\n")
        except Exception:
            try:
                source_lines = extract_ascii_strings(lib_path)
            except Exception as e:
                return [types.TextContent(type="text", text=f"Error: {str(e)}")]

        matches = [s for s in source_lines if pattern in s.lower()]

        if matches:
            result_text = f"Strings matching '{pattern}' in {lib_name}:\n\n"
            for match in matches[:50]:
                result_text += f"  {match}\n"
        else:
            result_text = f"No strings found matching '{pattern}'"

        return [types.TextContent(type="text", text=result_text)]
    
    else:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    """Run the MCP server"""
    # Check prerequisites
    log_runtime(f"Starting MCP server; cwd={Path.cwd()}")
    log_runtime(f"GHIDRA_HOME={GHIDRA_HOME}")
    log_runtime(f"PYTHONPATH={os.environ.get('PYTHONPATH', '')}")
    if not GHIDRA_HOME.exists():
        log_runtime("Ghidra not found; exiting")
        print(f"Error: Ghidra not found at {GHIDRA_HOME}", file=sys.stderr)
        print("Please set GHIDRA_INSTALL_DIR or install under tools-local/ghidra-master", file=sys.stderr)
        sys.exit(1)
    
    # Create directories
    LIBS_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="ghidra-cync-ble",
                    server_version="1.0.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    except Exception as exc:
        log_runtime(f"Unhandled exception: {exc!r}")
        raise

if __name__ == "__main__":
    asyncio.run(main())


