# Cync Ghidra Scan Log

Tracking actions and progress for BLE/Wi-Fi pairing analysis.

## 2026-01-08 15:53:09
- Started maintaining scan log as requested.
- Investigated MCP server failures: missing analyzeHeadless in PATH and missing GNU strings on Windows.
- Patched ghidra_mcp_server.py to prefer analyzeHeadless.bat on Windows and added a built-in ASCII strings fallback.
- Stopped stale ghidra_mcp_server.py processes to reload updated code.
- Next: restart MCP server via tool call and begin string/function scans across libraries for BLE/Wi-Fi/pairing flows.

## 2026-01-08 17:49:22
- Diagnosed MCP tool Transport closed issue; suspected cwd-relative paths causing startup failures under sandbox.
- Updated ghidra_mcp_server.py to anchor paths (project/libs/scripts/log) to script directory and run analyzeHeadless from that base.
- Next: retry MCP tool calls and begin string scans for BLE/Wi-Fi/pairing markers across libraries.

## 2026-01-08 17:55:41
- Reverted ghidra_mcp_server.py to the prior state to restore the original MCP server behavior.
- Next: retry MCP tool calls and confirm the server responds as before.

## 2026-01-08 17:57:42
- MCP tool calls still fail with Transport closed after revert.
- Found note in SESSION_NOTES indicating Codex must be restarted to reattach to the MCP server in this session.
- Next: restart Codex CLI, then retry MCP tool calls.

## 2026-01-08 18:36:38
- User selected restart option to restore MCP connectivity.
- Awaiting Codex CLI restart before resuming MCP tool calls and scans.

