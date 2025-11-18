# GhidraMCP Package Usage Summary

## Package Structure

The `bridge_mcp_ghidra` folder is a properly structured Python package (not a single .py file). It contains:

- `__init__.py` - Makes it a Python package and exports key components
- `main.py` - Entry point with the `main()` function
- `client.py` - HTTP client for communicating with Ghidra server
- `context.py` - Context management and configuration
- `tools/` - Directory containing all MCP tool implementations

## How to Use

### Running the MCP Server

Since `bridge_mcp_ghidra` is a package (not a standalone script), you must run it as a Python module:

```bash
python -m bridge_mcp_ghidra.main [options]
```

**Important**: You must run this command from the GhidraMCP directory (or set it as the working directory).

### Available Options

- `--ghidra-server URL` - Ghidra server URL (default: http://127.0.0.1:8089/)
- `--transport {stdio,sse}` - Transport protocol (default: stdio)
- `--mcp-host HOST` - MCP server host for SSE mode (default: 127.0.0.1)
- `--mcp-port PORT` - MCP server port for SSE mode (default: 8089)

## Configuration Examples

### Claude Desktop (Windows)

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "-m",
        "bridge_mcp_ghidra.main",
        "--ghidra-server",
        "http://127.0.0.1:8089/"
      ],
      "cwd": "C:\\Users\\YourUsername\\path\\to\\GhidraMCP"
    }
  }
}
```

### Claude Desktop (macOS/Linux)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "-m",
        "bridge_mcp_ghidra.main",
        "--ghidra-server",
        "http://127.0.0.1:8089/"
      ],
      "cwd": "/absolute/path/to/GhidraMCP"
    }
  }
}
```

### Cline

Run from the GhidraMCP directory:

```bash
cd /path/to/GhidraMCP
python -m bridge_mcp_ghidra.main --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8089/
```

Then in Cline, add remote server:
- Server Name: GhidraMCP
- Server URL: http://127.0.0.1:8081/sse

### VSCode (GitHub Copilot)

In VSCode Agent mode, add MCP server with command:

**Windows:**
```
cd C:\path\to\GhidraMCP ; python -m bridge_mcp_ghidra.main --ghidra-server http://localhost:8089/
```

**macOS/Linux:**
```
cd /path/to/GhidraMCP && python -m bridge_mcp_ghidra.main --ghidra-server http://localhost:8089/
```

## Dependencies

Install required packages:

```bash
pip install -r requirements.txt
```

Required packages:
- `fastmcp>=2.0.0` - High-level MCP server framework
- `mcp>=1.5.0` - Core MCP SDK
- `requests>=2.28.0` - HTTP client library

## Testing

Run the included test script to verify everything works:

**Windows:**
```powershell
.\test_mcp_execution.ps1
```

**Linux/macOS:**
```bash
# Test module import
python -c "import bridge_mcp_ghidra; print(bridge_mcp_ghidra.__version__)"

# Test help
python -m bridge_mcp_ghidra.main --help
```

## Changes Made

1. **Fixed decorator issue** in `client.py` - The `cached_request` decorator was incorrectly defined as an instance method. It's now a module-level function.

2. **Fixed import** in `main.py` - Changed from `from mcp import FastMCP` to `from fastmcp import FastMCP`.

3. **Updated requirements.txt** - Added `fastmcp` as a required dependency.

4. **Updated README.md** - All examples now use `python -m bridge_mcp_ghidra.main` with proper `cwd` settings instead of referencing a non-existent `bridge_mcp_ghidra.py` file.

5. **Created test script** - Added `test_mcp_execution.ps1` for verifying the package works correctly.

## Verification

All tests pass:
- ✓ Module imports successfully (Version 3.1.0)
- ✓ Main function is accessible
- ✓ --help flag works
- ✓ GhidraHTTPClient initializes correctly

The package is ready to use with any MCP client!
