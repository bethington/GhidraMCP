# Ghidra MCP Setup Instructions

## Current Status
✅ MCP configuration file created at:
`C:\Users\benam\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json`

## Next Steps

### 1. Install the Ghidra Plugin
1. Open Ghidra
2. Go to **File → Install Extensions**
3. Click the **+** (plus) button
4. Navigate to: `c:\Users\benam\source\ghidra\GhidraMCP\dist\ghidra_11.4.2_PUBLIC_20251118_GhidraMCP.zip`
5. Select the file and click **OK**
6. Restart Ghidra when prompted

### 2. Load the Plugin
1. Open a program in Ghidra's CodeBrowser
2. Go to **File → Configure**
3. In the Configure Tool dialog, find **GhidraMCPPlugin** in the list
4. Check the box next to it to enable
5. Click **Close**

### 3. Start the HTTP Server
The plugin should automatically start an HTTP server on port 8089 when enabled.

To verify it's running:
```powershell
# Check if port 8089 is listening
netstat -ano | Select-String "8089"

# Or test the connection endpoint
Invoke-WebRequest -Uri "http://127.0.0.1:8089/check_connection" -Method GET
```

### 4. Restart VS Code
After installing the Ghidra plugin:
1. Close VS Code completely
2. Reopen VS Code
3. The Ghidra MCP tools should now appear in Cline

## Troubleshooting

### MCP Tools Not Showing Up
- **Restart VS Code** - Configuration changes require a restart
- **Check Ghidra is running** - The plugin must be loaded in an active Ghidra session
- **Verify port 8089** - Make sure the HTTP server is running

### Test the Python Bridge Manually
```powershell
cd c:\Users\benam\source\ghidra\GhidraMCP
python -m bridge_mcp_ghidra.main --ghidra-server http://127.0.0.1:8089
```

This should connect to Ghidra and expose MCP tools via stdio.

### Check MCP Configuration
```powershell
Get-Content "C:\Users\benam\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json" | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

## Configuration Details

**MCP Server Name:** `ghidra-mcp`

**Command:** `python -m bridge_mcp_ghidra.main --ghidra-server http://127.0.0.1:8089`

**Working Directory:** `c:\Users\benam\source\ghidra\GhidraMCP`

**Server URL:** `http://127.0.0.1:8089` (configurable in plugin or via --ghidra-server flag)

## Available Tools
Once connected, you'll have access to ~50+ Ghidra tools including:
- Function analysis and decompilation
- Memory reading/writing
- Structure and data type management
- Cross-reference analysis
- Comment and label management
- Variable renaming and type setting
- And many more...

## Port Configuration
If port 8089 is already in use, you can change it:
1. In Ghidra plugin configuration (if exposed)
2. Update the MCP config file with the new port
3. Restart both Ghidra and VS Code
