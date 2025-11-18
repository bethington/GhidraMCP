# GhidraMCP Testing Checklist

## Pre-Test Verification ✅

- ✅ **Java Plugin Built**: `ghidra_11.4.2_PUBLIC_20251118_GhidraMCP.zip` exists in `dist/`
- ✅ **Python Bridge**: Version 3.1.0 imports successfully
- ✅ **MCP Configuration**: Port 8089 configured in Cline settings
- ✅ **No Build Errors**: All Java compilation errors fixed
- ✅ **Help Command Works**: `python -m bridge_mcp_ghidra.main --help` runs successfully

## Testing Steps

### 1. Install Ghidra Extension

1. Open Ghidra (version 11.4.2 at `F:\ghidra_11.4.2`)
2. Go to **File → Install Extensions**
3. Click the **+** (plus) button
4. Navigate to: `c:\Users\benam\source\ghidra\GhidraMCP\dist\ghidra_11.4.2_PUBLIC_20251118_GhidraMCP.zip`
5. Click **OK**
6. **Restart Ghidra** when prompted

### 2. Enable the Plugin

1. Open or create a project in Ghidra
2. Open a program in the **CodeBrowser** tool
3. Go to **File → Configure**
4. Search for "GhidraMCP" or "MCP"
5. Check the box next to **GhidraMCPPlugin**
6. Click **Close**

### 3. Verify HTTP Server Started

Open PowerShell and run:

```powershell
# Check if port 8089 is listening
netstat -ano | Select-String "8089"

# Test the connection endpoint
Invoke-WebRequest -Uri "http://127.0.0.1:8089/check_connection" -Method GET
```

**Expected Result**: 
- Port 8089 should be listening
- Connection endpoint should return a successful response

### 4. Test Python Bridge Connection

In a PowerShell terminal:

```powershell
cd c:\Users\benam\source\ghidra\GhidraMCP

# Test connection
python -c "from bridge_mcp_ghidra.client import GhidraHTTPClient; client = GhidraHTTPClient('http://127.0.0.1:8089/'); print(client.get('check_connection'))"
```

**Expected Result**: Should return connection status from Ghidra

### 5. Restart VS Code

1. **Close VS Code completely**
2. **Reopen VS Code**
3. Wait for Cline to load

### 6. Verify MCP Tools Available

In Cline chat, check if Ghidra MCP tools are listed:
- Look for tools like `ghidra_list_functions`, `ghidra_decompile_function`, etc.
- The tool count should be 50+ tools

### 7. Test a Simple MCP Tool

Try asking Cline to use a Ghidra tool, for example:
- "List all functions in the current Ghidra program"
- "Get the decompiled code for the function at address 0x00401000"

## Troubleshooting

### Plugin Not Loading
- **Check Ghidra Console**: Look for error messages about GhidraMCPPlugin
- **Check Java Version**: Must be Java 21
- **Verify Extension Path**: Make sure the zip file path is correct

### Port 8089 Not Listening
- **Check Plugin Enabled**: Verify in File → Configure
- **Check Port Conflict**: Another process may be using port 8089
  ```powershell
  netstat -ano | Select-String "8089"
  ```
- **Check Ghidra Console**: Look for HTTP server startup messages

### MCP Tools Not Showing in Cline
- **Restart VS Code**: Configuration changes require restart
- **Check MCP Config**:
  ```powershell
  Get-Content "C:\Users\benam\AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json"
  ```
- **Check Cline Logs**: Look for MCP server connection errors
- **Test Bridge Manually**:
  ```powershell
  cd c:\Users\benam\source\ghidra\GhidraMCP
  python -m bridge_mcp_ghidra.main --ghidra-server http://127.0.0.1:8089
  ```
  Then press Ctrl+C to stop

### Connection Refused Errors
- **Verify Ghidra Running**: Make sure CodeBrowser is open with a program loaded
- **Verify Plugin Active**: Check that GhidraMCPPlugin is enabled
- **Check Firewall**: Windows Firewall may be blocking port 8089

## Quick Manual Test

If MCP integration isn't working yet, you can test the HTTP API directly:

```powershell
# Start Ghidra with plugin enabled and a program loaded

# Test in PowerShell:
$response = Invoke-RestMethod -Uri "http://127.0.0.1:8089/list_functions" -Method GET
$response | ConvertTo-Json

# Or test decompilation:
$body = @{ address = "0x00401000" } | ConvertTo-Json
$response = Invoke-RestMethod -Uri "http://127.0.0.1:8089/decompile_function" -Method POST -Body $body -ContentType "application/json"
$response
```

## Success Criteria

- ✅ Ghidra plugin loads without errors
- ✅ HTTP server starts on port 8089
- ✅ Python bridge can connect to Ghidra
- ✅ MCP tools appear in Cline
- ✅ Can execute at least one MCP tool successfully

## Current Status

**Ready for Testing**: All components built and configured. Follow steps 1-7 above to test with Ghidra.
