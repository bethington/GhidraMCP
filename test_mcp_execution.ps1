# Test script to verify bridge_mcp_ghidra package can be executed
# This script tests that the MCP server can be started

Write-Host "Testing bridge_mcp_ghidra package execution..." -ForegroundColor Cyan

# Test 1: Check if module can be imported
Write-Host "`n[Test 1] Checking if module can be imported..." -ForegroundColor Yellow
python -c "import bridge_mcp_ghidra; print(f'Module imported successfully. Version: {bridge_mcp_ghidra.__version__}')"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Module import failed" -ForegroundColor Red
    exit 1
}

# Test 2: Check if main function is accessible
Write-Host "`n[Test 2] Checking if main function is accessible..." -ForegroundColor Yellow
python -c "from bridge_mcp_ghidra import main; print('Main function is accessible')"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Main function not accessible" -ForegroundColor Red
    exit 1
}

# Test 3: Check if --help works
Write-Host "`n[Test 3] Testing --help flag..." -ForegroundColor Yellow
python -m bridge_mcp_ghidra.main --help | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "--help works correctly" -ForegroundColor Green
} else {
    Write-Host "--help failed" -ForegroundColor Red
    exit 1
}

# Test 4: Check client initialization
Write-Host "`n[Test 4] Testing GhidraHTTPClient initialization..." -ForegroundColor Yellow
python -c "from bridge_mcp_ghidra.client import GhidraHTTPClient; client = GhidraHTTPClient('http://127.0.0.1:8089/'); print('Client initialized successfully')"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Client initialization failed" -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "All tests passed!" -ForegroundColor Green
Write-Host "The bridge_mcp_ghidra package is ready to use." -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

Write-Host "Example usage for Claude Desktop (Windows):" -ForegroundColor Cyan
Write-Host '{' -ForegroundColor White
Write-Host '  "mcpServers": {' -ForegroundColor White
Write-Host '    "ghidra": {' -ForegroundColor White
Write-Host '      "command": "python",' -ForegroundColor White
Write-Host '      "args": [' -ForegroundColor White
Write-Host '        "-m",' -ForegroundColor White
Write-Host '        "bridge_mcp_ghidra.main",' -ForegroundColor White
Write-Host '        "--ghidra-server",' -ForegroundColor White
Write-Host '        "http://127.0.0.1:8089/"' -ForegroundColor White
Write-Host '      ],' -ForegroundColor White
Write-Host '      "cwd": "C:\\Users\\benam\\source\\ghidra\\GhidraMCP"' -ForegroundColor White
Write-Host '    }' -ForegroundColor White
Write-Host '  }' -ForegroundColor White
Write-Host '}' -ForegroundColor White
