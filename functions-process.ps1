param(
    [switch]$Reverse,
    [switch]$Single,
    [string]$Function,
    [string]$Model = "claude-sonnet-4-20250514",
    [switch]$Help
)

$todoFile = ".\FunctionsTodo.txt"
$promptFile = ".\FUNCTION_DOC_WORKFLOW_V2.md"

# Check if prompt file exists, if not use a default prompt
if (-not (Test-Path $promptFile)) {
    Write-Host "WARNING: Prompt file not found at $promptFile" -ForegroundColor Yellow
    Write-Host "Using embedded default workflow prompt..." -ForegroundColor Yellow
    $defaultPrompt = $true
} else {
    $defaultPrompt = $false
}

function Show-Help {
    Write-Host "functions-process.ps1 - Function Processing with MCP"
    Write-Host ""
    Write-Host "OPTIONS:"
    Write-Host "  -Single           Process one function and stop"
    Write-Host "  -Function <name>  Process specific function"
    Write-Host "  -Reverse          Process from bottom to top"
    Write-Host "  -Model <model>    Claude model to use (default: claude-sonnet-4-20250514)"
    Write-Host "  -Help             Show this help"
    Write-Host ""
    Write-Host "EXAMPLES:"
    Write-Host "  .\functions-process.ps1                    # Process all functions"
    Write-Host "  .\functions-process.ps1 -Single            # Process one function"
    Write-Host "  .\functions-process.ps1 -Function FUN_123  # Process specific function"
    Write-Host "  .\functions-process.ps1 -Reverse           # Process from bottom"
    exit 0
}

function Process-Function {
    param([string]$funcName, [string]$address = "")
    
    if ($address) {
        Write-Host "Processing: $funcName @ $address" -ForegroundColor Green
    } else {
        Write-Host "Processing: $funcName" -ForegroundColor Green
    }
    
    # Check function completeness first
    Write-Host "Checking function completeness..." -ForegroundColor Cyan
    $completenessInfo = ""
    if ($address) {
        try {
            $completenessUrl = "http://127.0.0.1:8089/analyze_function_completeness?function_address=0x$address"
            $completenessResponse = Invoke-RestMethod -Uri $completenessUrl -Method GET -TimeoutSec 10
            
            if ($completenessResponse) {
                $score = $completenessResponse.completeness_score
                $hasCustomName = $completenessResponse.has_custom_name
                $hasPrototype = $completenessResponse.has_prototype
                $hasCallingConvention = $completenessResponse.has_calling_convention
                $hasPlateComment = $completenessResponse.has_plate_comment
                $undefinedVars = $completenessResponse.undefined_variables
                
                # Build missing items list
                $missingItems = @()
                if (-not $hasCustomName) { $missingItems += "Custom function name (currently has default FUN_ name)" }
                if (-not $hasPrototype) { $missingItems += "Function prototype with typed parameters" }
                if (-not $hasCallingConvention) { $missingItems += "Calling convention specification" }
                if (-not $hasPlateComment) { $missingItems += "Plate comment (function header documentation)" }
                if ($undefinedVars -gt 0) { $missingItems += "$undefinedVars undefined variable(s) need renaming" }
                
                $missingItemsText = if ($missingItems.Count -gt 0) {
                    "`n`nMissing Documentation Elements:`n" + ($missingItems | ForEach-Object { "  - $_" }) -join "`n"
                } else {
                    "`n`nAll core documentation elements are present."
                }
                
                $completenessInfo = @"

---

## FUNCTION COMPLETENESS ANALYSIS

**Current Completeness Score: $score/100**

Status Summary:
- Custom Name: $(if ($hasCustomName) { "✓ Present" } else { "✗ MISSING" })
- Function Prototype: $(if ($hasPrototype) { "✓ Present" } else { "✗ MISSING" })
- Calling Convention: $(if ($hasCallingConvention) { "✓ Present" } else { "✗ MISSING" })
- Plate Comment: $(if ($hasPlateComment) { "✓ Present" } else { "✗ MISSING" })
- Undefined Variables: $(if ($undefinedVars -eq 0) { "✓ None" } else { "✗ $undefinedVars need attention" })
$missingItemsText

**PRIORITY:** Focus on completing the missing elements above to achieve 100/100 completeness score.

---
"@
                Write-Host "  Completeness Score: $score/100" -ForegroundColor $(if ($score -ge 75) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" })
                if ($missingItems.Count -gt 0) {
                    Write-Host "  Missing: $($missingItems.Count) item(s)" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "  Warning: Could not check completeness: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    # Load the optimized prompt template
    if ($defaultPrompt) {
        # Use embedded minimal workflow prompt
        $basePrompt = @"
# FUNCTION DOCUMENTATION WORKFLOW V2

You are documenting functions in a Ghidra reverse engineering project using the GhidraMCP tools available to you.

## AVAILABLE MCP TOOLS

You have access to Ghidra MCP tools including:
- mcp_ghidra_decompile_function: Get decompiled code
- mcp_ghidra_get_function_variables: List all variables in a function
- mcp_ghidra_batch_rename_function_components: Rename function and variables atomically
- mcp_ghidra_batch_set_variable_types: Set types for multiple variables
- mcp_ghidra_batch_set_comments: Set multiple comments in one operation
- mcp_ghidra_set_function_prototype: Set function prototype
- And many more...

## WORKFLOW STEPS

For the target function specified below, execute these steps using the MCP tools:

1. **Decompile the function**: Call mcp_ghidra_decompile_function with the function name
2. **Get variables**: Call mcp_ghidra_get_function_variables to see all parameters and locals
3. **Analyze completeness**: Review the completeness analysis provided below
4. **Apply fixes for missing elements**:
   - If missing custom name: Rename function using batch_rename_function_components
   - If missing prototype: Set prototype with set_function_prototype
   - If missing calling convention: Include in prototype
   - If missing plate comment: Add using batch_set_comments
   - If undefined variables exist: Rename them using batch_rename_function_components
5. **Verify changes**: Call the appropriate tools to confirm changes were applied

## GUIDING PRINCIPLES

- Use descriptive, meaningful names that reflect purpose
- Document what the function does, not how it does it
- Focus on missing elements identified in the completeness analysis
- **IMPORTANT**: Actually call the MCP tools to make changes in Ghidra - don't just describe what should be done
- Use batch operations for efficiency
"@
    } else {
        if (-not (Test-Path $promptFile)) {
            Write-Host "ERROR: Prompt file not found at $promptFile" -ForegroundColor Red
            return $false
        }
        $basePrompt = Get-Content $promptFile -Raw
    }
    
    # Inject the specific function name and completeness info into the prompt
    $prompt = $basePrompt -replace 'get_current_function\(\)', "search_functions_by_name(`"$funcName`")"
    $prompt = $prompt + "`n`n## TARGET FUNCTION TO DOCUMENT`n`nFunction Name: **$funcName**$(if ($address) { "`nFunction Address: **0x$address**" })$completenessInfo`n`n**BEGIN DOCUMENTATION:** Proceed with complete and thorough documentation of this function following the workflow above."
    
    try {
    $env:NODE_OPTIONS = "--max-old-space-size=8192"
    Write-Host "Invoking Claude with MCP..." -ForegroundColor Cyan
    
    # Create a simple prompt that asks Claude to use the MCP tools
    # Claude Code should automatically detect and use available MCP servers from config
    
    # Invoke Claude with the prompt
    $output = echo $prompt | claude --model $Model 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -eq 0) {
            Write-Host "Success!" -ForegroundColor Green
            Write-Host $output
            return $true
        } else {
            Write-Host "Failed with exit code $exitCode" -ForegroundColor Red
            Write-Host $output
            return $false
        }
    }
    finally {
        $env:NODE_OPTIONS = $null
    }
}

if ($Help) { Show-Help }

if ($Function) {
    $success = Process-Function $Function
    if ($success) {
        $content = Get-Content $todoFile -Raw
        $updated = $content -replace "\[\s*\]\s+$Function\s+@", "[X] $Function @"
        Set-Content $todoFile $updated -NoNewline
    }
    exit 0
}

while ($true) {
    $content = Get-Content $todoFile
    $pending = $content | Where-Object { $_ -match '^\[ \] (.+?) @ ([0-9a-fA-F]+)' }
    
    if ($pending.Count -eq 0) { break }
    
    $line = if ($Reverse) { $pending | Select-Object -Last 1 } else { $pending | Select-Object -First 1 }
    $matches = [regex]::Match($line, '^\[ \] (.+?) @ ([0-9a-fA-F]+)')
    $funcName = $matches.Groups[1].Value
    $address = $matches.Groups[2].Value
    
    Write-Host "
$($pending.Count) remaining" -ForegroundColor Yellow
    $success = Process-Function $funcName $address
    
    if ($success) {
        $content = Get-Content $todoFile -Raw
        $escapedFuncName = [regex]::Escape($funcName)
        $updated = $content -replace "\[\s*\]\s+$escapedFuncName\s+@", "[X] $funcName @"
        Set-Content $todoFile $updated -NoNewline
    }
    
    if ($Single) { break }
    Start-Sleep -Seconds 2
}
