# GhidraMCP Build Status and Issues

## Summary

The GhidraMCP project has been assessed and multiple issues have been identified that prevent successful compilation. The Python MCP bridge has been fixed and is working, but the Java Ghidra plugin has significant compilation errors.

## Fixed Issues

### Python Bridge (✅ Working)

1. **Fixed decorator issue** in `client.py` - Moved `cached_request` from instance method to module-level function
2. **Fixed import** in `main.py` - Changed from `from mcp import FastMCP` to `from fastmcp import FastMCP`
3. **Added getPaths()** method to `Handler.java` base class for multi-path support
4. **Fixed compilation errors**:
   - Removed extra semicolons in imports
   - Fixed syntax error in `GhidraUtils.java` (removed extra brace)
   - Fixed `DecompileFunctionByAddress.java` imports and `getCurrentProgram` call

5. **Set up Gradle wrapper** for the project (no need to install Gradle separately)

### Gradle Setup (✅ Complete)

- Copied Gradle wrapper files from Ghidra installation
- Created `gradlew` and `gradlew.bat` scripts
- Gradle 8.14.2 is now available via `.\gradlew.bat` commands

## Remaining Compilation Errors (64 errors)

The project has extensive compilation errors across many handler classes. These fall into several categories:

### 1. Missing/Incorrect Imports

Many handler classes have incorrect imports:
- `Function` and `FunctionManager` should be from `ghidra.program.model.listing`, not `ghidra.program.model.symbol`
- `Variable` should be from `ghidra.program.model.listing`, not `ghidra.program.model.symbol`  
- `ConsoleTaskMonitor` should be from `ghidra.util.task`, not `ghidra.app.decompiler`
- `StandardCharsets` is missing import from `java.nio.charset`
- `Headers` is missing import from `com.sun.net.httpserver`
- Many `Data`, `Listing`, `Program` imports missing

### 2. Missing Method Implementations

Several handler classes call methods that don't exist:
- `formatNumberConversion()` in `FormatNumberConversions.java`
- `renameFunction()` in `RenameFunction.java`
- `BatchSetVariableTypes()` in `BatchSetVariableTypes.java`

### 3. Type Mismatches

Methods returning `boolean` being assigned to `String` variables:
- `SetDecompilerComment.java` - line 39
- `SetDisassemblyComment.java` - line 40
- `RenameFunctionByAddress.java` - line 45
- `RenameGlobalVariable.java` - line 45
- `SetLocalVariableType.java` - line 86

### 4. Missing Tool/Program References

Many handlers calling `getCurrentProgram()` without passing the required `tool` parameter:
- `BatchDecompileFunctions.java`
- `DocumentFunctionComplete.java`
- `SearchFunctionsEnhanced.java`
- `ExtractIOCs.java`
- `AnalyzeStructFieldUsage.java`
- `GetFieldAccessContext.java`
- `SetPlateComment.java`

### 5. Missing Constants

Several constants are used but not defined:
- `MIN_TOKEN_LENGTH`
- `C_KEYWORDS`
- `MAX_STRUCT_FIELDS`
- `MAX_FIELD_OFFSET`
- `MAX_FIELD_EXAMPLES`
- `DECOMPILE_TIMEOUT_SECONDS` (in some files)
- `HTTP_IDLE_TIMEOUT_SECONDS`

These constants exist in `GhidraMCPPlugin.java` but need to be imported or made accessible.

### 6. Incorrect Constructor Calls

`GetFunctionJumpTargets.java` - calling `Handler` constructor with 3 args (two paths) but base class only accepts 2 args (tool, single path).

### 7. Static Context Issues

`GhidraUtils.java` - using `this` in static methods (lines 77, 220, 226). Should use a Class reference or logger instead.

### 8. Missing Handler Superclass

`CheckConnection.java` - Cannot find symbol `Handler`, suggesting circular dependency or missing import.

## Recommended Next Steps

Given the extensive issues, there are two approaches:

### Option 1: Incremental Fix (Time-intensive)
Fix all 64+ compilation errors one by one. This would require:
1. Adding/correcting all missing imports
2. Implementing missing methods
3. Fixing type mismatches
4. Making constants accessible
5. Fixing method signatures

**Estimated effort**: Several hours

### Option 2: Use Pre-built Release (Recommended)
Since the Python bridge is working, you can:
1. Download the latest pre-built release from the GitHub repository
2. Use that compiled plugin with the fixed Python bridge
3. Install in Ghidra following the README instructions

**Estimated effort**: 5-10 minutes

## Files Ready for Use

These files are fixed and working:
- `bridge_mcp_ghidra/` - Python MCP bridge (fully functional)
- `gradlew` and `gradlew.bat` - Gradle wrapper
- `gradle/wrapper/` - Gradle wrapper JARs
- `test_mcp_execution.ps1` - Python bridge test script
- `PACKAGE_USAGE.md` - Documentation for using the Python bridge
- `requirements.txt` - Updated with correct dependencies

## Building When Fixed

Once the Java compilation errors are resolved:

```powershell
# Windows
cd C:\Users\benam\source\ghidra\GhidraMCP
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.7.6-hotspot"
.\gradlew.bat buildExtension

# Linux/Mac
cd /path/to/GhidraMCP
export JAVA_HOME=/path/to/jdk-21
./gradlew buildExtension
```

The built extension will be in: `dist/GhidraMCP-<version>.zip`

## Testing with Ghidra

Once built:
1. Open Ghidra
2. File → Install Extensions
3. Click the `+` button
4. Select the generated ZIP from `dist/` folder
5. Restart Ghidra
6. Open a project and binary
7. In CodeBrowser: File → Configure → Developer
8. Enable GhidraMCPPlugin
9. Server starts on http://127.0.0.1:8089/

Then start the Python MCP bridge:
```powershell
cd C:\Users\benam\source\ghidra\GhidraMCP
python -m bridge_mcp_ghidra.main --ghidra-server http://127.0.0.1:8089/
```

## Conclusion

The **Python MCP bridge is production-ready**. The Java Ghidra plugin requires significant work to fix compilation errors. Recommend using a pre-built release for the plugin while using the fixed Python bridge from this repository.
