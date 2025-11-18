# GhidraMCP Tools Inventory

This document lists all 89 MCP tools available in GhidraMCP, organized by category.

## Addresses (3 tools)
- [x] **can_rename_at_address** - Check what kind of symbol exists at an address
- [ ] **get_current_address** - Get the address currently selected by the user
- [ ] **get_function_jump_target_addresses** - Get all jump target addresses from a function's disassembly

## Arrays (2 tools)
- [ ] **create_array_type** - Create an array data type
- [ ] **detect_array_bounds** - Automatically detect array/table size and element boundaries

## BSim (7 tools)
- [ ] **bsim_disconnect** - Disconnect from the current BSim database
- [ ] **bsim_get_match_decompile** - Get the decompilation of a specific BSim match
- [ ] **bsim_get_match_disassembly** - Get the disassembly of a specific BSim match
- [ ] **bsim_query_all_functions** - Query all functions against the BSim database
- [ ] **bsim_query_function** - Query a single function for similar functions
- [ ] **bsim_select_database** - Select and connect to a BSim database
- [ ] **bsim_status** - Get BSim database connection status

## Categories (3 tools)
- [ ] **create_data_type_category** - Create a new data type category
- [ ] **list_data_type_categories** - List all data type categories
- [ ] **move_data_type_to_category** - Move a data type to a different category

## Classes (1 tool)
- [ ] **list_classes** - List all namespace/class names in the program

## Comments (4 tools)
- [ ] **batch_set_comments** - Set multiple comments in a single operation
- [ ] **set_decompiler_comment** - Set comment in function pseudocode
- [ ] **set_disassembly_comment** - Set comment in function disassembly
- [ ] **set_plate_comment** - Set function header comment

## Data (8 tools)
- [ ] **analyze_data_region** - Comprehensive data region analysis
- [ ] **format_number_conversions** - Convert numbers to different representations
- [ ] **get_data_by_label** - Get information about a data label
- [ ] **inspect_memory_content** - Read raw memory bytes with string detection
- [ ] **list_data_items** - List defined data labels and values
- [ ] **list_segments** - List all memory segments
- [ ] **search_byte_patterns** - Search for byte patterns with masks
- [ ] **write_bytes** - Write bytes to memory address

## Enums (2 tools)
- [ ] **create_enum** - Create enumeration data type
- [ ] **get_enum_values** - Get all values in an enumeration

## Functions (23 tools)
- [ ] **analyze_function_complete** - Comprehensive function analysis in one call
- [ ] **analyze_function_completeness** - Check function documentation completeness
- [ ] **batch_decompile_functions** - Decompile multiple functions at once
- [ ] **batch_rename_function_components** - Rename function and all components atomically
- [ ] **create_function_signature** - Create function signature data type
- [ ] **decompile_function** - Decompile function to C code
- [ ] **disassemble_function** - Get assembly code for function
- [ ] **document_function_complete** - Document function completely in one operation
- [ ] **find_next_undefined_function** - Find next function needing analysis
- [ ] **get_current_function** - Get currently selected function
- [ ] **get_full_call_graph** - Get complete program call graph
- [ ] **get_function_by_address** - Get function by address
- [ ] **get_function_call_graph** - Get call graph subgraph
- [ ] **get_function_callees** - Get functions called by this function
- [ ] **get_function_callers** - Get functions that call this function
- [ ] **list_functions** - List all functions with pagination
- [ ] **rename_function** - Rename function by name
- [ ] **rename_function_by_address** - Rename function by address
- [ ] **search_functions_by_name** - Search functions by substring
- [ ] **search_functions_enhanced** - Enhanced function search with filtering
- [ ] **set_function_prototype** - Set function prototype and calling convention
- [ ] **validate_function_prototype** - Validate prototype before applying

## Globals (5 tools)
- [ ] **get_data_by_label** - Get information about a data label
- [ ] **list_exports** - List exported functions/symbols
- [ ] **list_globals** - List globals with filtering
- [ ] **list_imports** - List imported symbols
- [ ] **rename_global_variable** - Rename global variable

## Labels (6 tools)
- [ ] **batch_create_labels** - Create multiple labels atomically
- [ ] **create_label** - Create new label at address
- [ ] **get_function_labels** - Get all labels within function
- [ ] **rename_data** - Rename data label at address
- [ ] **rename_label** - Rename existing label
- [ ] **rename_or_label** - Smart rename/create label at address

## Misc (3 tools)
- [ ] **check_connection** - Check if Ghidra plugin is accessible
- [ ] **get_entry_points** - Get all entry points
- [ ] **get_metadata** - Get program metadata

## Namespaces (1 tool)
- [ ] **list_namespaces** - List all non-global namespaces

## Security (1 tool)
- [ ] **extract_iocs** - Extract Indicators of Compromise from binary

## Strings (1 tool)
- [ ] **list_strings** - List all defined strings with addresses

## Structs (9 tools)
- [ ] **add_struct_field** - Add field to existing structure
- [ ] **analyze_struct_field_usage** - Analyze structure field access patterns
- [ ] **auto_create_struct_from_memory** - Auto-create structure from memory layout
- [ ] **create_struct** - Create new structure data type
- [ ] **get_field_access_context** - Get context for field offsets
- [ ] **get_struct_layout** - Get detailed structure layout
- [ ] **modify_struct_field** - Modify existing structure field
- [ ] **remove_struct_field** - Remove field from structure
- [ ] **suggest_field_names** - AI-assisted field name suggestions

## Types (15 tools)
- [ ] **analyze_data_types** - Analyze data types at address
- [ ] **apply_data_type** - Apply data type at memory address
- [ ] **clone_data_type** - Clone data type with new name
- [ ] **create_pointer_type** - Create pointer data type
- [ ] **create_typedef** - Create type alias
- [ ] **create_union** - Create union data type
- [ ] **delete_data_type** - Delete data type
- [ ] **export_data_types** - Export data types in various formats
- [ ] **get_type_size** - Get size/alignment for data type
- [ ] **get_valid_data_types** - Get list of valid Ghidra data types
- [ ] **list_data_types** - List all data types with filtering
- [ ] **search_data_types** - Search data types by pattern
- [ ] **validate_data_type** - Validate if type can be applied
- [ ] **validate_data_type_exists** - Check if data type exists

## Variables (5 tools)
- [ ] **batch_rename_variables** - Rename multiple variables atomically
- [ ] **batch_set_variable_types** - Set multiple variable types
- [ ] **get_function_variables** - List all function variables
- [ ] **rename_variable** - Rename local variable
- [ ] **set_local_variable_type** - Set local variable type

## Xrefs (5 tools)
- [ ] **batch_decompile_xref_sources** - Decompile all functions referencing an address
- [ ] **get_bulk_xrefs** - Get xrefs for multiple addresses
- [ ] **get_function_xrefs** - Get all references to function
- [ ] **get_xrefs_from** - Get references from address
- [ ] **get_xrefs_to** - Get references to address

---

**Total: 89 tools across 19 categories**

## Usage Instructions

To mark tools for removal:
1. Check the checkbox `[ ]` → `[x]` for tools you want to remove
2. Save the file and notify the development team
3. Tools marked for removal will be eliminated from the codebase
