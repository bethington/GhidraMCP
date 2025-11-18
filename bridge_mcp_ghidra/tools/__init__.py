from .addresses import register_address_tools
from .arrays import register_array_tools
#from .bsim import register_bsim_tools
from .categories import register_category_tools
from .classes import register_class_tools
from .comments import register_comment_tools
from .data import register_data_tools
from .enums import register_enum_tools
from .functions import register_function_tools
from .globals import register_global_tools
from .labels import register_label_tools
from .misc import register_misc_tools
from .namespaces import register_namespace_tools
from .security import register_security_tools
from .strings import register_string_tools
from .structs import register_struct_tools
from .types import register_type_tools
from .variables import register_variable_tools
from .xrefs import register_xref_tools

def register_all_tools(mcp):
	"""Register all Ghidra tools with the FastMCP instance."""
	register_address_tools(mcp)
	register_array_tools(mcp)
	#register_bsim_tools(mcp)
	register_category_tools(mcp)
	register_class_tools(mcp)
	register_comment_tools(mcp)
	register_data_tools(mcp)
	register_enum_tools(mcp)
	register_function_tools(mcp)
	register_global_tools(mcp)
	register_label_tools(mcp)
	register_misc_tools(mcp)
	register_namespace_tools(mcp)
	register_security_tools(mcp)
	register_string_tools(mcp)
	register_struct_tools(mcp)
	register_type_tools(mcp)
	register_variable_tools(mcp)
	register_xref_tools(mcp)

__all__ = [
	"register_all_tools"
]
