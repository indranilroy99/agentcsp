from mcp.server.fastmcp import FastMCP

mcp = FastMCP("source-python-readonly-tools")


@mcp.tool(
    name="python_read_internal_doc",
    description="Read an approved internal documentation record by identifier.",
    annotations={"readOnlyHint": True, "idempotentHint": True},
)
def read_internal_doc(document_id: str) -> str:
    return "approved internal summary"
