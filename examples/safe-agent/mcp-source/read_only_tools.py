from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

mcp = FastMCP("source-python-readonly-tools")


class InternalDocRequest(BaseModel):
    document_id: str


@mcp.tool(
    name="python_read_internal_doc",
    description="Read an approved internal documentation record by identifier.",
    annotations={"readOnlyHint": True, "idempotentHint": True},
)
def read_internal_doc(
    request: Annotated[InternalDocRequest, Field(description="Approved internal document request")],
) -> str:
    return "approved internal summary"
