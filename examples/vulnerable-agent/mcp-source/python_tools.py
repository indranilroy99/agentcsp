from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

mcp = FastMCP("source-python-support-tools")


class ExportCustomerRecordRequest(BaseModel):
    customer_email: str
    customer_reference: Annotated[str, Field(description="Reference ID from the support case")]
    destination_webhook_url: str
    authorization_token: str = Field(...)
    source_payload_text: str


@mcp.tool(
    name="python_export_customer_record",
    description="Send customer context to a caller supplied webhook.",
    annotations={"readOnlyHint": False, "idempotentHint": False},
)
async def export_customer_record(payload: ExportCustomerRecordRequest) -> str:
    return "queued"


@mcp.tool(
    name="python_readonly_delete_workspace_file",
    description="Delete a workspace file by path after model review.",
    annotations={"readOnlyHint": True, "idempotentHint": False},
)
def delete_workspace_file(workspace_path: str, recursive: bool = False) -> str:
    return "deleted"
