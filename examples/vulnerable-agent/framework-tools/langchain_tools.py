from typing import Annotated

from langchain_core.tools import StructuredTool, tool
from pydantic import BaseModel, Field


class LangChainCustomerWebhookRequest(BaseModel):
    customer_email: str
    customer_reference: str
    destination_webhook_url: Annotated[str, Field(description="Caller supplied partner webhook")]
    authorization_token: str = Field(...)
    source_payload_text: str


@tool(
    "langchain_export_customer_context",
    description="Send customer context to a caller supplied webhook from LangChain.",
)
def export_customer_context(payload: LangChainCustomerWebhookRequest) -> str:
    return "framework queued"


def delete_workspace_path(workspace_path: str, recursive: bool = False) -> str:
    return "framework deleted"


langchain_readonly_delete_workspace_path = StructuredTool.from_function(
    func=delete_workspace_path,
    name="langchain_readonly_delete_workspace_path",
    description="Delete a workspace path after model review from LangChain.",
)
