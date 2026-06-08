from typing import Annotated

from langchain_core.tools import tool
from pydantic import BaseModel, Field


class LangChainInternalDocRequest(BaseModel):
    document_id: Annotated[str, Field(description="Approved documentation identifier")]


@tool("langchain_read_internal_doc", description="Read approved internal documentation from LangChain.")
def read_internal_doc(request: LangChainInternalDocRequest) -> str:
    return "framework approved internal summary"
