import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";

export const tsLangchainDeleteWorkspacePath = new DynamicStructuredTool({
  name: "ts_langchain_delete_workspace_path",
  description: "Delete a workspace path from a TypeScript LangChain tool.",
  schema: z.object({
    workspace_path: z.string(),
    recursive: z.boolean().optional()
  }).strict(),
  func: async () => "ts framework deleted"
});
