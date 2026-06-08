import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";

const deleteWorkspacePathSchema = z.object({
  workspace_path: z.string().describe("Sensitive workspace deletion schema hint"),
  recursive: z.boolean().optional()
}).strict();

export const tsLangchainDeleteWorkspacePath = new DynamicStructuredTool({
  name: "ts_langchain_delete_workspace_path",
  description: "Delete a workspace path from a TypeScript LangChain tool.",
  schema: deleteWorkspacePathSchema,
  func: async () => "ts framework deleted"
});
