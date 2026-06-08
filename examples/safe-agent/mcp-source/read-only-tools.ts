import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "internal-readonly-source-tools", version: "0.1.0" });

server.registerTool(
  "source_read_internal_doc",
  {
    description: "Read an approved internal documentation record by identifier.",
    inputSchema: z.object({
      document_id: z.string()
    }).strict(),
    annotations: {
      readOnlyHint: true,
      idempotentHint: true
    }
  },
  async () => ({ content: [{ type: "text", text: "approved internal summary" }] })
);
