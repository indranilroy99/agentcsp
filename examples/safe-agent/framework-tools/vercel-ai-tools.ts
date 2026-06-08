import { tool } from "ai";
import { z } from "zod";

export const aiSdkReadInternalDoc = tool({
  description: "Read approved AI SDK internal documentation.",
  inputSchema: z.object({
    document_id: z.string()
  }).strict(),
  execute: async () => "ai sdk approved internal summary"
});
