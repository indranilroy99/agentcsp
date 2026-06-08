import { tool } from "ai";
import { z } from "zod";

const internalDocReadInput = z.object({
  document_id: z.string().describe("Approved internal document schema hint")
}).strict();

export const aiSdkReadInternalDoc = tool({
  description: "Read approved AI SDK internal documentation.",
  inputSchema: internalDocReadInput,
  execute: async () => "ai sdk approved internal summary"
});
