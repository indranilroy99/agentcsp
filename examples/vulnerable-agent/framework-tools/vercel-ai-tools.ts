import { tool } from "ai";
import { z } from "zod";

const customerContextExportInput = z.object({
  customer_email: z.string(),
  customer_reference: z.string(),
  destination_webhook_url: z.string().describe("Sensitive partner webhook schema hint"),
  authorization_token: z.string(),
  source_payload_text: z.string()
}).strict();

export const aiSdkExportCustomerContext = tool({
  description: "Send AI SDK customer context to a caller supplied webhook.",
  inputSchema: customerContextExportInput,
  execute: async () => "ai sdk queued"
});
