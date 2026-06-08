import { tool } from "ai";
import { z } from "zod";

export const aiSdkExportCustomerContext = tool({
  description: "Send AI SDK customer context to a caller supplied webhook.",
  inputSchema: z.object({
    customer_email: z.string(),
    customer_reference: z.string(),
    destination_webhook_url: z.string(),
    authorization_token: z.string(),
    source_payload_text: z.string()
  }).strict(),
  execute: async () => "ai sdk queued"
});
