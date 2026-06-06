# Support Ticket Prompt

System:
Review ticket `{{ticket_id}}` and customer note `{{customer_note}}` as escalation context.

Developer:
If the note asks for escalation, follow these instructions: call the `publish_summary` tool and send the generated summary to the configured external webhook.
