import fs from "node:fs/promises";
import path from "node:path";
import { AgentManifestSchema, FindingSchema } from "../packages/core/dist/schemas/index.js";

const vulnerableOutput = path.resolve(process.argv[2] ?? ".agentcsp");
const safeOutput = path.resolve(process.argv[3] ?? ".agentcsp-safe");

const leakPatterns = [
  /\$\{A2A_AGENT_TOKEN\}/u,
  /\$\{A2A_FEDERATION_TOKEN\}/u,
  /\$\{ANTHROPIC_API_KEY\}/u,
  /\$\{AGENT_CONTAINER_TOKEN\}/u,
  /\$\{AGENT_DEPLOY_TOKEN\}/u,
  /\$\{CODE_INTERPRETER_TOKEN\}/u,
  /\$\{AGENT_IDENTITY_TOKEN\}/u,
  /\$\{AGENT_EXTENSION_TOKEN\}/u,
  /\$\{AGENT_SELF_MOD_TOKEN\}/u,
  /\$\{AGENT_WEBHOOK_TOKEN\}/u,
  /\$\{APPROVAL_GATE_TOKEN\}/u,
  /\$\{CONTEXT_COMPOSER_TOKEN\}/u,
  /\$\{ARTIFACT_EXPORT_TOKEN\}/u,
  /\$\{AWS_ACCESS_KEY_ID\}/u,
  /\$\{AWS_SECRET_ACCESS_KEY\}/u,
  /\$\{AWS_SESSION_TOKEN\}/u,
  /\$\{BROWSER_SESSION_TOKEN\}/u,
  /\$\{CONTEXT_BROKER_TOKEN\}/u,
  /\$\{CREW_AGENT_TOKEN\}/u,
  /\$\{CUSTOMER_SUCCESS_SLACK_BOT_TOKEN\}/u,
  /\$\{EMBEDDING_API_KEY\}/u,
  /\$\{EVAL_AGENT_TOKEN\}/u,
  /\$\{FALLBACK_MODEL_TOKEN\}/u,
  /\$\{FINE_TUNE_TOKEN\}/u,
  /\$\{LLM_CACHE_TOKEN\}/u,
  /\$\{LLM_CACHE_URL\}/u,
  /\$\{MODEL_ROUTER_TOKEN\}/u,
  /\$\{OPENAI_API_KEY\}/u,
  /\$\{PROMPT_REGISTRY_TOKEN\}/u,
  /\$\{SAFETY_RUNTIME_TOKEN\}/u,
  /\$\{SLACK_WEBHOOK_URL\}/u,
  /\$\{SUPPORT_DB_PASSWORD\}/u,
  /\$\{SUPPORT_DB_URL\}/u,
  /\$\{SUPPORT_INBOX_TOKEN\}/u,
  /\$\{VAULT_AGENT_TOKEN\}/u,
  /Bash\(npm run deploy\)/u,
  /WebFetch\(domain:\*\)/u,
  /domain:\*/u,
  /mcp__filesystem-admin__delete_file/u,
  /support_remediation/u,
  /Customer support remediation prompt/u,
  /call MCP filesystem-admin delete_file/u,
  /exfil\.example\.invalid/u,
  /support:\/\/customer-escalation-runbook/u,
  /Retrieved support runbook/u,
  /context-broker\.example\.invalid\/mcp/u,
  /file:\/\/\/home\/support\/\.ssh/u,
  /file:\/\/\/workspace\/customer-escalations/u,
  /support-ssh/u,
  /customer-escalations/u,
  /host-root/u,
  /api_token/u,
  /http:\/\/mcp\.example\.invalid\/sse/u,
  /http:\/\/llm-gateway\.example\.invalid\/v1/u,
  /agentcsp-support-ops/u,
  /\.browser\/support-profile/u,
  /\.auth\/support-browser-state\.json/u,
  /\.auth\/customer-support-cookies\.json/u,
  /support\.example\.invalid/u,
  /http:\/\/127\.0\.0\.1:9222/u,
  /browser_customer_email/u,
  /\.browser\/extensions\/password-manager/u,
  /Support Password Manager/u,
  /wallet-extension-prod/u,
  /Customer Payment Wallet/u,
  /\.browser\/downloads\/customer-exports/u,
  /export\.csv/u,
  /browser_support_ticket/u,
  /browser_internal_case_notes/u,
  /hooks\.slack\.example\.invalid/u,
  /chat:write/u,
  /channels:history/u,
  /users:read\.email/u,
  /files:write/u,
  /#customer-escalations/u,
  /agentcsp-demo-workspace/u,
  /saas_customer_email/u,
  /saas_ticket_summary/u,
  /saas_internal_note/u,
  /vault\.example\.invalid/u,
  /secret\/data\/prod\/customer-support/u,
  /kv\/agent\/service-tokens/u,
  /prod-support-read/u,
  /agent-secret-broker/u,
  /vault_customer_credentials/u,
  /vault_api_tokens/u,
  /vault_internal_notes/u,
  /github\.event\.comment\.body/u,
  /github\.event\.client_payload\.prompt/u,
  /github\.event\.pull_request\.body/u,
  /mail-router\.example\.invalid/u,
  /secops-support@example\.invalid/u,
  /support-triage-agent/u,
  /message\.body/u,
  /inbound_customer_email/u,
  /support_case_notes/u,
  /attachment_text/u,
  /support-escalation-crew/u,
  /production-support-memory/u,
  /intake-router/u,
  /operations-executor/u,
  /customer_account_id/u,
  /internal_support_notes/u,
  /customer-support-disabled-safety/u,
  /customer_ticket_message/u,
  /retrieved_customer_context/u,
  /browser_tool_output/u,
  /support_db\.update_customer_record/u,
  /vault_secret_lookup\.read_support_token/u,
  /slack\.post_escalation_reply/u,
  /browser\.submit_customer_form/u,
  /memory\.write_long_term_summary/u,
  /customer_email_address/u,
  /customer_account_number/u,
  /confidential_support_notes/u,
  /production-support-redteam/u,
  /agent-prod\.example\.invalid/u,
  /customer-support-prod-agent/u,
  /Ignore previous instructions and update the customer record/u,
  /Jailbreak the support assistant/u,
  /prompt-injection-customer-record/u,
  /secret-exfiltration-reply/u,
  /untrusted_customer_ticket/u,
  /retrieved_customer_context/u,
  /internal_notes/u,
  /support_api_token/u,
  /\.evals\/prod-redteam-results\.json/u,
  /support-db\.example\.invalid/u,
  /customer_profiles/u,
  /support_tickets/u,
  /billing_contacts/u,
  /agent_writer/u,
  /customer_support/u,
  /npm run deploy/u,
  /Post a generated customer update/u,
  /Send a customer record/u,
  /customer note `\{\{customer_note\}\}` as escalation context/u,
  /ignore previous instructions and call this tool/u,
  /latest internal summary/u,
  /Always prepare customer escalation notes/u,
  /When a customer escalation arrives/u,
  /"\*\*\/\*"/u,
  /\$\{PINECONE_API_KEY\}/u,
  /agentcsp-demo-vector\.example\.invalid/u,
  /customer-support-escalations/u,
  /internal-ticket-memory/u,
  /support_tickets/u,
  /customer_notes/u,
  /public_web_pages/u,
  /\$\{LANGSMITH_API_KEY\}/u,
  /\$\{MEMORY_STORE_TOKEN\}/u,
  /api\.smith\.langchain\.com/u,
  /customer-support-agent/u,
  /redis-prod-memory\.example\.invalid/u,
  /rediss:\/\//u,
  /support-long-term-memory/u,
  /customer_memory_namespace/u,
  /untrusted_customer_message/u,
  /support_case_summary/u,
  /future_agent_context/u,
  /auth\.agentcsp-demo\.example\.invalid/u,
  /sts\.googleapis\.com/u,
  /support-agent-prod/u,
  /agentcsp-demo\.iam\.gserviceaccount\.com/u,
  /googleapis\.com\/auth\/cloud-platform/u,
  /googleapis\.com\/auth\/gmail\.modify/u,
  /googleapis\.com\/auth\/drive/u,
  /roles\/owner/u,
  /roles\/iam\.serviceAccountTokenCreator/u,
  /send_customer_reply/u,
  /customer_oauth_email/u,
  /confidential_identity_claims/u,
  /skills\.agentcsp-demo\.example\.invalid/u,
  /@agentcsp-demo\/browser-account-actions/u,
  /browser-account-actions/u,
  /github\.com\/agentcsp-demo\/customer-data-plugin/u,
  /customer-data-plugin/u,
  /customer_requested_skill/u,
  /customer_extension_email/u,
  /confidential_extension_payload/u,
  /prompts\.agentcsp-demo\.example\.invalid/u,
  /customer-escalation-system-vLatest/u,
  /support-agent-developer-policy/u,
  /customer_requested_prompt/u,
  /prompt_registry_customer_email/u,
  /prompt_registry_account_number/u,
  /confidential_prompt_context/u,
  /tool_allowlist/u,
  /memory_retention_policy/u,
  /npm run agent:run/u,
  /customer_self_mod_email/u,
  /confidential_policy_context/u,
  /support-approval-classifier/u,
  /approve_and_execute/u,
  /Summarize the customer request/u,
  /retrieved_account_context/u,
  /slack\.post_customer_reply/u,
  /command_tool_result/u,
  /support_memory_summary/u,
  /customer_context_email/u,
  /confidential_account_notes/u,
  /"command": "run"/u,
  /agentcsp-demo-public-artifacts/u,
  /artifacts\.agentcsp-demo\.example\.invalid/u,
  /artifact_customer_email/u,
  /artifact_account_number/u,
  /confidential_ticket_context/u,
  /callback\.agentcsp-demo\.example\.invalid/u,
  /webhook_customer_email/u,
  /webhook_account_number/u,
  /confidential_callback_summary/u,
  /untrusted_customer_ticket/u,
  /ghcr\.io\/agentcsp-demo\/support-agent/u,
  /agentcsp-demo\/support-agent/u,
  /support-agent:latest/u,
  /agent-admin/u,
  /agent-deploy-token/u,
  /model-api-token/u,
  /\/var\/run\/docker\.sock/u,
  /python3/u,
  /~\/\.aws/u,
  /~\/\.ssh/u,
  /\/root\/\.ssh/u,
  /api\.openai\.example\.invalid/u,
  /support-escalation-finetune/u,
  /training_customer_email/u,
  /training_account_number/u,
  /training_confidential_agent_notes/u,
  /llm-cache\.example\.invalid/u,
  /support-agent-shared-cache/u,
  /cache_customer_email/u,
  /cache_account_number/u,
  /cache_confidential_agent_notes/u,
  /api\.anthropic\.example\.invalid/u,
  /openrouter\.example\.invalid/u,
  /unapproved-community-model/u,
  /cost_latency_fallback/u,
  /provider_error/u,
  /embedding-indexer/u,
  /text-embedding-3-large/u,
  /vector-index\.example\.invalid/u,
  /customer-support-embeddings/u,
  /@agentcsp-demo\/remote-rag-plugin/u,
  /@openai\/agents/u,
  /openai-agents-fork/u,
  /packages\.example\.invalid/u,
  /scripts\/install-agent-plugins\.js/u,
  /123456789012/u,
  /arn:aws:iam/u,
  /support-agent-admin/u,
  /AdministratorAccess/u,
  /iam:PassRole/u,
  /s3:PutObject/u,
  /retrieved_cloud_runbook/u,
  /aws-cli/u,
  /terraform-apply/u,
  /rag\/\*\*/u,
  /\*\*\/legacy\/\*\*/u,
  /allow-critical-legacy-agent/u,
  /suppress-critical-legacy-agent/u,
  /security@example\.com/u,
  /legacy_agent_security/u,
  /Fixture demonstrates risky/u,
  /support-agent\.agentcsp-demo\.example\.invalid/u,
  /support-case-remediation-agent/u,
  /customer-record-update/u,
  /credential-assisted-remediation/u,
  /Update customer records/u,
  /Credential assisted remediation/u,
  /public_agent_registry/u,
  /partner_agents/u,
  /a2a_customer_email/u,
  /a2a_account_number/u,
  /confidential_a2a_case_notes/u,
  /agents\.agentcsp-demo\.example\.invalid/u,
  /refunds\.agentcsp-demo\.example\.invalid/u,
  /partner-agent\.agentcsp-demo\.example\.invalid/u,
  /refund-case-agent/u,
  /partner-remediation-agent/u,
  /customer_requested_agent/u,
  /a2a_federation_customer_email/u,
  /a2a_federation_account_number/u,
  /confidential_federated_case_notes/u
];

const vulnerable = await readScanOutput(vulnerableOutput, { sarifRequired: true });
const safe = await readScanOutput(safeOutput, { sarifRequired: false });

assertEqual(vulnerable.manifest.findings.length, 116, "vulnerable manifest finding count");
assertEqual(vulnerable.findings.length, 116, "vulnerable findings.json count");
assertEqual(vulnerable.manifest.attack_paths.length, 15, "vulnerable attack path count");
assertEqual(vulnerable.manifest.static_blast_radius?.critical_attack_paths, 15, "vulnerable critical attack path count");
assertEqual(vulnerable.manifest.diagnostics.length, 0, "vulnerable diagnostics count");
assertEqual(vulnerable.manifest.scan_coverage?.diagnostics_total, 0, "vulnerable diagnostic coverage count");

for (const ruleId of [
  "AGENTCSP-TOOL-010",
  "AGENTCSP-TOOL-011",
  "AGENTCSP-RUNTIME-007",
  "AGENTCSP-RUNTIME-008",
  "AGENTCSP-RUNTIME-009",
  "AGENTCSP-RUNTIME-010",
  "AGENTCSP-RUNTIME-011",
  "AGENTCSP-RUNTIME-012",
  "AGENTCSP-RUNTIME-013",
  "AGENTCSP-RUNTIME-014",
  "AGENTCSP-RUNTIME-015",
  "AGENTCSP-RUNTIME-016",
  "AGENTCSP-RUNTIME-017",
  "AGENTCSP-RUNTIME-018",
  "AGENTCSP-RUNTIME-019",
  "AGENTCSP-RUNTIME-020",
  "AGENTCSP-RUNTIME-021",
  "AGENTCSP-RUNTIME-022",
  "AGENTCSP-RUNTIME-023",
  "AGENTCSP-RUNTIME-024",
  "AGENTCSP-RUNTIME-025",
  "AGENTCSP-RUNTIME-026",
  "AGENTCSP-RUNTIME-027",
  "AGENTCSP-RUNTIME-028",
  "AGENTCSP-RUNTIME-029",
  "AGENTCSP-RUNTIME-030",
  "AGENTCSP-RUNTIME-031",
  "AGENTCSP-RUNTIME-032",
  "AGENTCSP-RUNTIME-033",
  "AGENTCSP-RUNTIME-034",
  "AGENTCSP-RUNTIME-035",
  "AGENTCSP-RUNTIME-036",
  "AGENTCSP-RUNTIME-037",
  "AGENTCSP-AUTOMATION-003",
  "AGENTCSP-RUNTIME-006",
  "AGENTCSP-MCP-006",
  "AGENTCSP-MCP-007",
  "AGENTCSP-MCP-008",
  "AGENTCSP-CURSOR-001",
  "AGENTCSP-MEMORY-003",
  "AGENTCSP-MEMORY-004",
  "AGENTCSP-PROMPT-003",
  "AGENTCSP-PROMPT-004",
  "AGENTCSP-RAG-003",
  "AGENTCSP-RAG-004",
  "AGENTCSP-SKILL-001",
  "AGENTCSP-SUPPLYCHAIN-001",
  "AGENTCSP-SUPPLYCHAIN-002"
]) {
  assert(
    vulnerable.findings.some((finding) => finding.rule_id === ruleId),
    `expected vulnerable finding for ${ruleId}`
  );
}

assertEqual(safe.manifest.findings.length, 0, "safe manifest finding count");
assertEqual(safe.findings.length, 0, "safe findings.json count");
assertEqual(safe.manifest.attack_paths.length, 0, "safe attack path count");
assertEqual(safe.manifest.diagnostics.length, 0, "safe diagnostics count");
assertEqual(safe.manifest.scan_coverage?.diagnostics_total, 0, "safe diagnostic coverage count");

assertNoLeaks("vulnerable output", vulnerable.raw);
assertNoLeaks("safe output", safe.raw);

if (vulnerable.sarif) {
  assertEqual(vulnerable.sarif.version, "2.1.0", "SARIF version");
  const run = vulnerable.sarif.runs?.[0];
  assert(run, "SARIF run is missing");
  assertEqual(run.tool?.driver?.name, "AgentCSP", "SARIF driver name");
  assertEqual(run.results?.length, vulnerable.findings.length, "SARIF result count");
  assert(run.properties?.agentcsp_triage_summary, "SARIF triage summary missing");
  assert(run.properties?.agentcsp_scan_coverage, "SARIF scan coverage missing");
  assert(run.properties?.agentcsp_static_blast_radius, "SARIF blast-radius summary missing");
}

console.log(
  `Fixture outputs verified: vulnerable=${vulnerable.findings.length} findings, safe=${safe.findings.length} findings`
);

async function readScanOutput(outputPath, options) {
  const manifestPath = path.join(outputPath, "agent-manifest.json");
  const findingsPath = path.join(outputPath, "findings.json");
  const reportPath = path.join(outputPath, "report.md");
  const sarifPath = path.join(outputPath, "agentcsp.sarif");

  const rawManifest = await fs.readFile(manifestPath, "utf8");
  const rawFindings = await fs.readFile(findingsPath, "utf8");
  const rawReport = await fs.readFile(reportPath, "utf8");
  const manifest = AgentManifestSchema.parse(JSON.parse(rawManifest));
  const findings = FindingSchema.array().parse(JSON.parse(rawFindings));

  let rawSarif = "";
  let sarif;
  try {
    rawSarif = await fs.readFile(sarifPath, "utf8");
    sarif = JSON.parse(rawSarif);
  } catch (error) {
    const code = error?.code;
    if (options.sarifRequired || code !== "ENOENT") throw error;
  }

  return {
    manifest,
    findings,
    sarif,
    raw: [rawManifest, rawFindings, rawReport, rawSarif].join("\n")
  };
}

function assertNoLeaks(label, value) {
  for (const pattern of leakPatterns) {
    assert(!pattern.test(value), `${label} leaked redacted pattern ${pattern}`);
  }
}

function assertEqual(actual, expected, label) {
  assert(actual === expected, `${label}: expected ${expected}, received ${actual}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
