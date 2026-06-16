import { describe, expect, it } from "vitest";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";

describe("static graph", () => {
  it("generates bounded, high-signal attack paths", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/vulnerable-agent"),
      output_path: "/private/tmp/agentcsp-graph-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.relationships.length).toBeGreaterThan(0);
    expect(result.manifest.attack_paths.length).toBeGreaterThan(0);
    expect(result.manifest.attack_paths.length).toBeLessThanOrEqual(15);
    expect(result.manifest.static_blast_radius?.attack_path_limit).toBe(15);
    expect(result.manifest.static_blast_radius?.attack_paths_total).toBeGreaterThanOrEqual(
      result.manifest.attack_paths.length
    );
    expect(result.manifest.static_blast_radius?.attack_paths_truncated).toBe(
      (result.manifest.static_blast_radius?.attack_paths_total ?? 0) > result.manifest.attack_paths.length
    );
    expect(result.manifest.static_blast_radius?.critical_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.attack_paths.every((path) => path.evidence.every((item) => item.redacted))).toBe(true);

    const influenceEdges = result.manifest.relationships.filter((edge) => edge.relation === "influences");
    expect(influenceEdges.length).toBeGreaterThan(0);
    expect(influenceEdges.every((edge) => edge.reason.includes("Specific context signal"))).toBe(true);
    expect(
      result.manifest.relationships.some(
        (edge) =>
          edge.relation === "calls" &&
          edge.source.path === ".codex/config.toml" &&
          edge.target.name === "filesystem-admin"
      )
    ).toBe(true);
    expect(
      result.manifest.relationships.some(
        (edge) =>
          edge.relation === "triggers" &&
          edge.source.path === ".github/workflows/agent-maintenance.yml" &&
          edge.target.name === "package-script:agent:run"
      )
    ).toBe(true);
    const runtimeDeployEdge = result.manifest.relationships.find(
      (edge) =>
        edge.relation === "triggers" &&
        edge.source.path === ".claude/settings.json" &&
        edge.target.name === "package-script:deploy"
    );
    expect(runtimeDeployEdge).toBeDefined();
    expect(runtimeDeployEdge?.reason).toContain("auto-approves this package script");
    const runtimeDeployPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === ".claude/settings.json" &&
        attackPath.target.name === "package-script:deploy" &&
        attackPath.title === "settings.json can auto-approve package-script:deploy"
    );
    expect(runtimeDeployPath).toBeDefined();
    expect(runtimeDeployPath?.severity).toBe("critical");
    expect(runtimeDeployPath?.confidence).toBe("very_high");
    expect(runtimeDeployPath?.recommended_control).toBe("require_approval");
    expect(runtimeDeployPath?.reason).toContain("auto-approves a package script");
    expect(JSON.stringify(runtimeDeployPath)).not.toContain("npm run deploy");
    const runtimeDestructiveMcpPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === ".claude/settings.json" &&
        attackPath.target.name === "filesystem-admin" &&
        attackPath.title === "settings.json can auto-approve destructive MCP on filesystem-admin"
    );
    expect(runtimeDestructiveMcpPath).toBeDefined();
    expect(runtimeDestructiveMcpPath?.severity).toBe("critical");
    expect(runtimeDestructiveMcpPath?.confidence).toBe("very_high");
    expect(runtimeDestructiveMcpPath?.recommended_control).toBe("require_approval");
    expect(runtimeDestructiveMcpPath?.reason).toContain("auto-approves a destructive MCP tool");
    expect(JSON.stringify(runtimeDestructiveMcpPath)).not.toContain("mcp__filesystem-admin__delete_file");
    const promptToolEdge = result.manifest.relationships.find(
      (edge) =>
        edge.relation === "influences" &&
        edge.source.path === "prompts/support-ticket.prompt.md" &&
        edge.target.name === "publish_summary"
    );
    expect(promptToolEdge).toBeDefined();
    expect(promptToolEdge?.reason).toContain("explicit tool reference");
    const promptExplicitToolPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "prompts/support-ticket.prompt.md" &&
        attackPath.target.name === "publish_summary" &&
        attackPath.title === "support-ticket.prompt.md can route untrusted input to publish_summary"
    );
    expect(promptExplicitToolPath).toBeDefined();
    expect(promptExplicitToolPath?.severity).toBe("critical");
    expect(promptExplicitToolPath?.confidence).toBe("very_high");
    expect(promptExplicitToolPath?.recommended_control).toBe("require_approval");
    expect(promptExplicitToolPath?.reason).toContain("explicit tool reference");
    expect(promptExplicitToolPath?.reason).toContain("specific agent-callable capability");
    expect(JSON.stringify(promptExplicitToolPath)).not.toContain("Review ticket");
    const memoryExplicitToolPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "memory/release-notes.md" &&
        attackPath.target.name === "publish_summary" &&
        attackPath.title === "release-notes.md can replay memory into publish_summary"
    );
    expect(memoryExplicitToolPath).toBeDefined();
    expect(memoryExplicitToolPath?.severity).toBe("critical");
    expect(memoryExplicitToolPath?.confidence).toBe("very_high");
    expect(memoryExplicitToolPath?.recommended_control).toBe("quarantine");
    expect(memoryExplicitToolPath?.reason).toContain("cross-session replay path");
    expect(JSON.stringify(memoryExplicitToolPath)).not.toContain("maintenance shortcut");
    expect(result.manifest.relationships.some((edge) => edge.source.path === "rag")).toBe(false);
    expect(result.manifest.relationships.some((edge) => edge.source.path === "memory")).toBe(false);
    expect(
      result.manifest.attack_paths.some(
        (attackPath) =>
          attackPath.source.path === "rag/customer-note.md" &&
          attackPath.target.name === "support-db.yaml" &&
          attackPath.reason.includes("tool directive")
      )
    ).toBe(true);
    const ragDatabaseAuthorityPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "rag/customer-note.md" &&
        attackPath.target.name === "support-db.yaml" &&
        attackPath.title ===
          "customer-note.md can influence support-db.yaml: Agent database connector exposes credential-backed sensitive writes"
    );
    expect(ragDatabaseAuthorityPath).toBeDefined();
    expect(ragDatabaseAuthorityPath?.severity).toBe("critical");
    expect(ragDatabaseAuthorityPath?.confidence).toBe("very_high");
    expect(ragDatabaseAuthorityPath?.recommended_control).toBe("require_approval");
    expect(ragDatabaseAuthorityPath?.reason).toContain("direct path from untrusted context to mutable records");
    expect(ragDatabaseAuthorityPath?.risk.data_classes).toContain("pii");
    expect(ragDatabaseAuthorityPath?.risk.actions).toEqual(["call", "delete", "execute", "read", "send", "write"]);
    expect(ragDatabaseAuthorityPath?.risk.external_reach).toBe(true);
    expect(JSON.stringify(ragDatabaseAuthorityPath)).not.toContain("customer_profiles");
    const ragDataEgressPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "rag/customer-note.md" &&
        attackPath.target.name === "publish_summary" &&
        attackPath.title === "customer-note.md can route sensitive context to publish_summary"
    );
    expect(ragDataEgressPath).toBeDefined();
    expect(ragDataEgressPath?.severity).toBe("critical");
    expect(ragDataEgressPath?.confidence).toBe("very_high");
    expect(ragDataEgressPath?.recommended_control).toBe("quarantine");
    expect(ragDataEgressPath?.reason).toContain("data-egress directive");
    expect(ragDataEgressPath?.reason).toContain("concrete exfiltration path");
    expect(ragDataEgressPath?.risk.data_classes).toContain("confidential");
    expect(ragDataEgressPath?.risk.external_reach).toBe(true);
    expect(JSON.stringify(ragDataEgressPath)).not.toContain("latest internal summary");
    const ragAgentOrchestrationPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "rag/customer-note.md" &&
        attackPath.target.name === "support-crew.yaml" &&
        attackPath.title ===
          "customer-note.md can influence support-crew.yaml: Multi-agent delegation routes untrusted context to privileged agents"
    );
    expect(ragAgentOrchestrationPath).toBeDefined();
    expect(ragAgentOrchestrationPath?.severity).toBe("critical");
    expect(ragAgentOrchestrationPath?.confidence).toBe("very_high");
    expect(ragAgentOrchestrationPath?.recommended_control).toBe("require_approval");
    expect(ragAgentOrchestrationPath?.risk.data_classes).toContain("pii");
    expect(ragAgentOrchestrationPath?.risk.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(ragAgentOrchestrationPath)).not.toContain("support-escalation-crew");
    expect(JSON.stringify(ragAgentOrchestrationPath)).not.toContain("operations-executor");
    const ragAiEvalHarnessPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "rag/customer-note.md" &&
        attackPath.target.name === "live-redteam.yaml" &&
        attackPath.title === "customer-note.md can influence live-redteam.yaml: Live eval harness runs adversarial prompts against privileged agents"
    );
    expect(ragAiEvalHarnessPath).toBeDefined();
    expect(ragAiEvalHarnessPath?.severity).toBe("critical");
    expect(ragAiEvalHarnessPath?.confidence).toBe("very_high");
    expect(ragAiEvalHarnessPath?.recommended_control).toBe("require_approval");
    expect(ragAiEvalHarnessPath?.risk.data_classes).toContain("pii");
    expect(ragAiEvalHarnessPath?.risk.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(ragAiEvalHarnessPath)).not.toContain("production-support-redteam");
    expect(JSON.stringify(ragAiEvalHarnessPath)).not.toContain("agent-prod.example.invalid");
    expect(JSON.stringify(ragAiEvalHarnessPath)).not.toContain("prompt-injection-customer-record");
    const ragInboundTriggerPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "rag/customer-note.md" &&
        attackPath.target.name === "support-triage.yaml" &&
        attackPath.title === "customer-note.md can influence support-triage.yaml: Inbound untrusted message can drive privileged agent tools"
    );
    expect(ragInboundTriggerPath).toBeDefined();
    expect(ragInboundTriggerPath?.severity).toBe("critical");
    expect(ragInboundTriggerPath?.confidence).toBe("very_high");
    expect(ragInboundTriggerPath?.recommended_control).toBe("require_approval");
    expect(ragInboundTriggerPath?.risk.data_classes).toContain("pii");
    expect(ragInboundTriggerPath?.risk.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(ragInboundTriggerPath)).not.toContain("mail-router.example.invalid");
    expect(JSON.stringify(ragInboundTriggerPath)).not.toContain("support-triage-agent");
    const ragAgentSafetyPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.target.name === "agent-safety.yaml" &&
        attackPath.title.endsWith(
          "can influence agent-safety.yaml: Disabled agent safety controls expose privileged tools to untrusted context"
        )
    );
    expect(ragAgentSafetyPath).toBeDefined();
    expect(ragAgentSafetyPath?.severity).toBe("critical");
    expect(ragAgentSafetyPath?.confidence).toBe("very_high");
    expect(ragAgentSafetyPath?.recommended_control).toBe("require_approval");
    expect(ragAgentSafetyPath?.reason).toContain("agent safety or guardrail configuration");
    expect(ragAgentSafetyPath?.risk.data_classes).toContain("pii");
    expect(ragAgentSafetyPath?.risk.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(ragAgentSafetyPath?.risk.external_reach).toBe(true);
    expect(JSON.stringify(ragAgentSafetyPath)).not.toContain("customer-support-disabled-safety");
    expect(JSON.stringify(ragAgentSafetyPath)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(ragAgentSafetyPath)).not.toContain("customer_email_address");
  });

  it("correlates generated-state replay with privileged capability paths when logs are included", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/vulnerable-agent"),
      output_path: "/private/tmp/agentcsp-graph-log-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: true,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const transcriptPaths = result.manifest.attack_paths.filter(
      (attackPath) => attackPath.source.path === "logs/session-transcript.txt"
    );
    expect(transcriptPaths).toHaveLength(1);

    const replayPath = transcriptPaths[0];
    expect(replayPath).toBeDefined();
    expect(replayPath?.title).toBe("session-transcript.txt can replay generated state into publish_summary");
    expect(replayPath?.target.name).toBe("publish_summary");
    expect(replayPath?.severity).toBe("critical");
    expect(replayPath?.confidence).toBe("very_high");
    expect(replayPath?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(replayPath)).not.toContain("Ignore previous repository instructions");
  });

  it("does not create graph paths from negated safety policy text", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/safe-agent"),
      output_path: "/private/tmp/agentcsp-graph-safe-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.relationships).toHaveLength(0);
    expect(result.manifest.attack_paths).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });
});
