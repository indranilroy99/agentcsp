import type { AgentManifest, AttackPath, Finding, SurfaceObject } from "../schemas/index.js";

export function renderMarkdownReport(manifest: AgentManifest): string {
  const counts = [
    ["Instructions", manifest.instructions.length],
    ["Skills", manifest.skills.length],
    ["Plugins", manifest.plugins.length],
    ["MCP servers", manifest.mcp_servers.length],
    ["Tools", manifest.tools.length],
    ["Secrets", manifest.secrets.length],
    ["Runtime configs", manifest.runtime_config.length],
    ["RAG sources", manifest.rag_sources.length],
    ["Memory surfaces", manifest.memory.length],
    ["CI/CD", manifest.ci_cd.length]
  ];

  return [
    "# AgentCSP Report",
    "",
    "AgentCSP scanned this project as an agent security surface. Evidence snippets are redacted by default and secret values are not collected.",
    "",
    "## Scan Metadata",
    "",
    `- Root: \`${manifest.metadata.root_path}\``,
    `- Generated: \`${manifest.metadata.generated_at}\``,
    `- Manifest schema: \`${manifest.metadata.schema_version}\``,
    `- Secret values collected: \`${manifest.metadata.config.secret_values_collected}\``,
    `- Evidence redacted: \`${manifest.metadata.config.evidence_redacted}\``,
    "",
    renderTriageSummary(manifest),
    "",
    renderBaselineComparison(manifest),
    "",
    renderScanCoverage(manifest),
    "",
    renderDiagnostics(manifest),
    "",
    "## Surface Inventory",
    "",
    ...counts.map(([label, count]) => `- ${label}: ${count}`),
    "",
    renderBlastRadius(manifest),
    "",
    renderAttackPaths(manifest.attack_paths),
    "",
    renderFindings(manifest.findings),
    "",
    "## High-Risk Objects",
    "",
    renderObjectTable(manifest.static_blast_radius?.high_risk_objects ?? []),
    "",
    "## Notes",
    "",
    "- Policy actions in this MVP are recommended controls, not runtime enforcement decisions.",
    "- The Static Blast-Radius Summary is based on discovered files and normalized metadata, not live graph traversal.",
    "- Use `.agentcspignore` to exclude project-specific generated or sensitive paths."
  ].join("\n");
}

function renderTriageSummary(manifest: AgentManifest): string {
  const summary = manifest.triage_summary;
  if (!summary) return "## Triage Summary\n\nNo triage summary was generated.";

  return [
    "## Triage Summary",
    "",
    `- Active findings: ${summary.active_findings}`,
    `- Suppressed findings: ${summary.suppressed_findings}`,
    `- Expired suppressions: ${summary.expired_suppressions}`,
    `- Highest active severity: \`${summary.highest_active_severity}\``,
    `- Max active risk score: ${summary.max_active_risk_score}`,
    "",
    "### Active Findings by Severity",
    "",
    renderSeverityCounts(summary.active_by_severity),
    "",
    "### Active Findings by Confidence",
    "",
    renderConfidenceCounts(summary.active_by_confidence),
    "",
    "### Active Findings by Surface",
    "",
    renderSurfaceCounts(summary.active_by_surface_type),
    "",
    "### Top Active Rules",
    "",
    renderTopRuleTable(summary.top_active_rules),
    "",
    "### Recommended Control Mix",
    "",
    renderControlCounts(summary.active_by_recommended_control),
    "",
    "### Top Active Risks",
    "",
    renderTopRiskTable(summary.top_active_risks)
  ].join("\n");
}

function renderDiagnostics(manifest: AgentManifest): string {
  if (manifest.diagnostics.length === 0) return "## Scan Diagnostics\n\nNo scan diagnostics were generated.";
  return [
    "## Scan Diagnostics",
    "",
    "| Severity | Code | Parser | Path | Reason |",
    "| --- | --- | --- | --- | --- |",
    ...manifest.diagnostics.map(
      (diagnostic) =>
        `| ${diagnostic.severity} | ${diagnostic.code} | ${diagnostic.parser} | \`${escapeTable(diagnostic.file_path)}\` | ${escapeTable(diagnostic.reason)} |`
    )
  ].join("\n");
}

function renderScanCoverage(manifest: AgentManifest): string {
  const coverage = manifest.scan_coverage;
  if (!coverage) return "## Scan Coverage\n\nNo scan coverage summary was generated.";

  return [
    "## Scan Coverage",
    "",
    `- Directories visited: ${coverage.directories_visited}`,
    `- Files seen: ${coverage.files_seen}`,
    `- Files indexed: ${coverage.files_indexed}`,
    `- Files skipped for size: ${coverage.files_skipped_for_size}`,
    `- Files skipped by ignore rules: ${coverage.files_skipped_by_ignore}`,
    `- Directories skipped by ignore rules: ${coverage.directories_skipped_by_ignore}`,
    `- Hidden directories skipped: ${coverage.directories_skipped_hidden}`,
    `- Log directories skipped: ${coverage.directories_skipped_logs}`,
    `- Max files reached: \`${coverage.max_files_reached}\``,
    `- Max files: ${coverage.max_files}`,
    `- Max file size bytes: ${coverage.max_file_size_bytes}`
  ].join("\n");
}

function renderBaselineComparison(manifest: AgentManifest): string {
  const comparison = manifest.baseline_comparison;
  if (!comparison) return "## Baseline Comparison\n\nNo baseline file was provided.";

  const newFindings = manifest.findings.filter((finding) => finding.baseline_status === "new");
  return [
    "## Baseline Comparison",
    "",
    `- Baseline: \`${comparison.baseline_path}\``,
    `- Baseline format: \`${comparison.baseline_format}\``,
    `- Current findings: ${comparison.current_findings}`,
    `- Baseline findings: ${comparison.baseline_findings}`,
    `- New findings: ${comparison.new_findings}`,
    `- Existing findings: ${comparison.existing_findings}`,
    `- Resolved findings: ${comparison.resolved_findings}`,
    "",
    "### New Findings",
    "",
    newFindings.length > 0 ? renderFindingTable(newFindings) : "No new findings were introduced."
  ].join("\n");
}

function renderBlastRadius(manifest: AgentManifest): string {
  const summary = manifest.static_blast_radius;
  if (!summary) return "## Static Blast-Radius Summary\n\nNo blast-radius summary was generated.";
  return [
    "## Static Blast-Radius Summary",
    "",
    `- Highest severity: \`${summary.highest_severity}\``,
    `- Read paths: ${summary.read_paths}`,
    `- Write paths: ${summary.write_paths}`,
    `- Execute paths: ${summary.execute_paths}`,
    `- External reach paths: ${summary.external_reach_paths}`,
    `- Secret reference paths: ${summary.secret_reference_paths}`,
    `- RAG surfaces: ${summary.rag_surfaces}`,
    `- Memory surfaces: ${summary.memory_surfaces}`,
    `- Relationships: ${summary.relationships}`,
    `- Attack paths: ${summary.attack_paths}`,
    `- Critical attack paths: ${summary.critical_attack_paths}`,
    `- Active suppressions: ${summary.active_suppressions}`,
    `- Expired suppressions: ${summary.expired_suppressions}`,
    "",
    "### Recommended Controls",
    "",
    summary.recommended_controls.length > 0
      ? summary.recommended_controls.map((control) => `- ${control}`).join("\n")
      : "- No recommended controls were generated."
  ].join("\n");
}

function renderSeverityCounts(counts: NonNullable<AgentManifest["triage_summary"]>["active_by_severity"]): string {
  return [
    "| Critical | High | Medium | Low | Info |",
    "| --- | --- | --- | --- | --- |",
    `| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |`
  ].join("\n");
}

function renderConfidenceCounts(counts: NonNullable<AgentManifest["triage_summary"]>["active_by_confidence"]): string {
  return [
    "| Very high | High | Medium | Low |",
    "| --- | --- | --- | --- |",
    `| ${counts.very_high} | ${counts.high} | ${counts.medium} | ${counts.low} |`
  ].join("\n");
}

function renderSurfaceCounts(
  counts: NonNullable<AgentManifest["triage_summary"]>["active_by_surface_type"]
): string {
  if (counts.length === 0) return "No active findings were generated.";
  return [
    "| Surface | Findings |",
    "| --- | --- |",
    ...counts.map((item) => `| ${item.surface_type} | ${item.count} |`)
  ].join("\n");
}

function renderControlCounts(
  counts: NonNullable<AgentManifest["triage_summary"]>["active_by_recommended_control"]
): string {
  if (counts.length === 0) return "No recommended controls were generated.";
  return [
    "| Recommended control | Findings |",
    "| --- | --- |",
    ...counts.map((item) => `| ${item.control.replaceAll("_", " ")} | ${item.count} |`)
  ].join("\n");
}

function renderTopRuleTable(
  rules: NonNullable<AgentManifest["triage_summary"]>["top_active_rules"]
): string {
  if (rules.length === 0) return "No active findings were generated.";
  return [
    "| Severity | Confidence | Rule | Category | Findings |",
    "| --- | --- | --- | --- | --- |",
    ...rules.map(
      (rule) =>
        `| ${rule.severity} | ${rule.confidence} | ${rule.rule_id} | ${escapeTable(rule.category)} | ${rule.count} |`
    )
  ].join("\n");
}

function renderTopRiskTable(
  risks: NonNullable<AgentManifest["triage_summary"]>["top_active_risks"]
): string {
  if (risks.length === 0) return "No active findings were generated.";
  return [
    "| Severity | Confidence | Risk | Rule | Object | Path | Recommended control |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...risks.map((risk) => {
      const object = `${risk.object_type}:${risk.object_name}`;
      return `| ${risk.severity} | ${risk.confidence} | ${risk.risk_score} | ${risk.rule_id} | \`${escapeTable(object)}\` | \`${escapeTable(risk.path)}\` | ${risk.recommended_control.replaceAll("_", " ")} |`;
    })
  ].join("\n");
}

function renderAttackPaths(attackPaths: AttackPath[]): string {
  if (attackPaths.length === 0) {
    return "## Static Attack Paths\n\nNo attack paths were generated by the current static model.";
  }

  return [
    "## Static Attack Paths",
    "",
    "| Severity | Confidence | Path | Recommended control |",
    "| --- | --- | --- | --- |",
    ...attackPaths.map((attackPath) => {
      const path = `${attackPath.source.type}:${attackPath.source.name} -> ${attackPath.target.type}:${attackPath.target.name}`;
      return `| ${attackPath.severity} | ${attackPath.confidence} | \`${escapeTable(path)}\` | ${attackPath.recommended_control.replaceAll("_", " ")} |`;
    })
  ].join("\n");
}

function renderFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return "## Findings\n\nNo findings were generated by the enabled rule pack.";
  }
  const activeFindings = findings.filter((finding) => finding.suppression?.status !== "active");
  const suppressedFindings = findings.filter((finding) => finding.suppression?.status === "active");

  return [
    "## Findings",
    "",
    "### Active Findings",
    "",
    activeFindings.length > 0
      ? renderFindingTable(activeFindings)
      : "No active findings remain after policy suppressions.",
    "",
    "### Suppressed Findings",
    "",
    suppressedFindings.length > 0
      ? renderSuppressedFindingTable(suppressedFindings)
      : "No active suppressions were applied."
  ].join("\n");
}

function renderFindingTable(findings: Finding[]): string {
  return [
    "| Severity | Confidence | Rule | Object | Recommended control | Policy | Risk factors |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...findings.map((finding) => {
      const factors = finding.risk.rationale.length > 0 ? finding.risk.rationale.join("; ") : "baseline rule match";
      const policy = finding.policy_control
        ? `policy override from ${finding.policy_control.previous_control.replaceAll("_", " ")}: ${finding.policy_control.reason}`
        : "";
      return `| ${finding.severity} | ${finding.confidence} | ${finding.rule_id} | \`${finding.matched_object.type}:${finding.matched_object.name}\` | ${finding.recommended_control.replaceAll("_", " ")} | ${escapeTable(policy)} | ${escapeTable(factors)} |`;
    })
  ].join("\n");
}

function renderSuppressedFindingTable(findings: Finding[]): string {
  return [
    "| Severity | Confidence | Rule | Object | Recommended control | Suppression | Expires | Owner |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...findings.map((finding) => {
      const suppression = finding.suppression;
      return `| ${finding.severity} | ${finding.confidence} | ${finding.rule_id} | \`${finding.matched_object.type}:${finding.matched_object.name}\` | ${finding.recommended_control.replaceAll("_", " ")} | ${escapeTable(suppression?.reason ?? "suppressed")} | ${suppression?.expires_at ?? "unknown"} | ${escapeTable(suppression?.owner ?? "unknown")} |`;
    })
  ].join("\n");
}

function renderObjectTable(objects: SurfaceObject[]): string {
  if (objects.length === 0) return "No high-risk objects were identified.";
  return [
    "| Type | Name | Path | Authority |",
    "| --- | --- | --- | --- |",
    ...objects.map((object) => `| ${object.type} | ${escapeTable(object.name)} | \`${object.path}\` | ${object.actions.join(", ") || "read"} |`)
  ].join("\n");
}

function escapeTable(value: string): string {
  return value.replaceAll("|", "\\|");
}
