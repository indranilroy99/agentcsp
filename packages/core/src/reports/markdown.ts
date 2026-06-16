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
    "- Root: `<scan-root>`",
    `- Generated: \`${manifest.metadata.generated_at}\``,
    `- Manifest schema: \`${manifest.metadata.schema_version}\``,
    `- Manifest fingerprint: \`${manifest.metadata.fingerprint?.value ?? "unavailable"}\``,
    `- Manifest fingerprint algorithm: \`${manifest.metadata.fingerprint?.algorithm ?? "unavailable"}\``,
    `- Manifest fingerprint excludes: ${manifest.metadata.fingerprint?.excludes.map((item) => `\`${item}\``).join(", ") ?? "none"}`,
    `- Rule pack fingerprint: \`${manifest.metadata.rule_pack.fingerprint.value}\``,
    `- Rule pack fingerprint algorithm: \`${manifest.metadata.rule_pack.fingerprint.algorithm}\``,
    `- Built-in rules loaded: ${manifest.metadata.rule_pack.built_in_rules}`,
    `- Project rules loaded: ${manifest.metadata.rule_pack.project_rules}`,
    `- Total rules loaded: ${manifest.metadata.rule_pack.total_rules}`,
    `- Project rules present: \`${manifest.metadata.rule_pack.project_rules_loaded}\``,
    `- Rule diagnostics: ${manifest.metadata.rule_pack.rule_diagnostics}`,
    `- Output formats: ${manifest.metadata.config.formats.map((format) => `\`${format}\``).join(", ")}`,
    `- Include hidden paths: \`${manifest.metadata.config.include_hidden}\``,
    `- Include logs: \`${manifest.metadata.config.include_logs}\``,
    `- Max files: ${manifest.metadata.config.max_files}`,
    `- Max file size bytes: ${manifest.metadata.config.max_file_size_bytes}`,
    `- Output path scope: \`${manifest.metadata.config.output_path_scope}\``,
    `- Policy config supplied: \`${manifest.metadata.config.config_path_configured}\``,
    `- Baseline supplied: \`${manifest.metadata.config.baseline_path_configured}\``,
    `- Severity gate: \`${manifest.metadata.config.fail_on ?? "none"}\``,
    `- Confidence gate: \`${manifest.metadata.config.fail_on_confidence ?? "none"}\``,
    `- New findings gate: \`${manifest.metadata.config.fail_on_new}\``,
    `- Expired suppressions gate: \`${manifest.metadata.config.fail_on_expired_suppressions}\``,
    `- Diagnostics gate: \`${manifest.metadata.config.fail_on_diagnostics}\``,
    `- Scan health gate: \`${manifest.metadata.config.fail_on_scan_health ?? "none"}\``,
    `- Secret values collected: \`${manifest.metadata.config.secret_values_collected}\``,
    `- Evidence redacted: \`${manifest.metadata.config.evidence_redacted}\``,
    "",
    renderTriageSummary(manifest),
    "",
    renderRulePackCoverage(manifest),
    "",
    renderActionPlan(manifest),
    "",
    renderHighestRiskBlastRadiusPaths(manifest.findings),
    "",
    renderCiGateSummary(manifest),
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

function renderRulePackCoverage(manifest: AgentManifest): string {
  const rulePack = manifest.metadata.rule_pack;
  return [
    "## Rule Pack Coverage",
    "",
    `- Fingerprint: \`${rulePack.fingerprint.value}\``,
    `- Fingerprint algorithm: \`${rulePack.fingerprint.algorithm}\``,
    `- Built-in rules: ${rulePack.built_in_rules}`,
    `- Project rules: ${rulePack.project_rules}`,
    `- Total rules: ${rulePack.total_rules}`,
    `- Rule diagnostics: ${rulePack.rule_diagnostics}`,
    "",
    "### Rule Categories",
    "",
    renderRuleCategoryTable(rulePack.by_category),
    "",
    "### Rule Severity Coverage",
    "",
    renderSeverityCounts(rulePack.by_severity),
    "",
    "### Rule Target Surfaces",
    "",
    renderRuleObjectTypeTable(rulePack.by_object_type)
  ].join("\n");
}

function renderRuleCategoryTable(categories: AgentManifest["metadata"]["rule_pack"]["by_category"]): string {
  if (categories.length === 0) return "No rule categories were loaded.";
  return [
    "| Category | Rules |",
    "| --- | --- |",
    ...categories.map((item) => `| ${escapeTable(item.category)} | ${item.count} |`)
  ].join("\n");
}

function renderRuleObjectTypeTable(objectTypes: AgentManifest["metadata"]["rule_pack"]["by_object_type"]): string {
  if (objectTypes.length === 0) return "No rule target surfaces were loaded.";
  return [
    "| Target surface | Rules |",
    "| --- | --- |",
    ...objectTypes.map((item) => `| ${escapeTable(item.object_type)} | ${item.count} |`)
  ].join("\n");
}

function renderActionPlan(manifest: AgentManifest): string {
  const plan = manifest.action_plan;
  if (!plan) return "## Action Plan\n\nNo action plan was generated.";
  if (plan.actions.length === 0) {
    return [
      "## Action Plan",
      "",
      "- Total actions: 0",
      "- Immediate actions: 0",
      "",
      "No active remediation actions were generated."
    ].join("\n");
  }

  return [
    "## Action Plan",
    "",
    `- Total actions: ${plan.total_actions}`,
    `- Active findings considered: ${plan.total_active_findings_considered}`,
    `- Max actions: ${plan.max_actions}`,
    `- Omitted actions: ${plan.omitted_actions}`,
    `- Omitted highest severity: ${plan.omitted_highest_severity}`,
    `- Omitted max risk score: ${plan.omitted_max_risk_score}`,
    `- Truncated: \`${plan.truncated}\``,
    `- Immediate actions: ${plan.immediate_actions}`,
    `- Urgent actions: ${plan.urgent_actions}`,
    `- Scheduled actions: ${plan.scheduled_actions}`,
    `- Backlog actions: ${plan.backlog_actions}`,
    `- Approval actions: ${plan.approval_actions}`,
    `- Quarantine actions: ${plan.quarantine_actions}`,
    `- Redaction actions: ${plan.redaction_actions}`,
    `- New actions: ${plan.new_actions}`,
    `- Existing actions: ${plan.existing_actions}`,
    "",
    "### Action Owners",
    "",
    renderActionOwnerTable(plan.by_owner),
    "",
    "### Omitted Action Risk",
    "",
    renderOmittedActionRiskTable(plan),
    "",
    "| Priority | Response | Severity | Risk | Baseline | Owner | Control | Rule | Surface | Path | Drivers | Validation steps | Remediation steps | Rationale |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...plan.actions.map(
      (action) =>
        `| ${action.priority} | ${action.response_tier} | ${action.severity} | ${action.risk_score} | ${action.baseline_status ?? "unbaselined"} | ${action.owner_hint} | ${action.recommended_control.replaceAll("_", " ")} | ${action.rule_id} | ${action.surface_type} | \`${escapeTable(action.path)}\` | ${escapeTable(formatRiskDrivers(action.risk_drivers))} | ${escapeTable(action.validation_steps.join("; "))} | ${escapeTable(action.remediation_steps.join("; "))} | ${escapeTable([...action.rationale, action.response_reason].join("; "))} |`
    )
  ].join("\n");
}

function renderOmittedActionRiskTable(plan: NonNullable<AgentManifest["action_plan"]>): string {
  if (plan.omitted_actions === 0) return "No active findings were omitted from the bounded action queue.";
  const counts = plan.omitted_by_severity;
  return [
    "| Omitted | Highest severity | Max risk | Critical | High | Medium | Low | Info |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    `| ${plan.omitted_actions} | ${plan.omitted_highest_severity} | ${plan.omitted_max_risk_score} | ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |`
  ].join("\n");
}

function renderActionOwnerTable(owners: NonNullable<AgentManifest["action_plan"]>["by_owner"]): string {
  if (owners.length === 0) return "No owner routing hints were generated.";
  return [
    "| Owner hint | Actions | Immediate | Urgent | Scheduled | Backlog | Highest severity | Max risk | Controls | Surfaces | Risk drivers | Top action IDs |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...owners.map(
      (owner) => {
        const controls = owner.by_recommended_control
          .map((item) => `${item.control.replaceAll("_", " ")}:${item.count}`)
          .join(", ");
        const surfaces = owner.by_surface_type.map((item) => `${item.surface_type}:${item.count}`).join(", ");
        const drivers = owner.by_risk_driver.map((item) => `${item.driver.replaceAll("_", " ")}:${item.count}`).join(", ");
        const actionIds = owner.top_action_ids.map((id) => `\`${escapeTable(id)}\``).join(", ");
        return `| ${owner.owner_hint} | ${owner.count} | ${owner.immediate_actions} | ${owner.urgent_actions} | ${owner.scheduled_actions} | ${owner.backlog_actions} | ${owner.highest_severity} | ${owner.max_risk_score} | ${escapeTable(controls)} | ${escapeTable(surfaces)} | ${escapeTable(drivers || "none")} | ${actionIds}${owner.top_action_ids_truncated ? " ..." : ""} |`;
      }
    )
  ].join("\n");
}

function formatRiskDrivers(drivers: string[]): string {
  return drivers.length > 0 ? drivers.map((driver) => driver.replaceAll("_", " ")).join(", ") : "none";
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
    `- Top active limit: ${summary.top_active_limit}`,
    `- Top active rules total: ${summary.top_active_rules_total}`,
    `- Top active rules truncated: \`${summary.top_active_rules_truncated}\``,
    `- Top active risks total: ${summary.top_active_risks_total}`,
    `- Top active risks truncated: \`${summary.top_active_risks_truncated}\``,
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
    "### Active Risk Drivers",
    "",
    renderRiskDriverCounts(summary.active_by_risk_driver),
    "",
    "### Top Active Risks",
    "",
    renderTopRiskTable(summary.top_active_risks)
  ].join("\n");
}

function renderCiGateSummary(manifest: AgentManifest): string {
  const summary = manifest.ci_gate_summary;
  if (!summary) return "## CI Gate Summary\n\nNo CI gate summary was generated.";
  const failedGates = summary.failed_gates.length > 0 ? summary.failed_gates.join(", ") : "none";
  return [
    "## CI Gate Summary",
    "",
    `- Status: \`${summary.status}\``,
    `- Should fail: \`${summary.should_fail}\``,
    `- Failed gates: ${failedGates}`,
    `- Severity threshold: \`${summary.fail_on ?? "none"}\``,
    `- Confidence threshold: \`${summary.fail_on_confidence ?? "none"}\``,
    `- New findings only: \`${summary.fail_on_new}\``,
    `- Fail on expired suppressions: \`${summary.fail_on_expired_suppressions}\``,
    `- Fail on diagnostics: \`${summary.fail_on_diagnostics}\``,
    `- Fail on scan health: \`${summary.fail_on_scan_health ?? "none"}\``,
    `- Scan health: \`${summary.scan_health}\``,
    `- Scan health reasons: ${summary.scan_health_reasons.length > 0 ? summary.scan_health_reasons.join(", ") : "none"}`,
    `- Evaluated findings: ${summary.evaluated_findings}`,
    `- Severity gate findings: ${summary.severity_gate_findings}`,
    `- Active suppressions excluded: ${summary.active_suppressions_excluded}`,
    `- Broad active suppressions: ${summary.broad_active_suppression_findings}`,
    `- Expired suppression findings: ${summary.expired_suppression_findings}`,
    `- Diagnostics: ${summary.diagnostic_count}`,
    `- Blocker ID limit: ${summary.blocker_id_limit}`,
    `- Blocker IDs truncated: \`${summary.blocker_ids_truncated}\``,
    "",
    "### CI Gate Blockers",
    "",
    renderGateBlockerSummary(summary),
    "",
    "### CI Gate Blocker Mix",
    "",
    renderGateBlockerMix(summary),
    "",
    "### Diagnostic Mix",
    "",
    renderDiagnosticMix(summary),
    "",
    "### Suppression Review Posture",
    "",
    renderSuppressionReviewPosture(summary),
    "",
    "### CI Gate Risk Drivers",
    "",
    renderGateRiskDrivers(summary),
    "",
    renderGateBlockers(summary)
  ].join("\n");
}

function renderGateBlockerSummary(summary: NonNullable<AgentManifest["ci_gate_summary"]>): string {
  return [
    "| Blocker list | Total | IDs shown | Truncated |",
    "| --- | --- | --- | --- |",
    `| severity/new finding | ${summary.severity_gate_findings} | ${summary.severity_gate_finding_ids.length} | \`${summary.severity_gate_finding_ids_truncated}\` |`,
    `| expired suppression | ${summary.expired_suppression_findings} | ${summary.expired_suppression_finding_ids.length} | \`${summary.expired_suppression_finding_ids_truncated}\` |`,
    `| diagnostic | ${summary.diagnostic_count} | ${summary.diagnostic_ids.length} | \`${summary.diagnostic_ids_truncated}\` |`
  ].join("\n");
}

function renderDiagnosticMix(summary: NonNullable<AgentManifest["ci_gate_summary"]>): string {
  if (summary.diagnostic_mix.length === 0) return "No diagnostics were generated.";
  return [
    "| Severity | Parser | Code | Count |",
    "| --- | --- | --- | --- |",
    ...summary.diagnostic_mix.map(
      (item) => `| ${item.severity} | ${escapeTable(item.parser)} | ${escapeTable(item.code)} | ${item.count} |`
    )
  ].join("\n");
}

function renderGateBlockerMix(summary: NonNullable<AgentManifest["ci_gate_summary"]>): string {
  return [
    "| Blocker set | Critical | High | Medium | Low | Info | Very high confidence | High confidence | Medium confidence | Low confidence |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    `| severity/new finding | ${summary.severity_gate_by_severity.critical} | ${summary.severity_gate_by_severity.high} | ${summary.severity_gate_by_severity.medium} | ${summary.severity_gate_by_severity.low} | ${summary.severity_gate_by_severity.info} | ${summary.severity_gate_by_confidence.very_high} | ${summary.severity_gate_by_confidence.high} | ${summary.severity_gate_by_confidence.medium} | ${summary.severity_gate_by_confidence.low} |`,
    `| active suppression exclusion | ${summary.active_suppressions_by_severity.critical} | ${summary.active_suppressions_by_severity.high} | ${summary.active_suppressions_by_severity.medium} | ${summary.active_suppressions_by_severity.low} | ${summary.active_suppressions_by_severity.info} | n/a | n/a | n/a | n/a |`,
    `| expired suppression | ${summary.expired_suppression_by_severity.critical} | ${summary.expired_suppression_by_severity.high} | ${summary.expired_suppression_by_severity.medium} | ${summary.expired_suppression_by_severity.low} | ${summary.expired_suppression_by_severity.info} | n/a | n/a | n/a | n/a |`
  ].join("\n");
}

function renderSuppressionReviewPosture(summary: NonNullable<AgentManifest["ci_gate_summary"]>): string {
  const scopes = summary.active_suppressions_by_scope;
  const broad = summary.broad_active_suppression_by_severity;
  const ids = summary.broad_active_suppression_finding_ids;
  return [
    "| Scope | Active suppressions |",
    "| --- | --- |",
    `| specific finding | ${scopes.specific_finding} |`,
    `| specific object | ${scopes.specific_object} |`,
    `| rule and path | ${scopes.rule_and_path} |`,
    `| rule | ${scopes.rule} |`,
    `| path | ${scopes.path} |`,
    `| category | ${scopes.category} |`,
    `| severity | ${scopes.severity} |`,
    `| broad | ${scopes.broad} |`,
    "",
    "| Broad active suppression severity | Critical | High | Medium | Low | Info | IDs shown | Truncated |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    `| broad active suppression | ${broad.critical} | ${broad.high} | ${broad.medium} | ${broad.low} | ${broad.info} | ${ids.length} | \`${summary.broad_active_suppression_finding_ids_truncated}\` |`
  ].join("\n");
}

function renderGateRiskDrivers(summary: NonNullable<AgentManifest["ci_gate_summary"]>): string {
  const rows = [
    ...summary.severity_gate_by_risk_driver.map((item) => ({ set: "severity/new finding", ...item })),
    ...summary.expired_suppression_by_risk_driver.map((item) => ({ set: "expired suppression", ...item }))
  ];
  if (rows.length === 0) return "No CI gate risk drivers were generated.";
  return [
    "| Blocker set | Driver | Findings | Max risk | Critical | High | Medium | Low | Info |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...rows.map(
      (item) =>
        `| ${item.set} | ${item.driver.replaceAll("_", " ")} | ${item.count} | ${item.max_risk_score} | ${item.by_severity.critical} | ${item.by_severity.high} | ${item.by_severity.medium} | ${item.by_severity.low} | ${item.by_severity.info} |`
    )
  ].join("\n");
}

function renderGateBlockers(summary: NonNullable<AgentManifest["ci_gate_summary"]>): string {
  const rows: Array<[string, string]> = [
    ...summary.severity_gate_finding_ids.map((id): [string, string] => ["severity/new finding", id]),
    ...summary.broad_active_suppression_finding_ids.map((id): [string, string] => ["broad active suppression", id]),
    ...summary.expired_suppression_finding_ids.map((id): [string, string] => ["expired suppression", id]),
    ...summary.diagnostic_ids.map((id): [string, string] => ["diagnostic", id])
  ];
  if (rows.length === 0) return "No CI gate blockers were identified.";
  return [
    "| Gate | ID |",
    "| --- | --- |",
    ...rows.map(([gate, id]) => `| ${gate} | \`${escapeTable(id)}\` |`)
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
    `- Scan health: \`${coverage.scan_health}\``,
    `- Scan health reasons: ${coverage.scan_health_reasons.length > 0 ? coverage.scan_health_reasons.join(", ") : "none"}`,
    `- Directories visited: ${coverage.directories_visited}`,
    `- Files seen: ${coverage.files_seen}`,
    `- Files indexed: ${coverage.files_indexed}`,
    `- Files skipped for size: ${coverage.files_skipped_for_size}`,
    `- Files skipped by ignore rules: ${coverage.files_skipped_by_ignore}`,
    `- Directories skipped by ignore rules: ${coverage.directories_skipped_by_ignore}`,
    `- Hidden directories skipped: ${coverage.directories_skipped_hidden}`,
    `- Log directories skipped: ${coverage.directories_skipped_logs}`,
    `- Diagnostics: ${coverage.diagnostics_total}`,
    `- Diagnostic errors: ${coverage.diagnostics_errors}`,
    `- Diagnostic warnings: ${coverage.diagnostics_warnings}`,
    `- Diagnostic info: ${coverage.diagnostics_info}`,
    `- Max files reached: \`${coverage.max_files_reached}\``,
    `- Max files: ${coverage.max_files}`,
    `- Max file size bytes: ${coverage.max_file_size_bytes}`,
    `- Skipped path preview limit: ${coverage.skipped_path_limit}`,
    `- Oversized file paths truncated: \`${coverage.oversized_file_paths_truncated}\``,
    "",
    "### Oversized Files",
    "",
    renderOversizedFilePaths(coverage)
  ].join("\n");
}

function renderOversizedFilePaths(coverage: NonNullable<AgentManifest["scan_coverage"]>): string {
  if (coverage.oversized_file_paths.length === 0) return "No oversized files were skipped.";
  return [
    "| Path |",
    "| --- |",
    ...coverage.oversized_file_paths.map((filePath) => `| \`${escapeTable(filePath)}\` |`)
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
    `- Baseline fingerprint: \`${comparison.baseline_fingerprint?.value ?? "unavailable"}\``,
    `- Baseline fingerprint algorithm: \`${comparison.baseline_fingerprint?.algorithm ?? "unavailable"}\``,
    `- Current findings: ${comparison.current_findings}`,
    `- Baseline findings: ${comparison.baseline_findings}`,
    `- New findings: ${comparison.new_findings}`,
    `- Existing findings: ${comparison.existing_findings}`,
    `- Resolved findings: ${comparison.resolved_findings}`,
    `- Baseline ID limit: ${comparison.baseline_id_limit}`,
    `- Baseline IDs truncated: \`${comparison.baseline_ids_truncated}\``,
    `- New finding IDs truncated: \`${comparison.new_finding_ids_truncated}\``,
    `- Resolved finding IDs truncated: \`${comparison.resolved_finding_ids_truncated}\``,
    "",
    "### New Finding Drift Mix",
    "",
    renderBaselineDriftMix(comparison),
    "",
    "### New Finding Risk Drivers",
    "",
    renderBaselineRiskDrivers(comparison),
    "",
    "### New Findings",
    "",
    newFindings.length > 0 ? renderFindingTable(newFindings) : "No new findings were introduced."
  ].join("\n");
}

function renderBaselineDriftMix(comparison: NonNullable<AgentManifest["baseline_comparison"]>): string {
  return [
    "| Critical | High | Medium | Low | Info | Very high confidence | High confidence | Medium confidence | Low confidence |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    `| ${comparison.new_findings_by_severity.critical} | ${comparison.new_findings_by_severity.high} | ${comparison.new_findings_by_severity.medium} | ${comparison.new_findings_by_severity.low} | ${comparison.new_findings_by_severity.info} | ${comparison.new_findings_by_confidence.very_high} | ${comparison.new_findings_by_confidence.high} | ${comparison.new_findings_by_confidence.medium} | ${comparison.new_findings_by_confidence.low} |`
  ].join("\n");
}

function renderBaselineRiskDrivers(comparison: NonNullable<AgentManifest["baseline_comparison"]>): string {
  if (comparison.new_findings_by_risk_driver.length === 0) {
    return "No new finding risk drivers were generated.";
  }
  return [
    "| Driver | New findings | Max risk | Critical | High | Medium | Low | Info |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...comparison.new_findings_by_risk_driver.map(
      (item) =>
        `| ${item.driver.replaceAll("_", " ")} | ${item.count} | ${item.max_risk_score} | ${item.by_severity.critical} | ${item.by_severity.high} | ${item.by_severity.medium} | ${item.by_severity.low} | ${item.by_severity.info} |`
    )
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
    `- Sensitive-data external reach paths: ${summary.sensitive_data_external_reach_paths}`,
    `- PII external reach paths: ${summary.pii_external_reach_paths}`,
    `- Credential external reach paths: ${summary.credential_external_reach_paths}`,
    `- RAG surfaces: ${summary.rag_surfaces}`,
    `- Memory surfaces: ${summary.memory_surfaces}`,
    `- Relationships: ${summary.relationships}`,
    `- Attack paths: ${summary.attack_paths}`,
    `- Attack path limit: ${summary.attack_path_limit}`,
    `- Attack paths total: ${summary.attack_paths_total}`,
    `- Attack paths truncated: \`${summary.attack_paths_truncated}\``,
    `- Critical attack paths: ${summary.critical_attack_paths}`,
    `- Sensitive-data attack paths: ${summary.sensitive_data_attack_paths}`,
    `- PII attack paths: ${summary.pii_attack_paths}`,
    `- Credential attack paths: ${summary.credential_attack_paths}`,
    `- Active suppressions: ${summary.active_suppressions}`,
    `- Expired suppressions: ${summary.expired_suppressions}`,
    `- Preview limit: ${summary.preview_limit}`,
    `- High-risk objects total: ${summary.high_risk_objects_total}`,
    `- High-risk objects shown: ${summary.high_risk_objects.length}`,
    `- High-risk objects truncated: \`${summary.high_risk_objects_truncated}\``,
    `- Recommended controls total: ${summary.recommended_controls_total}`,
    `- Recommended controls shown: ${summary.recommended_controls.length}`,
    `- Recommended controls truncated: \`${summary.recommended_controls_truncated}\``,
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

function renderRiskDriverCounts(
  counts: NonNullable<AgentManifest["triage_summary"]>["active_by_risk_driver"]
): string {
  if (counts.length === 0) return "No active risk drivers were generated.";
  return [
    "| Driver | Findings | Max risk | Critical | High | Medium | Low | Info |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...counts.map(
      (item) =>
        `| ${item.driver.replaceAll("_", " ")} | ${item.count} | ${item.max_risk_score} | ${item.by_severity.critical} | ${item.by_severity.high} | ${item.by_severity.medium} | ${item.by_severity.low} | ${item.by_severity.info} |`
    )
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
    "| Severity | Confidence | Risk | Drivers | Impact | Trust | Data | Actions | External | Secret | Untrusted->privileged | Boundary | Rule | Object | Path | Recommended control |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...risks.map((risk) => {
      const object = `${risk.object_type}:${risk.object_name}`;
      const dataClasses = risk.data_classes.length > 0 ? risk.data_classes.join(", ") : "none";
      const actions = risk.actions.length > 0 ? risk.actions.join(", ") : "none";
      const drivers = risk.risk_drivers.length > 0 ? risk.risk_drivers.map((driver) => driver.replaceAll("_", " ")).join(", ") : "none";
      return `| ${risk.severity} | ${risk.confidence} | ${risk.risk_score} | ${escapeTable(drivers)} | ${escapeTable(risk.impact)} | ${risk.trust_level} | ${escapeTable(dataClasses)} | ${escapeTable(actions)} | \`${risk.external_reach}\` | \`${risk.secret_exposure}\` | \`${risk.untrusted_to_privileged}\` | \`${risk.trust_boundary_crossed}\` | ${risk.rule_id} | \`${escapeTable(object)}\` | \`${escapeTable(risk.path)}\` | ${risk.recommended_control.replaceAll("_", " ")} |`;
    })
  ].join("\n");
}

function renderHighestRiskBlastRadiusPaths(findings: Finding[]): string {
  const activeFindings = findings
    .filter((finding) => finding.suppression?.status !== "active")
    .filter((finding) =>
      finding.matched_object.untrusted_to_privileged ||
      finding.matched_object.secret_exposure ||
      finding.matched_object.external_reach ||
      !finding.matched_object.reversible ||
      finding.matched_object.data_classes.some((dataClass) => ["credential", "secret", "pii"].includes(dataClass))
    )
    .sort(compareFindingsForBlastRadius)
    .slice(0, 12);

  if (activeFindings.length === 0) {
    return "## Highest-Risk Blast-Radius Paths\n\nNo active high-risk blast-radius paths were identified.";
  }

  return [
    "## Highest-Risk Blast-Radius Paths",
    "",
    "| Risk | Severity | Rule | Object | Boundary | Data | Actions | Recommended control |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...activeFindings.map((finding) => {
      const object = `${finding.matched_object.type}:${finding.matched_object.name}`;
      return [
        finding.risk.score,
        finding.severity,
        finding.rule_id,
        `\`${escapeTable(object)}\``,
        escapeTable(summarizeFindingBoundary(finding)),
        escapeTable(summarizeFindingData(finding)),
        escapeTable(summarizeFindingActions(finding)),
        finding.recommended_control.replaceAll("_", " ")
      ].join(" | ");
    }).map((row) => `| ${row} |`)
  ].join("\n");
}

function compareFindingsForBlastRadius(a: Finding, b: Finding): number {
  const riskCompare = b.risk.score - a.risk.score;
  if (riskCompare !== 0) return riskCompare;
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const severityCompare = severityOrder[a.severity] - severityOrder[b.severity];
  if (severityCompare !== 0) return severityCompare;
  const confidenceOrder = { very_high: 0, high: 1, medium: 2, low: 3 };
  const confidenceCompare = confidenceOrder[a.confidence] - confidenceOrder[b.confidence];
  if (confidenceCompare !== 0) return confidenceCompare;
  return a.id.localeCompare(b.id);
}

function summarizeFindingBoundary(finding: Finding): string {
  const object = finding.matched_object;
  const boundaries = [
    object.untrusted_to_privileged ? "untrusted -> privileged" : "",
    object.secret_exposure ? "secret exposure" : "",
    object.external_reach ? "external reach" : "",
    object.side_effect ? "side effect" : "",
    !object.reversible ? "irreversible" : ""
  ].filter(Boolean);
  return boundaries.length > 0 ? boundaries.join("; ") : "rule-defined authority boundary";
}

function summarizeFindingData(finding: Finding): string {
  const dataClasses = finding.matched_object.data_classes.length > 0
    ? finding.matched_object.data_classes
    : finding.risk.data_classes;
  return dataClasses.length > 0 ? dataClasses.join(", ") : "not classified";
}

function summarizeFindingActions(finding: Finding): string {
  const actions = finding.matched_object.actions.length > 0 ? finding.matched_object.actions : finding.risk.actions;
  return actions.length > 0 ? actions.join(", ") : "read";
}

function renderAttackPaths(attackPaths: AttackPath[]): string {
  if (attackPaths.length === 0) {
    return "## Static Attack Paths\n\nNo attack paths were generated by the current static model.";
  }

  return [
    "## Static Attack Paths",
    "",
    "| Severity | Confidence | Route | Path | Recommended control |",
    "| --- | --- | --- | --- | --- |",
    ...attackPaths.map((attackPath) => {
      const path = `${attackPath.source.type}:${attackPath.source.name} -> ${attackPath.target.type}:${attackPath.target.name}`;
      return `| ${attackPath.severity} | ${attackPath.confidence} | ${escapeTable(attackPath.title)} | \`${escapeTable(path)}\` | ${attackPath.recommended_control.replaceAll("_", " ")} |`;
    })
  ].join("\n");
}

function renderFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return "## Findings\n\nNo findings were generated by the enabled rule pack.";
  }
  const activeFindings = findings.filter((finding) => finding.suppression?.status !== "active");
  const suppressedFindings = findings.filter((finding) => finding.suppression?.status === "active");
  const expiredSuppressionFindings = findings.filter((finding) => finding.suppression?.status === "expired");

  return [
    "## Findings",
    "",
    "### Expired Suppressions",
    "",
    expiredSuppressionFindings.length > 0
      ? renderSuppressedFindingTable(expiredSuppressionFindings)
      : "No expired suppressions were applied.",
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
    "| Severity | Confidence | Rule | Object | Recommended control | Policy | Risk drivers | Analyst summary | Risk factors |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...findings.map((finding) => {
      const factors = finding.risk.rationale.length > 0 ? finding.risk.rationale.join("; ") : "baseline rule match";
      const policy = finding.policy_control
        ? `policy override from ${finding.policy_control.previous_control.replaceAll("_", " ")}: ${finding.policy_control.reason}`
        : "";
      const riskDrivers = finding.risk_summary.drivers.map((driver) => driver.replaceAll("_", " ")).join(", ") || "none";
      const analystSummary = finding.risk_summary.analyst_summary.join("; ");
      return `| ${finding.severity} | ${finding.confidence} | ${finding.rule_id} | \`${finding.matched_object.type}:${finding.matched_object.name}\` | ${finding.recommended_control.replaceAll("_", " ")} | ${escapeTable(policy)} | ${escapeTable(riskDrivers)} | ${escapeTable(analystSummary)} | ${escapeTable(factors)} |`;
    })
  ].join("\n");
}

function renderSuppressedFindingTable(findings: Finding[]): string {
  return [
    "| Severity | Confidence | Rule | Object | Recommended control | Suppression status | Scope | Matched on | Expires |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...findings.map((finding) => {
      const suppression = finding.suppression;
      const matchedOn = suppression?.matched_on.length ? suppression.matched_on.join(", ") : "unknown";
      const matchScope = suppression?.match_scope ? suppression.match_scope.replaceAll("_", " ") : "unknown";
      return `| ${finding.severity} | ${finding.confidence} | ${finding.rule_id} | \`${finding.matched_object.type}:${finding.matched_object.name}\` | ${finding.recommended_control.replaceAll("_", " ")} | ${suppression?.status ?? "unknown"} | ${matchScope} | ${escapeTable(matchedOn)} | ${suppression?.expires_at ?? "unknown"} |`;
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
