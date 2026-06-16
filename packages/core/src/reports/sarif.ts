import type { AgentManifest, Finding, Severity } from "../schemas/index.js";

type SarifLevel = "none" | "note" | "warning" | "error";

export function renderSarifReport(manifest: AgentManifest): Record<string, unknown> {
  const rulesById = new Map<string, Finding>();
  for (const finding of manifest.findings) {
    if (!rulesById.has(finding.rule_id)) rulesById.set(finding.rule_id, finding);
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "AgentCSP",
            informationUri: "https://github.com/indranilroy99/agentcsp",
            semanticVersion: manifest.metadata.scanner.version,
            rules: [...rulesById.values()].map((finding) => ({
              id: finding.rule_id,
              name: finding.name,
              shortDescription: {
                text: finding.name
              },
              fullDescription: {
                text: finding.reason
              },
              help: {
                text: `Recommended control: ${finding.recommended_control.replaceAll("_", " ")}`,
                markdown: sarifRuleHelpMarkdown(finding)
              },
              properties: {
                category: finding.category,
                precision: precisionForFinding(finding),
                "security-severity": securitySeverity(finding.severity),
                securitySeverity: securitySeverity(finding.severity),
                tags: [
                  finding.category,
                  ...finding.maps_to.owasp,
                  ...finding.maps_to.mitre_atlas,
                  ...finding.maps_to.nist_ai_rmf
                ]
              },
              defaultConfiguration: {
                level: sarifLevel(finding.severity),
                rank: sarifRank(finding.severity)
              }
            }))
          }
        },
        automationDetails: {
          id: "agentcsp-scan"
        },
        results: manifest.findings.map((finding) => ({
          ruleId: finding.rule_id,
          level: finding.suppression?.status === "active" ? "none" : sarifLevel(finding.severity),
          rank: sarifRank(finding.severity),
          baselineState: sarifBaselineState(finding.baseline_status),
          message: {
            text: `${finding.name}: ${finding.reason} ${finding.risk_summary.impact} Recommended control: ${finding.recommended_control.replaceAll("_", " ")}.`
          },
          suppressions:
            finding.suppression?.status === "active"
              ? [
                  {
                    kind: "external",
                    status: "accepted",
                    justification: `AgentCSP policy suppression accepted this finding. Suppression reason and owner are redacted. Scope: ${finding.suppression.match_scope.replaceAll("_", " ")}. Expires: ${finding.suppression.expires_at}.`
                  }
                ]
              : undefined,
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: sarifArtifactUri(finding.file_path)
                },
                region: {
                  startLine: finding.evidence[0]?.line ?? 1
                }
              },
              logicalLocations: [
                {
                  name: finding.matched_object.name,
                  kind: finding.matched_object.type
                }
              ]
            }
          ],
          partialFingerprints: {
            agentcspFindingId: finding.id,
            agentcspObjectId: finding.matched_object.id,
            agentcspRuleObject: `${finding.rule_id}:${finding.matched_object.id}`,
            agentcspRulePath: `${finding.rule_id}:${sarifFingerprintPath(finding.file_path)}`,
            agentcspSurfacePath: `${finding.matched_object.type}:${sarifFingerprintPath(finding.file_path)}`
          },
          properties: {
            severity: finding.severity,
            category: finding.category,
            precision: precisionForFinding(finding),
            "security-severity": securitySeverity(finding.severity),
            rule_tags: [
              finding.category,
              ...finding.maps_to.owasp,
              ...finding.maps_to.mitre_atlas,
              ...finding.maps_to.nist_ai_rmf
            ],
            risk_score: finding.risk.score,
            risk_factors: finding.risk.rationale,
            risk_summary: finding.risk_summary,
            confidence: finding.confidence,
            confidence_rationale: finding.confidence_rationale,
            baseline_status: finding.baseline_status,
            policy_control: finding.policy_control,
            trust_level: finding.risk.trust_level,
            data_classes: finding.data_classes,
            actions: finding.risk.actions,
            trust_boundary_crossed: finding.trust_boundary_crossed,
            evidence_redacted: true
          }
        })),
        properties: {
          agentcsp_scan_config: manifest.metadata.config,
          agentcsp_manifest_fingerprint: manifest.metadata.fingerprint,
          agentcsp_rule_pack: manifest.metadata.rule_pack,
          agentcsp_triage_summary: manifest.triage_summary,
          agentcsp_action_plan: manifest.action_plan,
          agentcsp_ci_gate_summary: manifest.ci_gate_summary,
          agentcsp_baseline_comparison: manifest.baseline_comparison,
          agentcsp_scan_coverage: manifest.scan_coverage,
          agentcsp_diagnostics: manifest.diagnostics,
          agentcsp_static_blast_radius: manifest.static_blast_radius,
          evidence_redacted: true,
          secret_values_collected: false
        }
      }
    ]
  };
}

function sarifRuleHelpMarkdown(finding: Finding): string {
  const mappings = [
    ...finding.maps_to.owasp.map((item) => `- OWASP: ${item}`),
    ...finding.maps_to.mitre_atlas.map((item) => `- MITRE ATLAS: ${item}`),
    ...finding.maps_to.nist_ai_rmf.map((item) => `- NIST AI RMF: ${item}`)
  ];
  return [
    `### ${finding.name}`,
    "",
    finding.reason,
    "",
    `Recommended control: ${finding.recommended_control.replaceAll("_", " ")}`,
    "",
    "Mappings:",
    ...mappings
  ].join("\n");
}

function sarifBaselineState(status: Finding["baseline_status"]): "new" | "unchanged" | undefined {
  if (status === "new") return "new";
  if (status === "existing") return "unchanged";
  return undefined;
}

function sarifArtifactUri(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "<unknown>";
  if (/^file:/iu.test(trimmed)) return "<redacted-file-uri>";
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(trimmed)) return "<redacted-uri>";
  if (/^(?:\/|[A-Za-z]:[\\/]|\\\\)/u.test(trimmed)) return "<redacted-path>";
  return trimmed.replaceAll("\\", "/");
}

function sarifFingerprintPath(value: string): string {
  return sarifArtifactUri(value);
}

function sarifLevel(severity: Severity): SarifLevel {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "note";
}

function securitySeverity(severity: Severity): string {
  const scores: Record<Severity, string> = {
    info: "1.0",
    low: "3.0",
    medium: "5.5",
    high: "8.0",
    critical: "9.5"
  };
  return scores[severity];
}

function sarifRank(severity: Severity): number {
  const ranks: Record<Severity, number> = {
    info: 10,
    low: 30,
    medium: 55,
    high: 80,
    critical: 95
  };
  return ranks[severity];
}

function precisionForFinding(finding: Finding): "very-high" | "high" | "medium" {
  if (finding.confidence === "very_high") return "very-high";
  if (finding.confidence === "high") return "high";
  return "medium";
}
