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
                text: `Recommended control: ${finding.recommended_control.replaceAll("_", " ")}`
              },
              properties: {
                category: finding.category,
                precision: precisionForFinding(finding),
                securitySeverity: securitySeverity(finding.severity),
                tags: [
                  finding.category,
                  ...finding.maps_to.owasp,
                  ...finding.maps_to.mitre_atlas,
                  ...finding.maps_to.nist_ai_rmf
                ]
              },
              defaultConfiguration: {
                level: sarifLevel(finding.severity)
              }
            }))
          }
        },
        results: manifest.findings.map((finding) => ({
          ruleId: finding.rule_id,
          level: finding.suppression?.status === "active" ? "none" : sarifLevel(finding.severity),
          message: {
            text: `${finding.name}: ${finding.reason} Recommended control: ${finding.recommended_control.replaceAll("_", " ")}.`
          },
          suppressions:
            finding.suppression?.status === "active"
              ? [
                  {
                    kind: "external",
                    status: "accepted",
                    justification: `${finding.suppression.reason} Owner: ${finding.suppression.owner}. Expires: ${finding.suppression.expires_at}.`
                  }
                ]
              : undefined,
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.file_path
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
            agentcspObjectId: finding.matched_object.id
          },
          properties: {
            severity: finding.severity,
            category: finding.category,
            risk_score: finding.risk.score,
            risk_factors: finding.risk.rationale,
            confidence: finding.confidence,
            confidence_rationale: finding.confidence_rationale,
            policy_control: finding.policy_control,
            trust_level: finding.risk.trust_level,
            data_classes: finding.data_classes,
            actions: finding.risk.actions,
            trust_boundary_crossed: finding.trust_boundary_crossed,
            evidence_redacted: true
          }
        }))
      }
    ]
  };
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

function precisionForFinding(finding: Finding): "very-high" | "high" | "medium" {
  if (finding.confidence === "very_high") return "very-high";
  if (finding.confidence === "high") return "high";
  return "medium";
}
