import { z } from "zod";

export const ManifestSchemaVersion = "0.1.0";

export const TrustLevelSchema = z.enum([
  "trusted",
  "project",
  "workspace",
  "third_party",
  "untrusted",
  "unknown"
]);

export const DataClassSchema = z.enum([
  "public",
  "internal",
  "confidential",
  "secret",
  "credential",
  "pii",
  "unknown"
]);

export const ActionTypeSchema = z.enum([
  "read",
  "write",
  "execute",
  "publish",
  "send",
  "delete",
  "approve",
  "remember",
  "call"
]);

export const ControlSchema = z.enum([
  "allow",
  "deny",
  "require_approval",
  "redact",
  "quarantine",
  "warn"
]);

export const SeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export const ConfidenceSchema = z.enum(["low", "medium", "high", "very_high"]);
export const SuppressionStatusSchema = z.enum(["active", "expired"]);
export const FindingBaselineStatusSchema = z.enum(["new", "existing"]);
export const CiGateStatusSchema = z.enum(["pass", "fail"]);
export const CiGateNameSchema = z.enum(["severity", "new_findings", "expired_suppressions", "diagnostics"]);

export const SurfaceTypeSchema = z.enum([
  "agent",
  "instruction",
  "skill",
  "plugin",
  "mcp_server",
  "tool",
  "prompt",
  "rag_source",
  "memory",
  "secret",
  "runtime_config",
  "ci_cd",
  "automation"
]);

export const RiskFactorsSchema = z.object({
  trust_level: TrustLevelSchema,
  data_classes: z.array(DataClassSchema).default([]),
  actions: z.array(ActionTypeSchema).default([]),
  side_effect: z.boolean().default(false),
  reversible: z.boolean().default(true),
  external_reach: z.boolean().default(false),
  secret_exposure: z.boolean().default(false),
  untrusted_to_privileged: z.boolean().default(false),
  score: z.number().int().min(0).max(100).default(0),
  rationale: z.array(z.string()).default([])
});

export const EvidenceSchema = z.object({
  id: z.string(),
  object_id: z.string(),
  file_path: z.string(),
  line: z.number().int().positive().optional(),
  snippet: z.literal("[redacted by default]").default("[redacted by default]"),
  redacted: z.literal(true).default(true),
  reason: z.string()
});

export const ScanDiagnosticSchema = z.object({
  id: z.string(),
  severity: z.enum(["info", "warning", "error"]),
  code: z.string(),
  file_path: z.string(),
  parser: z.string(),
  reason: z.string(),
  content_redacted: z.literal(true).default(true)
});

export const SurfaceObjectSchema = z.object({
  id: z.string(),
  type: SurfaceTypeSchema,
  name: z.string(),
  path: z.string(),
  trust_level: TrustLevelSchema.default("unknown"),
  data_classes: z.array(DataClassSchema).default([]),
  actions: z.array(ActionTypeSchema).default([]),
  side_effect: z.boolean().default(false),
  reversible: z.boolean().default(true),
  external_reach: z.boolean().default(false),
  secret_exposure: z.boolean().default(false),
  untrusted_to_privileged: z.boolean().default(false),
  evidence: z.array(EvidenceSchema).default([]),
  metadata: z.record(z.unknown()).default({})
});

export const GraphNodeRefSchema = z.object({
  id: z.string(),
  type: SurfaceTypeSchema,
  name: z.string(),
  path: z.string(),
  trust_level: TrustLevelSchema
});

export const GraphRelationSchema = z.enum([
  "influences",
  "loads",
  "calls",
  "reads",
  "writes",
  "uses_secret",
  "external_reach",
  "persists",
  "triggers"
]);

export const GraphEdgeSchema = z.object({
  id: z.string(),
  source: GraphNodeRefSchema,
  target: GraphNodeRefSchema,
  relation: GraphRelationSchema,
  reason: z.string(),
  evidence: z.array(EvidenceSchema).default([])
});

export const FindingSuppressionSchema = z.object({
  id: z.string(),
  status: SuppressionStatusSchema,
  reason: z.string(),
  owner: z.string(),
  expires_at: z.string(),
  matched_on: z.array(z.string()).default([]),
  applied_at: z.string()
});

export const FindingPolicyControlSchema = z.object({
  id: z.string().optional(),
  control: ControlSchema,
  previous_control: ControlSchema,
  reason: z.string(),
  matched_on: z.array(z.string()).default([]),
  applied_at: z.string()
});

export const FindingSchema = z.object({
  id: z.string(),
  rule_id: z.string(),
  name: z.string(),
  category: z.string(),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  confidence_rationale: z.array(z.string()).default([]),
  matched_object: SurfaceObjectSchema,
  file_path: z.string(),
  reason: z.string(),
  trust_boundary_crossed: z.boolean(),
  data_classes: z.array(DataClassSchema),
  recommended_control: ControlSchema,
  risk: RiskFactorsSchema,
  maps_to: z
    .object({
      owasp: z.array(z.string()).default([]),
      mitre_atlas: z.array(z.string()).default([]),
      nist_ai_rmf: z.array(z.string()).default([])
    })
    .default({ owasp: [], mitre_atlas: [], nist_ai_rmf: [] }),
  policy_control: FindingPolicyControlSchema.optional(),
  suppression: FindingSuppressionSchema.optional(),
  baseline_status: FindingBaselineStatusSchema.optional(),
  evidence: z.array(EvidenceSchema).default([])
});

export const SeverityCountsSchema = z.object({
  critical: z.number().int().nonnegative().default(0),
  high: z.number().int().nonnegative().default(0),
  medium: z.number().int().nonnegative().default(0),
  low: z.number().int().nonnegative().default(0),
  info: z.number().int().nonnegative().default(0)
});

export const ConfidenceCountsSchema = z.object({
  very_high: z.number().int().nonnegative().default(0),
  high: z.number().int().nonnegative().default(0),
  medium: z.number().int().nonnegative().default(0),
  low: z.number().int().nonnegative().default(0)
});

export const TriageSurfaceCountSchema = z.object({
  surface_type: SurfaceTypeSchema,
  count: z.number().int().nonnegative()
});

export const TriageCategoryCountSchema = z.object({
  category: z.string(),
  count: z.number().int().nonnegative()
});

export const TriageControlCountSchema = z.object({
  control: ControlSchema,
  count: z.number().int().nonnegative()
});

export const TriageRuleSummarySchema = z.object({
  rule_id: z.string(),
  name: z.string(),
  category: z.string(),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  count: z.number().int().positive()
});

export const TriageFindingSummarySchema = z.object({
  finding_id: z.string(),
  rule_id: z.string(),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  risk_score: z.number().int().min(0).max(100),
  object_id: z.string(),
  object_type: SurfaceTypeSchema,
  object_name: z.string(),
  path: z.string(),
  recommended_control: ControlSchema
});

export const TriageSummarySchema = z.object({
  title: z.literal("AgentCSP Triage Summary").default("AgentCSP Triage Summary"),
  total_findings: z.number().int().nonnegative().default(0),
  active_findings: z.number().int().nonnegative().default(0),
  suppressed_findings: z.number().int().nonnegative().default(0),
  expired_suppressions: z.number().int().nonnegative().default(0),
  highest_active_severity: SeveritySchema.default("info"),
  max_active_risk_score: z.number().int().min(0).max(100).default(0),
  active_by_severity: SeverityCountsSchema.default({ critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
  active_by_confidence: ConfidenceCountsSchema.default({ very_high: 0, high: 0, medium: 0, low: 0 }),
  active_by_surface_type: z.array(TriageSurfaceCountSchema).default([]),
  active_by_category: z.array(TriageCategoryCountSchema).default([]),
  active_by_recommended_control: z.array(TriageControlCountSchema).default([]),
  top_active_rules: z.array(TriageRuleSummarySchema).default([]),
  top_active_risks: z.array(TriageFindingSummarySchema).default([])
});

export const BaselineComparisonSchema = z.object({
  title: z.literal("AgentCSP Baseline Comparison").default("AgentCSP Baseline Comparison"),
  baseline_path: z.string(),
  baseline_format: z.enum(["findings", "manifest"]),
  current_findings: z.number().int().nonnegative().default(0),
  baseline_findings: z.number().int().nonnegative().default(0),
  new_findings: z.number().int().nonnegative().default(0),
  existing_findings: z.number().int().nonnegative().default(0),
  resolved_findings: z.number().int().nonnegative().default(0),
  baseline_id_limit: z.number().int().positive().default(50),
  baseline_ids_truncated: z.boolean().default(false),
  new_finding_ids: z.array(z.string()).default([]),
  new_finding_ids_truncated: z.boolean().default(false),
  resolved_finding_ids: z.array(z.string()).default([]),
  resolved_finding_ids_truncated: z.boolean().default(false)
});

export const CiGateSummarySchema = z.object({
  title: z.literal("AgentCSP CI Gate Summary").default("AgentCSP CI Gate Summary"),
  status: CiGateStatusSchema.default("pass"),
  should_fail: z.boolean().default(false),
  fail_on: SeveritySchema.optional(),
  fail_on_confidence: ConfidenceSchema.optional(),
  fail_on_new: z.boolean().default(false),
  fail_on_expired_suppressions: z.boolean().default(false),
  fail_on_diagnostics: z.boolean().default(false),
  evaluated_findings: z.number().int().nonnegative().default(0),
  severity_gate_findings: z.number().int().nonnegative().default(0),
  active_suppressions_excluded: z.number().int().nonnegative().default(0),
  expired_suppression_findings: z.number().int().nonnegative().default(0),
  diagnostic_count: z.number().int().nonnegative().default(0),
  failed_gates: z.array(CiGateNameSchema).default([]),
  blocker_id_limit: z.number().int().positive().default(50),
  blocker_ids_truncated: z.boolean().default(false),
  severity_gate_finding_ids: z.array(z.string()).default([]),
  severity_gate_finding_ids_truncated: z.boolean().default(false),
  expired_suppression_finding_ids: z.array(z.string()).default([]),
  expired_suppression_finding_ids_truncated: z.boolean().default(false),
  diagnostic_ids: z.array(z.string()).default([]),
  diagnostic_ids_truncated: z.boolean().default(false)
});

export const RemediationActionSchema = z.object({
  id: z.string(),
  priority: z.number().int().positive(),
  title: z.string(),
  owner_hint: z.string(),
  owner_reason: z.string(),
  recommended_control: ControlSchema,
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  risk_score: z.number().int().min(0).max(100),
  rule_id: z.string(),
  category: z.string(),
  surface_type: SurfaceTypeSchema,
  path: z.string(),
  baseline_status: FindingBaselineStatusSchema.optional(),
  rationale: z.array(z.string()).default([]),
  related_finding_ids: z.array(z.string()).default([]),
  data_classes: z.array(DataClassSchema).default([]),
  actions: z.array(ActionTypeSchema).default([]),
  trust_boundary_crossed: z.boolean().default(false)
});

export const ActionPlanOwnerSummarySchema = z.object({
  owner_hint: z.string(),
  count: z.number().int().nonnegative(),
  highest_severity: SeveritySchema,
  max_risk_score: z.number().int().min(0).max(100)
});

export const ActionPlanSummarySchema = z.object({
  title: z.literal("AgentCSP Action Plan").default("AgentCSP Action Plan"),
  total_actions: z.number().int().nonnegative().default(0),
  total_active_findings_considered: z.number().int().nonnegative().default(0),
  max_actions: z.number().int().positive().default(12),
  omitted_actions: z.number().int().nonnegative().default(0),
  omitted_by_severity: SeverityCountsSchema.default({ critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
  omitted_highest_severity: SeveritySchema.default("info"),
  omitted_max_risk_score: z.number().int().min(0).max(100).default(0),
  truncated: z.boolean().default(false),
  immediate_actions: z.number().int().nonnegative().default(0),
  approval_actions: z.number().int().nonnegative().default(0),
  quarantine_actions: z.number().int().nonnegative().default(0),
  redaction_actions: z.number().int().nonnegative().default(0),
  warn_actions: z.number().int().nonnegative().default(0),
  new_actions: z.number().int().nonnegative().default(0),
  existing_actions: z.number().int().nonnegative().default(0),
  by_owner: z.array(ActionPlanOwnerSummarySchema).default([]),
  actions: z.array(RemediationActionSchema).default([])
});

export const AttackPathSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  source: GraphNodeRefSchema,
  target: GraphNodeRefSchema,
  edges: z.array(GraphEdgeSchema).default([]),
  reason: z.string(),
  recommended_control: ControlSchema,
  risk: RiskFactorsSchema,
  evidence: z.array(EvidenceSchema).default([])
});

export const RuleConditionSchema = z.object({
  field: z.string(),
  op: z.enum(["equals", "not_equals", "includes", "contains_any", "exists", "in", "gt", "gte", "lt", "lte"]),
  value: z.unknown().optional()
});

export const RuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  category: z.string(),
  severity: SeveritySchema,
  maps_to: z
    .object({
      owasp: z.array(z.string()).default([]),
      mitre_atlas: z.array(z.string()).default([]),
      nist_ai_rmf: z.array(z.string()).default([])
    })
    .default({ owasp: [], mitre_atlas: [], nist_ai_rmf: [] }),
  match: z.object({
    object_type: SurfaceTypeSchema.optional(),
    where: z.array(RuleConditionSchema).default([])
  }),
  recommendation: z.object({
    control: ControlSchema,
    text: z.string()
  })
});

export const PolicySchema = z.object({
  schema_version: z.string().default("0.1"),
  trust_overrides: z
    .array(
      z.object({
        path: z.string(),
        trust_level: TrustLevelSchema
      })
    )
    .default([]),
  recommended_controls: z
    .array(
      z.object({
        id: z.string().optional(),
        match: z.record(z.unknown()),
        control: ControlSchema,
        reason: z.string()
      })
    )
    .default([]),
  suppressions: z
    .array(
      z.object({
        id: z.string(),
        reason: z.string(),
        owner: z.string(),
        expires_at: z.string(),
        match: z.object({
          finding_id: z.string().optional(),
          rule_id: z.string().optional(),
          object_id: z.string().optional(),
          path: z.string().optional(),
          category: z.string().optional(),
          severity: SeveritySchema.optional()
        })
      })
    )
    .default([])
});

export const StaticBlastRadiusSummarySchema = z.object({
  title: z.literal("Static Blast-Radius Summary").default("Static Blast-Radius Summary"),
  read_paths: z.number().int().nonnegative().default(0),
  write_paths: z.number().int().nonnegative().default(0),
  execute_paths: z.number().int().nonnegative().default(0),
  external_reach_paths: z.number().int().nonnegative().default(0),
  secret_reference_paths: z.number().int().nonnegative().default(0),
  sensitive_data_external_reach_paths: z.number().int().nonnegative().default(0),
  pii_external_reach_paths: z.number().int().nonnegative().default(0),
  credential_external_reach_paths: z.number().int().nonnegative().default(0),
  sensitive_data_attack_paths: z.number().int().nonnegative().default(0),
  pii_attack_paths: z.number().int().nonnegative().default(0),
  credential_attack_paths: z.number().int().nonnegative().default(0),
  memory_surfaces: z.number().int().nonnegative().default(0),
  rag_surfaces: z.number().int().nonnegative().default(0),
  relationships: z.number().int().nonnegative().default(0),
  attack_paths: z.number().int().nonnegative().default(0),
  critical_attack_paths: z.number().int().nonnegative().default(0),
  active_suppressions: z.number().int().nonnegative().default(0),
  expired_suppressions: z.number().int().nonnegative().default(0),
  highest_severity: SeveritySchema.default("info"),
  high_risk_objects: z.array(SurfaceObjectSchema).default([]),
  recommended_controls: z.array(z.string()).default([])
});

export const ScanCoverageSummarySchema = z.object({
  title: z.literal("AgentCSP Scan Coverage").default("AgentCSP Scan Coverage"),
  scan_health: z.enum(["complete", "degraded", "incomplete"]).default("complete"),
  scan_health_reasons: z.array(z.string()).default([]),
  directories_visited: z.number().int().nonnegative().default(0),
  files_seen: z.number().int().nonnegative().default(0),
  files_indexed: z.number().int().nonnegative().default(0),
  files_skipped_for_size: z.number().int().nonnegative().default(0),
  files_skipped_by_ignore: z.number().int().nonnegative().default(0),
  directories_skipped_by_ignore: z.number().int().nonnegative().default(0),
  directories_skipped_hidden: z.number().int().nonnegative().default(0),
  directories_skipped_logs: z.number().int().nonnegative().default(0),
  diagnostics_total: z.number().int().nonnegative().default(0),
  diagnostics_errors: z.number().int().nonnegative().default(0),
  diagnostics_warnings: z.number().int().nonnegative().default(0),
  diagnostics_info: z.number().int().nonnegative().default(0),
  max_files_reached: z.boolean().default(false),
  max_files: z.number().int().positive(),
  max_file_size_bytes: z.number().int().positive()
});

export const ManifestMetadataSchema = z.object({
  schema_version: z.literal(ManifestSchemaVersion),
  generated_at: z.string(),
  root_path: z.string(),
  scanner: z.object({
    name: z.literal("agentcsp"),
    version: z.string()
  }),
  config: z.object({
    include_hidden: z.boolean(),
    include_logs: z.boolean(),
    max_file_size_bytes: z.number().int().positive(),
    evidence_redacted: z.literal(true),
    secret_values_collected: z.literal(false)
  })
});

export const AgentManifestSchema = z.object({
  metadata: ManifestMetadataSchema,
  agents: z.array(SurfaceObjectSchema).default([]),
  instructions: z.array(SurfaceObjectSchema).default([]),
  skills: z.array(SurfaceObjectSchema).default([]),
  plugins: z.array(SurfaceObjectSchema).default([]),
  mcp_servers: z.array(SurfaceObjectSchema).default([]),
  tools: z.array(SurfaceObjectSchema).default([]),
  prompts: z.array(SurfaceObjectSchema).default([]),
  rag_sources: z.array(SurfaceObjectSchema).default([]),
  memory: z.array(SurfaceObjectSchema).default([]),
  secrets: z.array(SurfaceObjectSchema).default([]),
  runtime_config: z.array(SurfaceObjectSchema).default([]),
  ci_cd: z.array(SurfaceObjectSchema).default([]),
  automations: z.array(SurfaceObjectSchema).default([]),
  relationships: z.array(GraphEdgeSchema).default([]),
  attack_paths: z.array(AttackPathSchema).default([]),
  findings: z.array(FindingSchema).default([]),
  evidence: z.array(EvidenceSchema).default([]),
  diagnostics: z.array(ScanDiagnosticSchema).default([]),
  triage_summary: TriageSummarySchema.optional(),
  action_plan: ActionPlanSummarySchema.optional(),
  baseline_comparison: BaselineComparisonSchema.optional(),
  ci_gate_summary: CiGateSummarySchema.optional(),
  scan_coverage: ScanCoverageSummarySchema.optional(),
  static_blast_radius: StaticBlastRadiusSummarySchema.optional()
});

export const ScanConfigSchema = z
  .object({
    root_path: z.string(),
    output_path: z.string().default(".agentcsp"),
    config_path: z.string().optional(),
    formats: z.array(z.enum(["json", "md", "sarif"])).default(["json", "md"]),
    include_hidden: z.boolean().default(true),
    include_logs: z.boolean().default(false),
    max_file_size_bytes: z.number().int().positive().default(1024 * 1024),
    max_files: z.number().int().positive().default(5000),
    quiet: z.boolean().default(false),
    fail_on: SeveritySchema.optional(),
    fail_on_confidence: ConfidenceSchema.optional(),
    baseline_path: z.string().optional(),
    fail_on_new: z.boolean().default(false),
    fail_on_expired_suppressions: z.boolean().default(false),
    fail_on_diagnostics: z.boolean().default(false)
  })
  .superRefine((config, context) => {
    if (config.fail_on_confidence && !config.fail_on) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["fail_on_confidence"],
        message: "fail_on_confidence requires fail_on"
      });
    }
    if (config.fail_on_new && !config.fail_on) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["fail_on_new"],
        message: "fail_on_new requires fail_on"
      });
    }
    if (config.fail_on_new && !config.baseline_path) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["fail_on_new"],
        message: "fail_on_new requires baseline_path"
      });
    }
  });

export type TrustLevel = z.infer<typeof TrustLevelSchema>;
export type DataClass = z.infer<typeof DataClassSchema>;
export type ActionType = z.infer<typeof ActionTypeSchema>;
export type Control = z.infer<typeof ControlSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type Confidence = z.infer<typeof ConfidenceSchema>;
export type SuppressionStatus = z.infer<typeof SuppressionStatusSchema>;
export type FindingBaselineStatus = z.infer<typeof FindingBaselineStatusSchema>;
export type CiGateStatus = z.infer<typeof CiGateStatusSchema>;
export type CiGateName = z.infer<typeof CiGateNameSchema>;
export type SurfaceType = z.infer<typeof SurfaceTypeSchema>;
export type RiskFactors = z.infer<typeof RiskFactorsSchema>;
export type Evidence = z.infer<typeof EvidenceSchema>;
export type ScanDiagnostic = z.infer<typeof ScanDiagnosticSchema>;
export type SurfaceObject = z.infer<typeof SurfaceObjectSchema>;
export type GraphNodeRef = z.infer<typeof GraphNodeRefSchema>;
export type GraphRelation = z.infer<typeof GraphRelationSchema>;
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;
export type AttackPath = z.infer<typeof AttackPathSchema>;
export type FindingSuppression = z.infer<typeof FindingSuppressionSchema>;
export type FindingPolicyControl = z.infer<typeof FindingPolicyControlSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type SeverityCounts = z.infer<typeof SeverityCountsSchema>;
export type ConfidenceCounts = z.infer<typeof ConfidenceCountsSchema>;
export type TriageSummary = z.infer<typeof TriageSummarySchema>;
export type RemediationAction = z.infer<typeof RemediationActionSchema>;
export type ActionPlanSummary = z.infer<typeof ActionPlanSummarySchema>;
export type BaselineComparison = z.infer<typeof BaselineComparisonSchema>;
export type CiGateSummary = z.infer<typeof CiGateSummarySchema>;
export type ScanCoverageSummary = z.infer<typeof ScanCoverageSummarySchema>;
export type Rule = z.infer<typeof RuleSchema>;
export type Policy = z.infer<typeof PolicySchema>;
export type AgentManifest = z.infer<typeof AgentManifestSchema>;
export type ScanConfig = z.infer<typeof ScanConfigSchema>;
export type StaticBlastRadiusSummary = z.infer<typeof StaticBlastRadiusSummarySchema>;
