import {
  AgentManifestArtifactSchema,
  FindingArtifactSchema,
  type AgentManifest,
  type AgentManifestArtifact,
  type Finding,
  type FindingArtifact,
  type SurfaceObject,
  type SurfaceObjectArtifact
} from "../schemas/index.js";

export function toFindingArtifact(finding: Finding): FindingArtifact {
  const {
    matched_object,
    evidence,
    confidence_rationale: _confidenceRationale,
    risk_summary: _riskSummary,
    risk,
    ...fields
  } = finding;
  const { rationale: _riskRationale, ...compactRisk } = risk;
  return FindingArtifactSchema.parse({
    ...fields,
    risk: compactRisk,
    matched_object_ref: {
      id: matched_object.id,
      type: matched_object.type,
      name: matched_object.name,
      path: matched_object.path,
      trust_level: matched_object.trust_level
    },
    evidence_refs: evidence.map((item) => item.id).sort((a, b) => a.localeCompare(b))
  });
}

export function toFindingArtifacts(findings: Finding[]): FindingArtifact[] {
  return findings.map(toFindingArtifact).sort((a, b) => a.id.localeCompare(b.id));
}

export function toSurfaceObjectArtifact(surface: SurfaceObject): SurfaceObjectArtifact {
  const { evidence, metadata: _metadata, ...fields } = surface;
  return {
    ...fields,
    evidence_refs: evidence.map((item) => item.id).sort((a, b) => a.localeCompare(b))
  };
}

function toSurfaceObjectArtifacts(surfaces: SurfaceObject[]): SurfaceObjectArtifact[] {
  return surfaces.map(toSurfaceObjectArtifact).sort((a, b) => a.id.localeCompare(b.id));
}

export function toAgentManifestArtifact(manifest: AgentManifest): AgentManifestArtifact {
  return AgentManifestArtifactSchema.parse({
    ...manifest,
    agents: toSurfaceObjectArtifacts(manifest.agents),
    instructions: toSurfaceObjectArtifacts(manifest.instructions),
    skills: toSurfaceObjectArtifacts(manifest.skills),
    plugins: toSurfaceObjectArtifacts(manifest.plugins),
    mcp_servers: toSurfaceObjectArtifacts(manifest.mcp_servers),
    tools: toSurfaceObjectArtifacts(manifest.tools),
    prompts: toSurfaceObjectArtifacts(manifest.prompts),
    rag_sources: toSurfaceObjectArtifacts(manifest.rag_sources),
    memory: toSurfaceObjectArtifacts(manifest.memory),
    secrets: toSurfaceObjectArtifacts(manifest.secrets),
    runtime_config: toSurfaceObjectArtifacts(manifest.runtime_config),
    ci_cd: toSurfaceObjectArtifacts(manifest.ci_cd),
    automations: toSurfaceObjectArtifacts(manifest.automations),
    findings: toFindingArtifacts(manifest.findings),
    static_blast_radius: manifest.static_blast_radius
      ? {
          ...manifest.static_blast_radius,
          high_risk_objects: toSurfaceObjectArtifacts(manifest.static_blast_radius.high_risk_objects)
        }
      : undefined
  });
}
