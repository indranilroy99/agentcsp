import { describe, expect, it } from "vitest";
import { buildCiGateSummary, ciGateBlockerIdLimit } from "../src/reports/gates.js";
import type { Finding, ScanConfig, ScanDiagnostic } from "../src/schemas/index.js";

describe("CI gate summary", () => {
  it("reports blocker ID truncation for bounded CI previews", () => {
    const findings = Array.from({ length: ciGateBlockerIdLimit + 3 }, (_, index) =>
      finding(`finding_${index.toString().padStart(3, "0")}`)
    );
    const diagnostics = Array.from({ length: ciGateBlockerIdLimit + 2 }, (_, index) =>
      diagnostic(`diagnostic_${index.toString().padStart(3, "0")}`)
    );

    const summary = buildCiGateSummary({
      findings,
      diagnostics,
      config: {
        root_path: ".",
        output_path: ".agentcsp",
        formats: ["json"],
        include_hidden: true,
        include_logs: false,
        max_file_size_bytes: 1024 * 1024,
        max_files: 5000,
        quiet: true,
        fail_on: "high",
        fail_on_diagnostics: true
      } satisfies ScanConfig
    });

    expect(summary).toMatchObject({
      status: "fail",
      blocker_id_limit: ciGateBlockerIdLimit,
      blocker_ids_truncated: true,
      severity_gate_findings: ciGateBlockerIdLimit + 3,
      severity_gate_finding_ids_truncated: true,
      diagnostic_count: ciGateBlockerIdLimit + 2,
      diagnostic_ids_truncated: true,
      expired_suppression_findings: 0,
      expired_suppression_finding_ids_truncated: false
    });
    expect(summary.severity_gate_finding_ids).toHaveLength(ciGateBlockerIdLimit);
    expect(summary.diagnostic_ids).toHaveLength(ciGateBlockerIdLimit);
    expect(summary.severity_gate_finding_ids[0]).toBe("finding_000");
    expect(summary.diagnostic_ids[0]).toBe("diagnostic_000");
  });
});

function finding(id: string): Finding {
  return {
    id,
    severity: "high",
    confidence: "high",
    suppression: undefined
  } as Finding;
}

function diagnostic(id: string): ScanDiagnostic {
  return {
    id,
    code: "TEST_DIAGNOSTIC",
    severity: "warning",
    message: "Synthetic diagnostic for gate summary regression.",
    path: "<test>",
    content_redacted: true
  };
}
