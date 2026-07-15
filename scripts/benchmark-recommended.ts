import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { detectSurfaces } from "../packages/core/src/scanner/detect.js";
import { loadBuiltInRuleCatalog } from "../packages/core/src/rules/catalog.js";
import { runRules } from "../packages/core/src/rules/engine.js";

interface BenchmarkCase {
  id: string;
  expected: boolean;
  relativePath: string;
  content: string;
  rationale: string;
}

const ruleId = "AGENTCSP-RUNTIME-001";
const cases = benchmarkCases();
const rules = await loadBuiltInRuleCatalog();
const rule = rules.find((candidate) => candidate.id === ruleId);
if (!rule) throw new Error(`${ruleId} is missing from the built-in catalog`);

const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-rule-benchmark-"));
const actualPath = path.join(temporaryDirectory, "case-input");
const outcomes: Array<BenchmarkCase & { predicted: boolean }> = [];

try {
  for (const benchmarkCase of cases) {
    await fs.writeFile(actualPath, benchmarkCase.content, "utf8");
    const surfaces = await detectSurfaces([
      {
        absolutePath: actualPath,
        relativePath: benchmarkCase.relativePath,
        size: Buffer.byteLength(benchmarkCase.content),
        skippedForSize: false
      }
    ]);
    const predicted = runRules(surfaces, [rule]).some((finding) => finding.rule_id === ruleId);
    outcomes.push({ ...benchmarkCase, predicted });
  }
} finally {
  await fs.rm(temporaryDirectory, { recursive: true, force: true });
}

const truePositives = outcomes.filter((item) => item.expected && item.predicted).length;
const falsePositives = outcomes.filter((item) => !item.expected && item.predicted).length;
const falseNegatives = outcomes.filter((item) => item.expected && !item.predicted).length;
const trueNegatives = outcomes.filter((item) => !item.expected && !item.predicted).length;
const precision = ratio(truePositives, truePositives + falsePositives);
const recall = ratio(truePositives, truePositives + falseNegatives);
const precisionWilsonLowerBound = wilsonLowerBound(truePositives, truePositives + falsePositives);
const failures = outcomes
  .filter((item) => item.expected !== item.predicted)
  .map((item) => ({ id: item.id, expected: item.expected, predicted: item.predicted, rationale: item.rationale }));

const result = {
  schema_version: "0.1.0",
  benchmark: "agentcsp-runtime-001-parser-conformance",
  evaluation_class: "synthetic_conformance",
  enforcement_eligible: false,
  limitation:
    "Template-generated cases verify parser and rule behavior. They are not an independent labeled corpus and do not establish production precision.",
  rule_id: ruleId,
  cases: cases.length,
  positive_labels: cases.filter((item) => item.expected).length,
  negative_opportunities: cases.filter((item) => !item.expected).length,
  true_positives: truePositives,
  false_positives: falsePositives,
  false_negatives: falseNegatives,
  true_negatives: trueNegatives,
  precision,
  precision_wilson_lower_bound_95_descriptive_only: precisionWilsonLowerBound,
  recall,
  thresholds: {
    minimum_positive_predictions: 50,
    minimum_negative_opportunities: 100,
    minimum_precision: 0.98,
    minimum_precision_wilson_lower_bound_95_descriptive_only: 0.9,
    minimum_recall: 0.85
  },
  failures
};

console.log(JSON.stringify(result, null, 2));

if (
  truePositives + falsePositives < result.thresholds.minimum_positive_predictions ||
  result.negative_opportunities < result.thresholds.minimum_negative_opportunities ||
  precision < result.thresholds.minimum_precision ||
  precisionWilsonLowerBound < result.thresholds.minimum_precision_wilson_lower_bound_95_descriptive_only ||
  recall < result.thresholds.minimum_recall ||
  failures.length > 0
) {
  process.exitCode = 1;
}

function benchmarkCases(): BenchmarkCase[] {
  const positives = Array.from({ length: 50 }, (_, index) => positiveCase(index));
  const negatives = Array.from({ length: 100 }, (_, index) => negativeCase(index));
  return [...positives, ...negatives];
}

function positiveCase(index: number): BenchmarkCase {
  const sandboxValues = ["danger-full-access", "disabled", "none", "off"];
  const approvalValues = ["never", "disabled", "none", "auto-approve"];
  const formats = ["toml", "json", "yaml"] as const;
  const format = formats[index % formats.length] ?? "toml";
  const sandbox = sandboxValues[index % sandboxValues.length] ?? "danger-full-access";
  const approval = approvalValues[Math.floor(index / sandboxValues.length) % approvalValues.length] ?? "never";
  return {
    id: `positive-${String(index + 1).padStart(3, "0")}`,
    expected: true,
    relativePath: runtimePath(index, format),
    content: runtimeContent(format, sandbox, approval),
    rationale: "Structured runtime configuration explicitly disables both sandbox isolation and approval gating."
  };
}

function negativeCase(index: number): BenchmarkCase {
  const formats = ["toml", "json", "yaml"] as const;
  const format = formats[index % formats.length] ?? "toml";
  const category = index % 5;
  if (category === 0) {
    return {
      id: `negative-safe-${String(index + 1).padStart(3, "0")}`,
      expected: false,
      relativePath: runtimePath(index, format),
      content: runtimeContent(format, "workspace-write", "required"),
      rationale: "Sandbox and approval controls are both present."
    };
  }
  if (category === 1) {
    return {
      id: `negative-sandbox-only-${String(index + 1).padStart(3, "0")}`,
      expected: false,
      relativePath: runtimePath(index, format),
      content: runtimeContent(format, "danger-full-access", "required"),
      rationale: "Sandbox is disabled, but approval remains required; the conjunction is not satisfied."
    };
  }
  if (category === 2) {
    return {
      id: `negative-approval-only-${String(index + 1).padStart(3, "0")}`,
      expected: false,
      relativePath: runtimePath(index, format),
      content: runtimeContent(format, "read-only", "never"),
      rationale: "Approval is bypassed, but the runtime remains sandboxed; the conjunction is not satisfied."
    };
  }
  if (category === 3) {
    return {
      id: `negative-near-miss-${String(index + 1).padStart(3, "0")}`,
      expected: false,
      relativePath: runtimePath(index, format),
      content: runtimeContent(format, "full-isolation", "auto-deny"),
      rationale: "Values containing risky substrings do not carry the corresponding unsafe semantics."
    };
  }
  return {
    id: `negative-unrelated-${String(index + 1).padStart(3, "0")}`,
    expected: false,
    relativePath: runtimePath(index, format),
    content: unrelatedContent(format),
    rationale: "Configuration contains no sandbox-disable or approval-bypass fields."
  };
}

function runtimePath(index: number, format: "toml" | "json" | "yaml"): string {
  const roots = [".codex", ".agents", ".claude", ".cursor"];
  const root = roots[index % roots.length] ?? ".codex";
  const name = format === "toml" ? "config.toml" : format === "json" ? "settings.json" : "runtime.yaml";
  return `${root}/${name}`;
}

function runtimeContent(format: "toml" | "json" | "yaml", sandbox: string, approval: string): string {
  if (format === "json") return `${JSON.stringify({ sandbox, approval_policy: approval }, null, 2)}\n`;
  if (format === "yaml") return `sandbox: ${sandbox}\napproval_policy: ${approval}\n`;
  return `sandbox = "${sandbox}"\napproval_policy = "${approval}"\n`;
}

function unrelatedContent(format: "toml" | "json" | "yaml"): string {
  if (format === "json") return '{"model":"local","telemetry":false}\n';
  if (format === "yaml") return "model: local\ntelemetry: false\n";
  return 'model = "local"\ntelemetry = false\n';
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

function wilsonLowerBound(successes: number, samples: number, z = 1.959963984540054): number {
  if (samples === 0) return 0;
  const proportion = successes / samples;
  const denominator = 1 + (z * z) / samples;
  const center = proportion + (z * z) / (2 * samples);
  const margin = z * Math.sqrt((proportion * (1 - proportion) + (z * z) / (4 * samples)) / samples);
  return (center - margin) / denominator;
}
