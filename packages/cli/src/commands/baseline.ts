import fs from "node:fs/promises";
import path from "node:path";
import {
  createBaselineEnvelopeFromFile,
  diffBaselineEnvelopes,
  type BaselineEnvelope
} from "@agentcsp/core";

export async function runBaselineCreate(
  sourcePath: string,
  options: { out: string; json?: boolean }
): Promise<void> {
  const baseline = await createBaselineEnvelopeFromFile(sourcePath);
  const outputPath = path.resolve(options.out);
  await writeJsonAtomic(outputPath, baseline);
  if (options.json) {
    console.log(JSON.stringify({ type: "agentcsp_baseline_created", path: outputPath, findings: baseline.findings.length }));
  } else {
    console.log(`[PASS] Baseline created with ${baseline.findings.length} finding identity record(s): ${outputPath}`);
  }
}

export async function runBaselineDiff(
  baselinePath: string,
  currentPath: string,
  options: { json?: boolean }
): Promise<void> {
  const baseline = await createBaselineEnvelopeFromFile(baselinePath);
  const current = await createBaselineEnvelopeFromFile(currentPath);
  const diff = diffBaselineEnvelopes(baseline, current);
  if (options.json) {
    console.log(JSON.stringify({ type: "agentcsp_baseline_diff", ...diff }));
    return;
  }
  console.log(`Baseline diff: ${diff.added.length} added, ${diff.removed.length} removed, ${diff.unchanged.length} unchanged`);
  for (const id of diff.added.slice(0, 20)) console.log(`  + ${id}`);
  for (const id of diff.removed.slice(0, 20)) console.log(`  - ${id}`);
}

export async function runBaselineMigrate(
  sourcePath: string,
  options: { out: string; json?: boolean }
): Promise<void> {
  await runBaselineCreate(sourcePath, options);
}

async function writeJsonAtomic(outputPath: string, value: BaselineEnvelope): Promise<void> {
  const parentPath = path.dirname(outputPath);
  const temporaryPath = path.join(parentPath, `.${path.basename(outputPath)}.${process.pid}.tmp`);
  await fs.mkdir(parentPath, { recursive: true, mode: 0o700 });
  try {
    await fs.writeFile(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await fs.rename(temporaryPath, outputPath);
  } finally {
    await fs.unlink(temporaryPath).catch(() => undefined);
  }
}
