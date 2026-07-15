import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { scanProject } from "../packages/core/src/scanner/scan.js";

const targetFiles = 5_000;
const targetBytes = 100 * 1024 * 1024;
const bytesPerFile = Math.ceil(targetBytes / targetFiles);
const benchmarkRuns = 5;
const maximumP95DurationMs = 15_000;
const maximumRssBytes = 512 * 1024 * 1024;
const maximumPrimaryArtifactBytes = 10 * 1024 * 1024;
const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-scale-"));
const projectRoot = path.join(temporaryRoot, "project");
const outputRoot = path.join(temporaryRoot, "output");
const payload = Buffer.alloc(bytesPerFile, 0x61);

let peakRssBytes = process.memoryUsage().rss;
const memorySampler = setInterval(() => {
  peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
}, 20);
memorySampler.unref();

try {
  await fs.mkdir(projectRoot, { recursive: true });
  for (let start = 0; start < targetFiles; start += 100) {
    const end = Math.min(start + 100, targetFiles);
    await Promise.all(
      Array.from({ length: end - start }, (_, offset) => {
        const index = start + offset;
        return fs.writeFile(path.join(projectRoot, `source-${String(index).padStart(5, "0")}.txt`), payload);
      })
    );
  }

  const durationsMs: number[] = [];
  let result: Awaited<ReturnType<typeof scanProject>> | undefined;
  for (let run = 0; run < benchmarkRuns; run += 1) {
    const startedAt = performance.now();
    result = await scanProject({
      root_path: projectRoot,
      output_path: outputRoot,
      profile: "advisory",
      artifact_profile: "portable",
      ruleset: "recommended",
      formats: ["json"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 256 * 1024,
      max_files: targetFiles,
      quiet: true
    });
    durationsMs.push(performance.now() - startedAt);
  }
  if (!result) throw new Error("Scale benchmark did not execute.");
  const sortedDurationsMs = [...durationsMs].sort((a, b) => a - b);
  const p95DurationMs = sortedDurationsMs[Math.ceil(sortedDurationsMs.length * 0.95) - 1]!;
  peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
  const manifestBytes = (await fs.stat(result.outputFiles.manifest!)).size;
  const findingsBytes = (await fs.stat(result.outputFiles.findings!)).size;
  const primaryArtifactBytes = manifestBytes + findingsBytes;
  const indexedBytes = bytesPerFile * targetFiles;

  const report = {
    schema_version: "0.1.0",
    benchmark: "agentcsp-v0.2-scale-envelope",
    target: {
      files: targetFiles,
      runs: benchmarkRuns,
      indexed_bytes_minimum: targetBytes,
      duration_p95_ms_maximum: maximumP95DurationMs,
      rss_bytes_maximum: maximumRssBytes,
      primary_artifact_bytes_maximum: maximumPrimaryArtifactBytes
    },
    observed: {
      files_indexed: result.manifest.scan_coverage?.files_indexed,
      indexed_bytes: indexedBytes,
      duration_samples_ms: durationsMs.map((durationMs) => Math.round(durationMs)),
      duration_p95_ms: Math.round(p95DurationMs),
      peak_rss_bytes: peakRssBytes,
      scan_health: result.manifest.scan_coverage?.scan_health,
      max_files_reached: result.manifest.scan_coverage?.max_files_reached,
      primary_artifact_bytes: primaryArtifactBytes,
      findings: result.findings.length
    }
  };

  console.log(JSON.stringify(report, null, 2));

  assert(result.manifest.scan_coverage?.files_indexed === targetFiles, "file coverage did not reach the target");
  assert(result.manifest.scan_coverage?.scan_health === "complete", "scan health was not complete");
  assert(result.manifest.scan_coverage?.max_files_reached === false, "max-files was reported at the exact envelope");
  assert(indexedBytes >= targetBytes, "indexed byte target was not reached");
  assert(p95DurationMs <= maximumP95DurationMs, "scan exceeded the release p95 duration budget");
  assert(peakRssBytes <= maximumRssBytes, "scan exceeded the release memory budget");
  assert(primaryArtifactBytes <= maximumPrimaryArtifactBytes, "portable JSON exceeded the release artifact budget");
} finally {
  clearInterval(memorySampler);
  payload.fill(0);
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
