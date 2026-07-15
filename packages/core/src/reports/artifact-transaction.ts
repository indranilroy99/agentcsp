import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { AgentCspError } from "../errors.js";
import {
  ArtifactReceiptSchema,
  type ArtifactProfile,
  type ArtifactReceipt
} from "../schemas/index.js";

const ownershipMarkerName = ".agentcsp-owned";
const ownershipMarkerContent = "agentcsp-artifact-set-v1\n";
const receiptName = "receipt.json";
const maxReceiptBytes = 1024 * 1024;
const maxManagedArtifacts = 32;

export interface ArtifactPayload {
  name: string;
  content: string;
}

export interface PublishedArtifactSet {
  files: Record<string, string>;
  receipt: ArtifactReceipt;
  receiptPath: string;
}

export async function publishArtifactSet(input: {
  outputPath: string;
  artifactProfile: ArtifactProfile;
  artifacts: ArtifactPayload[];
}): Promise<PublishedArtifactSet> {
  const outputPath = path.resolve(input.outputPath);
  const parentPath = path.dirname(outputPath);
  const transactionId = `${process.pid}-${randomUUID()}`;
  const stagePath = path.join(parentPath, `${path.basename(outputPath)}.stage-${transactionId}`);
  const backupPath = path.join(parentPath, `${path.basename(outputPath)}.previous-${transactionId}`);
  const lockPath = path.join(parentPath, `${path.basename(outputPath)}.lock`);
  let lock: Awaited<ReturnType<typeof fs.open>> | undefined;
  let lockAcquired = false;
  let movedExistingOutput = false;

  await fs.mkdir(parentPath, { recursive: true, mode: 0o700 });
  try {
    try {
      lock = await fs.open(lockPath, "wx", 0o600);
      lockAcquired = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new AgentCspError({
          code: "AGENTCSP-E3002",
          kind: "integrity",
          problem: "Another AgentCSP artifact transaction is active for this output path.",
          fix: "Wait for the active scan to finish. Remove a stale lock only after confirming no scan is running.",
          help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#artifact-transactions",
          cause: error
        });
      }
      throw error;
    }

    await fs.mkdir(stagePath, { mode: 0o700 });
    const files: ArtifactReceipt["files"] = [];
    for (const artifact of [...input.artifacts].sort((a, b) => a.name.localeCompare(b.name))) {
      assertSafeArtifactName(artifact.name);
      validateArtifactContent(artifact);
      const content = ensureTrailingNewline(artifact.content);
      await fs.writeFile(path.join(stagePath, artifact.name), content, { encoding: "utf8", mode: 0o600, flag: "wx" });
      files.push({
        name: artifact.name,
        size_bytes: Buffer.byteLength(content),
        sha256: createHash("sha256").update(content).digest("hex")
      });
    }

    const receipt = ArtifactReceiptSchema.parse({
      schema_version: "0.1.0",
      status: "complete",
      generated_at: new Date().toISOString(),
      artifact_profile: input.artifactProfile,
      files
    });
    await fs.writeFile(path.join(stagePath, "receipt.json"), `${JSON.stringify(receipt, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx"
    });

    await fs.writeFile(path.join(stagePath, ownershipMarkerName), ownershipMarkerContent, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx"
    });

    if (await pathEntryExists(outputPath)) {
      await fs.rename(outputPath, backupPath);
      movedExistingOutput = true;
      await assertReplaceableOutput(backupPath);
    }
    await fs.rename(stagePath, outputPath);
    if (movedExistingOutput) await fs.rm(backupPath, { recursive: true, force: true });

    return {
      files: Object.fromEntries(input.artifacts.map((artifact) => [artifact.name, path.join(outputPath, artifact.name)])),
      receipt,
      receiptPath: path.join(outputPath, "receipt.json")
    };
  } catch (error) {
    await fs.rm(stagePath, { recursive: true, force: true }).catch(() => undefined);
    if (movedExistingOutput && !(await pathEntryExists(outputPath)) && (await pathEntryExists(backupPath))) {
      await fs.rename(backupPath, outputPath).catch(() => undefined);
    }
    throw error;
  } finally {
    await lock?.close().catch(() => undefined);
    if (lockAcquired) await fs.unlink(lockPath).catch(() => undefined);
  }
}

function assertSafeArtifactName(name: string): void {
  if (path.basename(name) !== name || name === "." || name === "..") {
    throw new AgentCspError({
      code: "AGENTCSP-E4002",
      kind: "internal",
      problem: "Artifact generation produced an unsafe output name.",
      fix: "Report this error code with the pinned AgentCSP version.",
      help: "https://github.com/indranilroy99/agentcsp/issues"
    });
  }
}

function validateArtifactContent(artifact: ArtifactPayload): void {
  if (artifact.name.endsWith(".json") || artifact.name.endsWith(".sarif")) {
    try {
      JSON.parse(artifact.content);
    } catch (error) {
      throw new AgentCspError({
        code: "AGENTCSP-E4003",
        kind: "internal",
        problem: `Generated ${artifact.name} is not valid JSON.`,
        fix: "Report this error code with the pinned AgentCSP version.",
        help: "https://github.com/indranilroy99/agentcsp/issues",
        cause: error
      });
    }
  }
}

function ensureTrailingNewline(content: string): string {
  return content.endsWith("\n") ? content : `${content}\n`;
}

async function pathEntryExists(candidate: string): Promise<boolean> {
  try {
    await fs.lstat(candidate);
    return true;
  } catch {
    return false;
  }
}

async function assertReplaceableOutput(candidate: string): Promise<void> {
  const stats = await fs.lstat(candidate);
  if (!stats.isDirectory() || stats.isSymbolicLink()) throw outputOwnershipError();

  const entries = await fs.readdir(candidate, { withFileTypes: true });
  if (entries.length === 0) return;
  if (entries.length > maxManagedArtifacts + 2) throw outputOwnershipError();
  if (entries.some((entry) => !entry.isFile())) throw outputOwnershipError();

  let marker: string;
  let receiptContent: string;
  try {
    const receiptStats = await fs.lstat(path.join(candidate, receiptName));
    if (!receiptStats.isFile() || receiptStats.size > maxReceiptBytes) throw outputOwnershipError();
    [marker, receiptContent] = await Promise.all([
      fs.readFile(path.join(candidate, ownershipMarkerName), "utf8"),
      fs.readFile(path.join(candidate, receiptName), "utf8")
    ]);
  } catch (error) {
    if (error instanceof AgentCspError) throw error;
    throw outputOwnershipError(error);
  }
  if (marker !== ownershipMarkerContent) throw outputOwnershipError();

  let receipt: ArtifactReceipt;
  try {
    receipt = ArtifactReceiptSchema.parse(JSON.parse(receiptContent));
  } catch (error) {
    throw outputOwnershipError(error);
  }
  if (receipt.status !== "complete" || receipt.files.length > maxManagedArtifacts) {
    throw outputOwnershipError();
  }

  const managedNames = new Set([ownershipMarkerName, receiptName]);
  for (const file of receipt.files) {
    try {
      assertSafeArtifactName(file.name);
    } catch (error) {
      throw outputOwnershipError(error);
    }
    if (managedNames.has(file.name)) throw outputOwnershipError();
    managedNames.add(file.name);
  }
  const entryNames = new Set(entries.map((entry) => entry.name));
  if (entryNames.size !== managedNames.size || [...entryNames].some((name) => !managedNames.has(name))) {
    throw outputOwnershipError();
  }

  for (const file of receipt.files) {
    const artifactPath = path.join(candidate, file.name);
    const artifactStats = await fs.lstat(artifactPath);
    if (!artifactStats.isFile() || artifactStats.size !== file.size_bytes) throw outputOwnershipError();
    if ((await sha256File(artifactPath)) !== file.sha256) throw outputOwnershipError();
  }
}

async function sha256File(filePath: string): Promise<string> {
  const handle = await fs.open(filePath, "r");
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
    return hash.digest("hex");
  } finally {
    buffer.fill(0);
    await handle.close();
  }
}

function outputOwnershipError(cause?: unknown): AgentCspError {
  return new AgentCspError({
    code: "AGENTCSP-E3006",
    kind: "integrity",
    problem: "Existing output is not an intact AgentCSP-managed artifact directory.",
    fix: "Choose an empty output directory or remove unknown files only after preserving any data you need.",
    help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#artifact-transactions",
    cause
  });
}
