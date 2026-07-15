import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { AgentCspError } from "../errors.js";
import { isPathInsideRoot } from "../utils/paths.js";

export interface VerifiedTrustedInput {
  path: string;
  real_path: string;
  sha256: string;
  size: number;
  content: Buffer;
}

export async function verifyTrustedInput(input: {
  rootPath: string;
  inputPath: string;
  expectedSha256: string;
  label: "policy" | "baseline";
  maxBytes: number;
}): Promise<VerifiedTrustedInput> {
  const resolvedRoot = await realPathOrResolved(input.rootPath);
  const resolvedInput = path.resolve(input.inputPath);
  let realInput: string;
  let stats: Awaited<ReturnType<typeof fs.stat>>;
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;

  try {
    realInput = await fs.realpath(resolvedInput);
    handle = await fs.open(realInput, "r");
    stats = await handle.stat();
  } catch (error) {
    await handle?.close().catch(() => undefined);
    throw new AgentCspError({
      code: "AGENTCSP-E1001",
      kind: "input",
      problem: `Trusted ${input.label} input could not be read.`,
      fix: `Provide an existing ${input.label} file outside the scanned checkout and recompute its SHA-256 digest.`,
      help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#trusted-inputs",
      cause: error
    });
  }
  if (!handle) throw new Error("Trusted input file handle was not opened.");

  try {
    if (!stats.isFile()) {
      throw new AgentCspError({
        code: "AGENTCSP-E1002",
        kind: "configuration",
        problem: `Trusted ${input.label} input is not a regular file.`,
        fix: `Provide a regular ${input.label} file outside the scanned checkout.`,
        help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#trusted-inputs"
      });
    }

    if (realInput === resolvedRoot || isPathInsideRoot(resolvedRoot, realInput)) {
      throw new AgentCspError({
        code: "AGENTCSP-E2001",
        kind: "configuration",
        problem: `Trusted ${input.label} input resolves inside the scanned checkout.`,
        fix: `Move the ${input.label} to a protected path outside the checkout and pass its expected SHA-256 digest.`,
        help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#trusted-inputs"
      });
    }

    if (stats.size > input.maxBytes) {
      throw trustedInputTooLarge(input);
    }

    const content = await readBounded(handle, input.maxBytes);
    if (!content) {
      throw trustedInputTooLarge(input);
    }
    const actualSha256 = createHash("sha256").update(content).digest("hex");
    if (actualSha256 !== input.expectedSha256.toLowerCase()) {
      throw new AgentCspError({
        code: "AGENTCSP-E2002",
        kind: "integrity",
        problem: `Trusted ${input.label} digest does not match the expected SHA-256 value.`,
        fix: `Review the ${input.label} change and update the protected digest only after approval.`,
        help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#trusted-inputs"
      });
    }

    return {
      path: resolvedInput,
      real_path: realInput,
      sha256: actualSha256,
      size: content.byteLength,
      content
    };
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function readBounded(
  handle: Awaited<ReturnType<typeof fs.open>>,
  maxBytes: number
): Promise<Buffer | undefined> {
  const buffer = Buffer.alloc(maxBytes + 1);
  let total = 0;
  while (total < buffer.byteLength) {
    const { bytesRead } = await handle.read(buffer, total, buffer.byteLength - total, total);
    if (bytesRead === 0) break;
    total += bytesRead;
  }
  if (total > maxBytes) return undefined;
  return Buffer.from(buffer.subarray(0, total));
}

function trustedInputTooLarge(input: {
  label: "policy" | "baseline";
  maxBytes: number;
}): AgentCspError {
  return new AgentCspError({
    code: "AGENTCSP-E2003",
    kind: "configuration",
    problem: `Trusted ${input.label} input exceeds the ${input.maxBytes}-byte safety limit.`,
    fix: `Reduce the ${input.label} to the supported bounded format or remove the input.`,
    help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#resource-limits"
  });
}

async function realPathOrResolved(value: string): Promise<string> {
  try {
    return await fs.realpath(value);
  } catch {
    return path.resolve(value);
  }
}
