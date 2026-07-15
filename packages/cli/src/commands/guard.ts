import { createHash } from "node:crypto";
import { execFile as execFileCallback, spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { configurationError } from "../errors.js";

const execFile = promisify(execFileCallback);
const MANAGED_MARKER = "AGENTCSP_GIT_GUARD_V1";
const EMPTY_GIT_OBJECT = /^0{40,64}$/u;
const MAX_DIFF_BYTES = 16 * 1024 * 1024;

export type GuardHook = "pre-commit" | "pre-push";

export interface GuardFinding {
  file_path: string;
  secret_type:
    | "aws_access_key"
    | "credentialed_url"
    | "environment_file"
    | "generic_secret_assignment"
    | "github_token"
    | "gitlab_token"
    | "openai_api_key"
    | "private_key"
    | "slack_token"
    | "anthropic_api_key";
  fingerprint: string;
}

interface GuardStatus {
  repository_root: string;
  hooks_path: string;
  hooks: Array<{ name: GuardHook; status: "installed" | "not_installed" | "unmanaged"; preserved_hook: boolean }>;
}

export async function runGuardInstall(targetPath: string, options: { json?: boolean } = {}): Promise<void> {
  const context = await resolveGitContext(targetPath);
  const scriptPath = currentCliEntrypoint();
  await fs.mkdir(context.hooksPath, { recursive: true, mode: 0o700 });

  for (const hook of guardHooks()) {
    await installHook(context.hooksPath, hook, scriptPath);
  }

  const status = await readGuardStatus(context);
  emit(options.json, { type: "agentcsp_guard", action: "install", status: "installed", ...status }, () => {
    console.log(`AgentCSP guard installed in ${status.hooks.length} Git hooks.`);
    console.log("It will block detected secrets before commit and push; secret values are never displayed.");
  });
}

export async function runGuardStatus(targetPath: string, options: { json?: boolean } = {}): Promise<void> {
  const status = await readGuardStatus(await resolveGitContext(targetPath));
  emit(options.json, { type: "agentcsp_guard", action: "status", ...status }, () => {
    console.log(`AgentCSP guard: ${status.hooks.every((hook) => hook.status === "installed") ? "installed" : "incomplete"}`);
    for (const hook of status.hooks) {
      console.log(`  ${hook.name}: ${hook.status}${hook.preserved_hook ? " (preserved hook chained)" : ""}`);
    }
  });
}

export async function runGuardUninstall(targetPath: string, options: { json?: boolean } = {}): Promise<void> {
  const context = await resolveGitContext(targetPath);
  const removed: GuardHook[] = [];
  for (const hook of guardHooks()) {
    const hookPath = path.join(context.hooksPath, hook);
    if (!(await isManagedHook(hookPath))) continue;
    await fs.unlink(hookPath);
    const preservedPath = preservedHookPath(hookPath);
    if (await isRegularFile(preservedPath)) await fs.rename(preservedPath, hookPath);
    removed.push(hook);
  }

  emit(options.json, { type: "agentcsp_guard", action: "uninstall", status: "removed", hooks: removed }, () => {
    console.log(`AgentCSP guard removed from ${removed.length} Git hook${removed.length === 1 ? "" : "s"}.`);
  });
}

export async function runGuardCheck(
  targetPath: string,
  options: { hook?: GuardHook; json?: boolean } = {}
): Promise<void> {
  const hook = options.hook ?? "pre-commit";
  const context = await resolveGitContext(targetPath);
  const diff = hook === "pre-commit" ? await stagedDiff(context.repositoryRoot) : await outgoingDiff(context.repositoryRoot, await readStandardInput());
  const findings = findSecretExposures(diff);
  const result = {
    type: "agentcsp_guard_check",
    hook,
    status: findings.length === 0 ? "pass" : "blocked",
    findings
  };

  if (options.json) {
    console.log(JSON.stringify(result));
  } else if (findings.length === 0) {
    console.log(`AgentCSP guard: pass (${hook}).`);
  } else {
    console.error(`AgentCSP guard blocked ${findings.length} possible secret exposure${findings.length === 1 ? "" : "s"} (${hook}).`);
    for (const finding of findings) {
      console.error(`  ${finding.file_path}: ${finding.secret_type} [${finding.fingerprint}]`);
    }
    console.error("Remove the secret from the Git diff and rotate it if it is real. AgentCSP never prints the matched value.");
  }

  if (findings.length > 0) process.exitCode = 1;
}

export function findSecretExposures(diff: string): GuardFinding[] {
  const findings = new Map<string, GuardFinding>();
  let filePath = "unknown";
  let environmentFileReported = false;

  for (const line of diff.split(/\r?\n/u)) {
    if (line.startsWith("+++ b/")) {
      filePath = sanitizePath(line.slice(6));
      environmentFileReported = false;
      continue;
    }
    if (!line.startsWith("+") || line.startsWith("+++")) continue;
    if (isLikelyEnvironmentFile(filePath) && !environmentFileReported) {
      addFinding(findings, filePath, "environment_file", filePath);
      environmentFileReported = true;
    }
    const addedLine = line.slice(1);
    for (const pattern of secretPatterns) {
      for (const match of addedLine.matchAll(pattern.expression)) {
        const candidate = match[0];
        addFinding(findings, filePath, pattern.type, candidate);
      }
    }
    if (/-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----/u.test(addedLine)) {
      addFinding(findings, filePath, "private_key", "private-key-header");
    }
    for (const candidate of genericSecretAssignments(addedLine)) {
      if (!looksLikePlaceholder(candidate)) addFinding(findings, filePath, "generic_secret_assignment", candidate);
    }
    for (const candidate of credentialedUrls(addedLine)) {
      addFinding(findings, filePath, "credentialed_url", candidate);
    }
  }

  return [...findings.values()].sort((left, right) =>
    left.file_path.localeCompare(right.file_path) || left.secret_type.localeCompare(right.secret_type) || left.fingerprint.localeCompare(right.fingerprint)
  );
}

function addFinding(
  findings: Map<string, GuardFinding>,
  filePath: string,
  secretType: GuardFinding["secret_type"],
  secretMaterial: string
): void {
  const fingerprint = `sha256:${createHash("sha256").update(secretMaterial).digest("hex").slice(0, 12)}`;
  const finding: GuardFinding = { file_path: sanitizePath(filePath), secret_type: secretType, fingerprint };
  findings.set(`${finding.file_path}:${finding.secret_type}:${finding.fingerprint}`, finding);
}

const secretPatterns: Array<{ type: Exclude<GuardFinding["secret_type"], "environment_file" | "generic_secret_assignment" | "credentialed_url" | "private_key">; expression: RegExp }> = [
  { type: "github_token", expression: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/gu },
  { type: "gitlab_token", expression: /\bglpat-[A-Za-z0-9_-]{20,}\b/gu },
  { type: "openai_api_key", expression: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/gu },
  { type: "anthropic_api_key", expression: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/gu },
  { type: "slack_token", expression: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/gu },
  { type: "aws_access_key", expression: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu }
];

function genericSecretAssignments(line: string): string[] {
  const values: string[] = [];
  const expression = /(?:^|[\s,{])(?:["']?)(?:[A-Za-z][A-Za-z0-9_.-]*?(?:api[_-]?key|token|secret|password|passwd|credential|private[_-]?key|client[_-]?secret|access[_-]?key|authorization?))[A-Za-z0-9_.-]*(?:["']?)\s*[:=]\s*["']?([^\s"',}]{16,})/giu;
  for (const match of line.matchAll(expression)) values.push(match[1] ?? "");
  return values;
}

function credentialedUrls(line: string): string[] {
  return [...line.matchAll(/https?:\/\/[^\s/:@]+:[^\s@]+@[^\s/]+/gu)].map((match) => match[0]);
}

function looksLikePlaceholder(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    normalized.startsWith("$") ||
    normalized.startsWith("{{") ||
    /(?:example|sample|dummy|fake|placeholder|replace|changeme|your[_-]?|test[_-]?only|not[-_]?a[-_]?secret|invalid)/u.test(normalized)
  );
}

function isLikelyEnvironmentFile(filePath: string): boolean {
  const basename = path.posix.basename(filePath).toLowerCase();
  return /^\.env(?:\.|$)/u.test(basename) && !/^\.env\.(?:example|sample|template|defaults?)$/u.test(basename);
}

function sanitizePath(filePath: string): string {
  return filePath.replace(/[\u0000-\u001f\u007f]/gu, "?").replaceAll("\\", "/").slice(0, 512) || "unknown";
}

async function installHook(hooksPath: string, hook: GuardHook, scriptPath: string): Promise<void> {
  const hookPath = path.join(hooksPath, hook);
  const preservedPath = preservedHookPath(hookPath);
  if (await isManagedHook(hookPath)) {
    await writeManagedHook(hookPath, hook, scriptPath);
    return;
  }
  if (await pathExists(hookPath)) {
    if (!(await isRegularFile(hookPath))) {
      throw configurationError(`Refusing to replace non-regular Git hook ${hook}.`, "Replace the hook with a regular file, then rerun guard install.");
    }
    if (await pathExists(preservedPath)) {
      throw configurationError(
        `A preserved hook already exists for ${hook}.`,
        "Review the existing preserved hook, then remove or merge it before rerunning guard install."
      );
    }
    await fs.rename(hookPath, preservedPath);
  }
  await writeManagedHook(hookPath, hook, scriptPath);
}

async function writeManagedHook(hookPath: string, hook: GuardHook, scriptPath: string): Promise<void> {
  await fs.writeFile(hookPath, managedHookScript(hook, scriptPath), { encoding: "utf8", mode: 0o755 });
  await fs.chmod(hookPath, 0o755);
}

function managedHookScript(hook: GuardHook, scriptPath: string): string {
  const command = `node ${shellQuote(scriptPath)} guard check --hook ${hook}`;
  const preserved = '"$0.agentcsp-user"';
  if (hook === "pre-push") {
    return [
      "#!/bin/sh",
      `# ${MANAGED_MARKER}`,
      "set -u",
      'input="$(mktemp "${TMPDIR:-/tmp}/agentcsp-pre-push.XXXXXX")" || exit 1',
      'trap \'rm -f "$input"\' 0 HUP INT TERM',
      'cat > "$input"',
      `if [ -x ${preserved} ]; then`,
      `  ${preserved} "$@" < "$input" || exit $?`,
      "fi",
      `${command} < "$input"`
    ].join("\n") + "\n";
  }
  return [
    "#!/bin/sh",
    `# ${MANAGED_MARKER}`,
    "set -u",
    `if [ -x ${preserved} ]; then`,
    `  ${preserved} "$@" || exit $?`,
    "fi",
    `exec ${command}`
  ].join("\n") + "\n";
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
}

function currentCliEntrypoint(): string {
  const entrypoint = process.argv[1];
  if (!entrypoint) {
    throw configurationError("AgentCSP could not determine its CLI entrypoint for the Git hook.", "Run agentcsp from an installed package or built source tree.");
  }
  return path.resolve(entrypoint);
}

async function readGuardStatus(context: GitContext): Promise<GuardStatus> {
  return {
    repository_root: context.repositoryRoot,
    hooks_path: context.hooksPath,
    hooks: await Promise.all(
      guardHooks().map(async (name) => {
        const hookPath = path.join(context.hooksPath, name);
        const exists = await pathExists(hookPath);
        return {
          name,
          status: !exists ? "not_installed" : (await isManagedHook(hookPath)) ? "installed" : "unmanaged",
          preserved_hook: await isRegularFile(preservedHookPath(hookPath))
        };
      })
    )
  };
}

interface GitContext {
  repositoryRoot: string;
  hooksPath: string;
}

async function resolveGitContext(targetPath: string): Promise<GitContext> {
  const cwd = path.resolve(targetPath);
  const repositoryRoot = await gitOutput(cwd, ["rev-parse", "--show-toplevel"], "AgentCSP guard must run inside a Git working tree.");
  const localHooksPath = await gitOutputOptional(repositoryRoot, ["config", "--local", "--get", "core.hooksPath"]);
  const effectiveHooksPath = await gitOutputOptional(repositoryRoot, ["config", "--get", "core.hooksPath"]);
  if (effectiveHooksPath && !localHooksPath) {
    throw configurationError(
      "This repository inherits a shared Git hooks path, so AgentCSP will not modify it.",
      "Configure a repository-local core.hooksPath or install the guard in the shared hooks management system."
    );
  }
  const hooksPathValue = localHooksPath ?? await gitOutput(
    repositoryRoot,
    ["rev-parse", "--git-path", "hooks"],
    "Git hooks could not be resolved for this repository."
  );
  const hooksPath = path.resolve(repositoryRoot, hooksPathValue);
  return { repositoryRoot, hooksPath };
}

async function stagedDiff(repositoryRoot: string): Promise<string> {
  return gitOutput(repositoryRoot, ["diff", "--cached", "--no-ext-diff", "--unified=0", "--diff-filter=ACMR"], "Staged changes could not be read for guard inspection.");
}

async function outgoingDiff(repositoryRoot: string, input: string): Promise<string> {
  const ranges = input
    .split(/\r?\n/u)
    .map((line) => line.trim().split(/\s+/u))
    .filter((fields) => fields.length >= 4 && fields[1] && fields[3] && !EMPTY_GIT_OBJECT.test(fields[1] ?? ""))
    .map((fields) => ({ local: fields[1] as string, remote: fields[3] as string }));
  if (ranges.length === 0) return "";

  const emptyTree = await gitOutput(repositoryRoot, ["hash-object", "-t", "tree", "--stdin"], "Git empty tree could not be resolved for guard inspection.", "");
  const diffs = await Promise.all(
    ranges.map(({ local, remote }) =>
      gitOutput(
        repositoryRoot,
        ["diff", "--no-ext-diff", "--unified=0", "--diff-filter=ACMR", EMPTY_GIT_OBJECT.test(remote) ? emptyTree : remote, local],
        "Outgoing changes could not be read for guard inspection."
      )
    )
  );
  return diffs.join("\n");
}

async function readStandardInput(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

async function gitOutput(cwd: string, args: string[], problem: string, input?: string): Promise<string> {
  try {
    if (input !== undefined) return (await commandOutputWithInput("git", args, cwd, input)).trimEnd();
    const result = await execFile("git", args, { cwd, encoding: "utf8", maxBuffer: MAX_DIFF_BYTES });
    return result.stdout.trimEnd();
  } catch {
    throw configurationError(problem, "Resolve the Git repository state and rerun the AgentCSP guard.");
  }
}

async function commandOutputWithInput(command: string, args: string[], cwd: string, input: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(error);
    };
    child.on("error", fail);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      if (Buffer.byteLength(stdout) > MAX_DIFF_BYTES) fail(new Error("Git output exceeded guard limit."));
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      if (code === 0) resolve(stdout);
      else reject(new Error("Git command failed."));
    });
    child.stdin.end(input);
  });
}

async function gitOutputOptional(cwd: string, args: string[]): Promise<string | undefined> {
  try {
    const result = await execFile("git", args, { cwd, encoding: "utf8", maxBuffer: 64 * 1024 });
    const value = result.stdout.trim();
    return value || undefined;
  } catch {
    return undefined;
  }
}

function guardHooks(): GuardHook[] {
  return ["pre-commit", "pre-push"];
}

function preservedHookPath(hookPath: string): string {
  return `${hookPath}.agentcsp-user`;
}

async function isManagedHook(filePath: string): Promise<boolean> {
  if (!(await isRegularFile(filePath))) return false;
  const content = await fs.readFile(filePath, "utf8");
  return content.includes(MANAGED_MARKER);
}

async function isRegularFile(filePath: string): Promise<boolean> {
  try {
    return (await fs.lstat(filePath)).isFile();
  } catch {
    return false;
  }
}

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await fs.lstat(filePath);
    return true;
  } catch {
    return false;
  }
}

function emit(json: boolean | undefined, value: Record<string, unknown>, text: () => void): void {
  if (json) console.log(JSON.stringify(value));
  else text();
}
