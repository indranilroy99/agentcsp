import path from "node:path";
import type { ActionType, DataClass, SurfaceObject, SurfaceType, TrustLevel } from "../schemas/index.js";
import { stableId } from "../utils/ids.js";
import { redactedEvidence } from "./read-safe.js";

const SECRET_KEY_PATTERN =
  /(api[_-]?key|token|secret|password|passwd|credential|private[_-]?key|client[_-]?secret|access[_-]?key|auth)/i;

const EXTERNAL_PATTERN = /(https?:\/\/|curl\b|wget\b|fetch\(|axios|slack|github|api\.|webhook|smtp|s3:\/\/)/i;
const EXECUTION_PATTERN = /(\bbash\b|\bsh\b|\bzsh\b|\bnode\b|\bpython\b|\bnpm\b|\bpnpm\b|\byarn\b|\bdocker\b|\bsudo\b|\brm\s+-rf\b)/i;
const IRREVERSIBLE_PATTERN = /(\brm\s+-rf\b|\bdelete\b|\bdrop\b|\btruncate\b|\bforce\b|\bpublish\b|\brelease\b|\bdeploy\b)/i;
const NETWORK_TO_SHELL_PATTERN = /\b(curl|wget)\b[\s\S]*(\|\s*(bash|sh|zsh)|bash\s+-c|sh\s+-c|zsh\s+-c)/i;
const RELEASE_OR_PUBLISH_PATTERN = /\b(gh\s+release|npm\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|docker\s+push|git\s+push)\b/i;
const DESTRUCTIVE_COMMAND_PATTERN = /\b(rm\s+-rf|delete|drop|truncate)\b/i;

export function createSurfaceObject(input: {
  type: SurfaceType;
  name: string;
  path: string;
  trust_level?: TrustLevel;
  data_classes?: DataClass[];
  actions?: ActionType[];
  side_effect?: boolean;
  reversible?: boolean;
  external_reach?: boolean;
  secret_exposure?: boolean;
  untrusted_to_privileged?: boolean;
  reason: string;
  metadata?: Record<string, unknown>;
}): SurfaceObject {
  const id = stableId(input.type, [input.path, input.name]);
  return {
    id,
    type: input.type,
    name: input.name,
    path: input.path,
    trust_level: input.trust_level ?? inferTrustLevel(input.path),
    data_classes: unique(input.data_classes ?? []),
    actions: unique(input.actions ?? []),
    side_effect: input.side_effect ?? false,
    reversible: input.reversible ?? true,
    external_reach: input.external_reach ?? false,
    secret_exposure: input.secret_exposure ?? false,
    untrusted_to_privileged: input.untrusted_to_privileged ?? false,
    evidence: [
      {
        id: stableId("evidence", [input.type, input.path, input.name, input.reason]),
        object_id: id,
        file_path: input.path,
        ...redactedEvidence(input.reason)
      }
    ],
    metadata: input.metadata ?? {}
  };
}

export function inferTrustLevel(filePath: string): TrustLevel {
  const normalized = filePath.replaceAll("\\", "/");
  if (normalized.startsWith(".github/") || normalized.startsWith(".codex/") || normalized === "AGENTS.md") {
    return "project";
  }
  if (normalized.startsWith(".cursor/") || normalized.startsWith(".agents/")) {
    return "workspace";
  }
  if (normalized.includes("node_modules/")) return "third_party";
  if (normalized.includes("rag/") || normalized.includes("logs/")) return "unknown";
  return "project";
}

export function inferDataClasses(text: string, filePath: string): DataClass[] {
  const classes: DataClass[] = [];
  if (SECRET_KEY_PATTERN.test(text) || /\.env(\.|$)?/.test(path.basename(filePath))) {
    classes.push("credential");
  }
  if (/pii|email|phone|address|ssn|passport/i.test(text)) classes.push("pii");
  if (/confidential|internal only|proprietary/i.test(text)) classes.push("confidential");
  if (classes.length === 0) classes.push("unknown");
  return unique(classes);
}

export function detectActions(text: string): ActionType[] {
  const actions: ActionType[] = [];
  if (hasAffirmedPattern(text, /\b(read|load|open|fetch|retrieve)\b/i)) actions.push("read");
  if (hasAffirmedPattern(text, /\b(write|save|update|modify|commit)\b/i)) actions.push("write");
  if (hasAffirmedPattern(text, EXECUTION_PATTERN)) actions.push("execute");
  if (hasAffirmedPattern(text, /\b(publish|release|deploy|post)\b/i)) actions.push("publish");
  if (hasAffirmedPattern(text, /\b(send|email|slack|webhook)\b/i)) actions.push("send");
  if (hasAffirmedPattern(text, /\b(delete|remove|drop|truncate)\b/i)) actions.push("delete");
  if (hasAffirmedPattern(text, /\b(remember|memory|store)\b/i)) actions.push("remember");
  if (hasAffirmedPattern(text, /\b(tool|api|mcp|function|call)\b/i)) actions.push("call");
  return unique(actions);
}

export function hasExternalReach(text: string): boolean {
  return hasAffirmedPattern(text, EXTERNAL_PATTERN);
}

export function hasExecution(text: string): boolean {
  return hasAffirmedPattern(text, EXECUTION_PATTERN);
}

export function isReversible(text: string): boolean {
  return !hasAffirmedPattern(text, IRREVERSIBLE_PATTERN);
}

export function hasSecretExposure(text: string): boolean {
  return SECRET_KEY_PATTERN.test(text);
}

export function isUntrustedToPrivileged(object: {
  trust_level: TrustLevel;
  actions: ActionType[];
  data_classes: DataClass[];
  external_reach: boolean;
  secret_exposure: boolean;
}): boolean {
  const untrusted = object.trust_level === "untrusted" || object.trust_level === "unknown" || object.trust_level === "third_party";
  const privilegedAction = object.actions.some((action) =>
    ["write", "execute", "publish", "send", "delete", "remember", "call"].includes(action)
  );
  const sensitiveData = object.secret_exposure || object.data_classes.some((value) => value === "credential" || value === "secret");
  return untrusted && (privilegedAction || sensitiveData || object.external_reach);
}

export function safeEnvKeyNames(text: string): string[] {
  const keys = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = trimmed.match(/^(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=/i);
    if (match?.[1]) keys.add(match[1]);
  }
  return [...keys].sort((a, b) => a.localeCompare(b));
}

export function redactedCommandSignals(command: string): Record<string, unknown> {
  const tokens = new Set<string>();
  for (const candidate of ["curl", "wget", "bash", "sh", "node", "python", "docker", "sudo", "rm", "scp", "ssh", "gh"]) {
    const pattern = new RegExp(`\\b${candidate}\\b`, "i");
    if (pattern.test(command)) tokens.add(candidate);
  }
  return {
    command_redacted: true,
    command_signals: [...tokens].sort((a, b) => a.localeCompare(b)),
    network_to_shell: NETWORK_TO_SHELL_PATTERN.test(command),
    release_or_publish: RELEASE_OR_PUBLISH_PATTERN.test(command),
    destructive_command: DESTRUCTIVE_COMMAND_PATTERN.test(command)
  };
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function hasAffirmedPattern(text: string, pattern: RegExp): boolean {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const matcher = new RegExp(pattern.source, flags);
  let match: RegExpExecArray | null;
  while ((match = matcher.exec(text)) !== null) {
    if (!isNegatedActionMatch(text, match.index)) return true;
    if (match[0].length === 0) matcher.lastIndex += 1;
  }
  return false;
}

function isNegatedActionMatch(text: string, index: number): boolean {
  const before = text.slice(Math.max(0, index - 120), index);
  const clauseStart = Math.max(before.lastIndexOf("."), before.lastIndexOf("\n"), before.lastIndexOf(";"));
  const clause = before.slice(clauseStart + 1);
  return /\b(do not|don't|dont|must not|should not|cannot|can't|never|not allowed to|not permitted to|forbid(?:s|den)?|prohibit(?:s|ed)?)\b/i.test(
    clause
  );
}
