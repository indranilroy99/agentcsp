import path from "node:path";
import { parse as parseToml } from "smol-toml";
import YAML from "yaml";
import {
  DEFAULT_MCP_CONFIG_NAMES,
  INSTRUCTION_FILE_NAMES,
  LOG_DIR_NAMES,
  MEMORY_DIR_NAMES,
  RAG_DIR_NAMES
} from "./defaults.js";
import type { SurfaceObject } from "../schemas/index.js";
import type { WalkedFile } from "./walk.js";
import { readTextFile } from "./read-safe.js";
import {
  createSurfaceObject,
  detectActions,
  hasExecution,
  hasExternalReach,
  hasSecretExposure,
  inferDataClasses,
  inferTrustLevel,
  isReversible,
  isUntrustedToPrivileged,
  redactedCommandSignals,
  safeEnvKeyNames
} from "./classify.js";

export interface DetectedSurfaces {
  agents: SurfaceObject[];
  instructions: SurfaceObject[];
  skills: SurfaceObject[];
  plugins: SurfaceObject[];
  mcp_servers: SurfaceObject[];
  tools: SurfaceObject[];
  prompts: SurfaceObject[];
  rag_sources: SurfaceObject[];
  memory: SurfaceObject[];
  secrets: SurfaceObject[];
  runtime_config: SurfaceObject[];
  ci_cd: SurfaceObject[];
  automations: SurfaceObject[];
}

export function emptyDetectedSurfaces(): DetectedSurfaces {
  return {
    agents: [],
    instructions: [],
    skills: [],
    plugins: [],
    mcp_servers: [],
    tools: [],
    prompts: [],
    rag_sources: [],
    memory: [],
    secrets: [],
    runtime_config: [],
    ci_cd: [],
    automations: []
  };
}

export async function detectSurfaces(files: WalkedFile[]): Promise<DetectedSurfaces> {
  const surfaces = emptyDetectedSurfaces();
  const seenDirectories = new Set<string>();

  for (const file of files) {
    const basename = path.basename(file.relativePath);
    const dirname = path.dirname(file.relativePath).replaceAll("\\", "/");
    const lowerPath = file.relativePath.toLowerCase();
    const lowerBase = basename.toLowerCase();
    const text = await readTextFile(file);

    detectDirectoryHeuristics(file, seenDirectories, surfaces);

    if (isEnvFile(basename)) {
      const keyNames = text ? safeEnvKeyNames(text) : [];
      surfaces.secrets.push(
        createSurfaceObject({
          type: "secret",
          name: basename,
          path: file.relativePath,
          trust_level: inferTrustLevel(file.relativePath),
          data_classes: ["credential"],
          actions: ["read"],
          secret_exposure: keyNames.length > 0,
          reason: "Environment file presence and key names were collected without reading or emitting values.",
          metadata: {
            env_key_names: keyNames,
            values_collected: false,
            skipped_for_size: file.skippedForSize
          }
        })
      );
      continue;
    }

    if (INSTRUCTION_FILE_NAMES.has(basename) || lowerPath.includes(".cursor/rules/")) {
      const content = text ?? "";
      const actions = detectActions(content);
      const dataClasses = inferDataClasses(content, file.relativePath);
      const externalReach = hasExternalReach(content);
      const secretExposure = hasSecretExposure(content);
      const base = {
        trust_level: inferTrustLevel(file.relativePath),
        actions,
        data_classes: dataClasses,
        external_reach: externalReach,
        secret_exposure: secretExposure
      };
      surfaces.instructions.push(
        createSurfaceObject({
          type: "instruction",
          name: basename,
          path: file.relativePath,
          trust_level: base.trust_level,
          data_classes: dataClasses,
          actions,
          side_effect: actions.some((action) => action !== "read"),
          reversible: isReversible(content),
          external_reach: externalReach,
          secret_exposure: secretExposure,
          untrusted_to_privileged: isUntrustedToPrivileged(base),
          reason: "Instruction file discovered as agent-consumable context.",
          metadata: {
            bytes: file.size,
            skipped_for_size: file.skippedForSize,
            content_redacted: true
          }
        })
      );
      continue;
    }

    if (basename === "SKILL.md") {
      const content = text ?? "";
      const actions = detectActions(content);
      const externalReach = hasExternalReach(content);
      const dataClasses = inferDataClasses(content, file.relativePath);
      surfaces.skills.push(
        createSurfaceObject({
          type: "skill",
          name: path.basename(dirname),
          path: file.relativePath,
          data_classes: dataClasses,
          actions,
          side_effect: actions.some((action) => ["write", "execute", "send", "publish", "delete", "call"].includes(action)),
          reversible: isReversible(content),
          external_reach: externalReach,
          secret_exposure: hasSecretExposure(content),
          reason: "Skill manifest discovered as agent-loadable capability context.",
          metadata: {
            skill_directory: dirname,
            content_redacted: true
          }
        })
      );
      continue;
    }

    if (lowerPath.endsWith(".codex-plugin/plugin.json") || lowerBase === "plugin.json") {
      surfaces.plugins.push(
        createSurfaceObject({
          type: "plugin",
          name: dirname === "." ? basename : path.basename(dirname),
          path: file.relativePath,
          actions: ["call"],
          side_effect: true,
          reason: "Plugin manifest discovered as agent capability metadata.",
          metadata: {
            content_redacted: true,
            skipped_for_size: file.skippedForSize
          }
        })
      );
      continue;
    }

    if (DEFAULT_MCP_CONFIG_NAMES.has(basename) || lowerPath.endsWith("/mcp.json")) {
      await detectMcpConfig(file, text, surfaces);
      continue;
    }

    if (isRuntimeConfigPath(file.relativePath, basename)) {
      detectRuntimeConfig(file, text, surfaces);
      continue;
    }

    if (basename === "package.json") {
      await detectPackageScripts(file, text, surfaces);
      continue;
    }

    if (lowerPath.startsWith(".github/workflows/") && (lowerPath.endsWith(".yml") || lowerPath.endsWith(".yaml"))) {
      detectWorkflow(file, text, surfaces);
      continue;
    }

    if (lowerBase.includes("tool") && (lowerBase.endsWith(".json") || lowerBase.endsWith(".yaml") || lowerBase.endsWith(".yml"))) {
      detectToolDefinition(file, text, surfaces);
    }
  }

  return surfaces;
}

function detectDirectoryHeuristics(file: WalkedFile, seenDirectories: Set<string>, surfaces: DetectedSurfaces): void {
  const segments = file.relativePath.split("/");
  for (let index = 0; index < segments.length - 1; index += 1) {
    const segment = segments[index]?.toLowerCase();
    if (!segment) continue;
    const dirPath = segments.slice(0, index + 1).join("/");
    if (seenDirectories.has(dirPath)) continue;
    if (RAG_DIR_NAMES.has(segment)) {
      seenDirectories.add(dirPath);
      surfaces.rag_sources.push(
        createSurfaceObject({
          type: "rag_source",
          name: segments[index] ?? dirPath,
          path: dirPath,
          trust_level: "unknown",
          data_classes: ["unknown"],
          actions: ["read"],
          reason: "Directory name suggests an agent retrieval or knowledge source.",
          metadata: { heuristic: true }
        })
      );
    }
    if (MEMORY_DIR_NAMES.has(segment)) {
      seenDirectories.add(dirPath);
      surfaces.memory.push(
        createSurfaceObject({
          type: "memory",
          name: segments[index] ?? dirPath,
          path: dirPath,
          trust_level: "unknown",
          data_classes: ["unknown"],
          actions: ["read", "remember"],
          side_effect: true,
          reason: "Directory name suggests persisted agent memory or session state.",
          metadata: { heuristic: true }
        })
      );
    }
    if (LOG_DIR_NAMES.has(segment)) {
      seenDirectories.add(dirPath);
      surfaces.memory.push(
        createSurfaceObject({
          type: "memory",
          name: segments[index] ?? dirPath,
          path: dirPath,
          trust_level: "unknown",
          data_classes: ["unknown"],
          actions: ["read"],
          reason: "Directory name suggests logs that may be consumed as future agent context.",
          metadata: { heuristic: true, logs_included: false }
        })
      );
    }
  }
}

async function detectMcpConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): Promise<void> {
  const raw = text ?? "{}";
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = {};
  }
  const servers = extractMcpServers(parsed);
  if (servers.length === 0) {
    surfaces.mcp_servers.push(
      createSurfaceObject({
        type: "mcp_server",
        name: path.basename(file.relativePath),
        path: file.relativePath,
        actions: ["call"],
        side_effect: true,
        reason: "MCP configuration discovered.",
        metadata: { content_redacted: true, server_count: 0 }
      })
    );
    return;
  }

  for (const server of servers) {
    const signalText = `${server.command ?? ""} ${(server.args ?? []).join(" ")} ${(server.envKeys ?? []).join(" ")}`;
    const actions = detectActions(signalText);
    const object = createSurfaceObject({
      type: "mcp_server",
      name: server.name,
      path: file.relativePath,
      data_classes: server.envKeys && server.envKeys.length > 0 ? ["credential"] : ["unknown"],
      actions: actions.length > 0 ? actions : ["call"],
      side_effect: true,
      external_reach: hasExternalReach(signalText),
      secret_exposure: Boolean(server.envKeys?.some((key) => /token|secret|key|password/i.test(key))),
      reversible: isReversible(signalText),
      reason: "MCP server configuration exposes agent-callable tools and authority.",
      metadata: {
        command_name: server.command ? path.basename(server.command) : undefined,
        args_count: server.args?.length ?? 0,
        env_key_names: server.envKeys ?? [],
        values_collected: false,
        content_redacted: true
      }
    });
    surfaces.mcp_servers.push({
      ...object,
      untrusted_to_privileged: isUntrustedToPrivileged(object)
    });
  }
}

async function detectPackageScripts(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): Promise<void> {
  if (!text) return;
  try {
    const parsed = JSON.parse(text) as { scripts?: Record<string, string>; name?: string };
    const scripts = parsed.scripts ?? {};
    for (const [scriptName, command] of Object.entries(scripts).sort(([a], [b]) => a.localeCompare(b))) {
      const actions = detectActions(command);
      const object = createSurfaceObject({
        type: "tool",
        name: `package-script:${scriptName}`,
        path: file.relativePath,
        data_classes: inferDataClasses(command, file.relativePath),
        actions: actions.length > 0 ? actions : ["execute"],
        side_effect: true,
        external_reach: hasExternalReach(command),
        secret_exposure: hasSecretExposure(command),
        reversible: isReversible(command),
        reason: "Package script discovered as shell-executable project authority.",
        metadata: {
          package_name: parsed.name,
          script_name: scriptName,
          ...redactedCommandSignals(command)
        }
      });
      surfaces.tools.push({
        ...object,
        untrusted_to_privileged: isUntrustedToPrivileged(object)
      });
    }
  } catch {
    return;
  }
}

function detectWorkflow(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const content = text ?? "";
  let parsed: Record<string, unknown> = {};
  try {
    parsed = (YAML.parse(content) ?? {}) as Record<string, unknown>;
  } catch {
    parsed = {};
  }
  const permissions = parsed.permissions;
  const actions = detectActions(content);
  const object = createSurfaceObject({
    type: "ci_cd",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: "project",
    data_classes: inferDataClasses(content, file.relativePath),
    actions: actions.length > 0 ? actions : ["execute"],
    side_effect: true,
    external_reach: hasExternalReach(content),
    secret_exposure: hasSecretExposure(content),
    reversible: isReversible(content),
    reason: "GitHub Actions workflow discovered as CI/CD authority.",
    metadata: {
      content_redacted: true,
      has_permissions_block: Boolean(permissions),
      trigger_names: extractWorkflowTriggers(parsed.on),
      pull_request_trigger: extractWorkflowTriggers(parsed.on).some((trigger) =>
        ["pull_request", "pull_request_target"].includes(trigger)
      ),
      write_permissions: hasWritePermissions(permissions),
      mentions_secrets_context: /secrets\./i.test(content)
    }
  });
  surfaces.ci_cd.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectToolDefinition(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const content = text ?? "";
  const toolDefinitions = extractToolDefinitions(content);
  if (toolDefinitions.length === 0) {
    const actions = detectActions(content);
    const object = createSurfaceObject({
      type: "tool",
      name: path.basename(file.relativePath),
      path: file.relativePath,
      data_classes: inferDataClasses(content, file.relativePath),
      actions: actions.length > 0 ? actions : ["call"],
      side_effect: true,
      external_reach: hasExternalReach(content),
      secret_exposure: hasSecretExposure(content),
      reversible: isReversible(content),
      reason: "Tool definition file discovered as agent-callable capability metadata.",
      metadata: { content_redacted: true, parsed_tool_schema: false }
    });
    surfaces.tools.push({
      ...object,
      untrusted_to_privileged: isUntrustedToPrivileged(object)
    });
    return;
  }

  for (const definition of toolDefinitions) {
    const authority = classifyToolAuthority(definition);
    const object = createSurfaceObject({
      type: "tool",
      name: definition.name,
      path: file.relativePath,
      data_classes: authority.secret_exposure ? ["credential"] : ["unknown"],
      actions: authority.actions,
      side_effect: authority.side_effect,
      external_reach: authority.external_reach,
      secret_exposure: authority.secret_exposure,
      reversible: !authority.destructive_action && !authority.external_write,
      reason: "Tool schema discovered as agent-callable capability metadata.",
      metadata: {
        tool_name: definition.name,
        description_redacted: true,
        parsed_tool_schema: true,
        authority_classes: authority.authority_classes,
        schema_properties: definition.schemaProperties,
        required_properties: definition.requiredProperties,
        accepts_secret_like_input: authority.accepts_secret_like_input,
        accepts_path_input: authority.accepts_path_input,
        accepts_url_input: authority.accepts_url_input,
        external_write: authority.external_write,
        destructive_action: authority.destructive_action,
        read_only_hint: definition.annotations?.readOnlyHint,
        idempotent_hint: definition.annotations?.idempotentHint,
        open_world_schema: definition.openWorldSchema
      }
    });
    surfaces.tools.push({
      ...object,
      untrusted_to_privileged: isUntrustedToPrivileged(object)
    });
  }
}

function detectRuntimeConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseRuntimeConfig(text ?? "", file.relativePath);
  if (!parsed) {
    const object = createSurfaceObject({
      type: "runtime_config",
      name: path.basename(file.relativePath),
      path: file.relativePath,
      actions: ["call"],
      reason: "Agent runtime configuration file discovered but not parsed.",
      metadata: {
        content_redacted: true,
        parsed_runtime_config: false,
        skipped_for_size: file.skippedForSize
      }
    });
    surfaces.runtime_config.push(object);
    return;
  }

  const posture = classifyRuntimeConfig(parsed);
  const actions = new Set<"read" | "write" | "execute" | "publish" | "send" | "delete" | "remember" | "call">(["call"]);
  if (posture.privileged_tool_signals.some((signal) => ["shell", "terminal", "exec"].includes(signal))) actions.add("execute");
  if (posture.network_enabled) actions.add("send");
  if (posture.sandbox_disabled || posture.workspace_write) actions.add("write");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    data_classes: posture.secret_env_exposure ? ["credential"] : ["unknown"],
    actions: [...actions].sort((a, b) => a.localeCompare(b)),
    side_effect:
      posture.sandbox_disabled ||
      posture.approval_bypass ||
      posture.network_enabled ||
      posture.privileged_tools_allowed ||
      posture.secret_env_exposure,
    external_reach: posture.network_enabled || posture.privileged_tool_signals.some((signal) => ["browser", "github", "slack", "email"].includes(signal)),
    secret_exposure: posture.secret_env_exposure,
    reason: "Agent runtime configuration discovered as policy-relevant execution posture.",
    metadata: {
      content_redacted: true,
      parsed_runtime_config: true,
      runtime_fields: posture.runtime_fields,
      sandbox_mode: posture.sandbox_mode,
      sandbox_disabled: posture.sandbox_disabled,
      workspace_write: posture.workspace_write,
      approval_policy: posture.approval_policy,
      approval_bypass: posture.approval_bypass,
      network_access: posture.network_access,
      network_enabled: posture.network_enabled,
      allowed_tools: posture.allowed_tools,
      disabled_tools: posture.disabled_tools,
      privileged_tools_allowed: posture.privileged_tools_allowed,
      privileged_tool_signals: posture.privileged_tool_signals,
      env_key_names: posture.env_key_names,
      secret_env_exposure: posture.secret_env_exposure,
      secret_values_collected: false
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function extractMcpServers(value: unknown): Array<{ name: string; command?: string; args?: string[]; envKeys?: string[] }> {
  if (!value || typeof value !== "object") return [];
  const root = value as Record<string, unknown>;
  const container = (root.mcpServers ?? root.servers) as Record<string, unknown> | undefined;
  if (!container || typeof container !== "object") return [];
  return Object.entries(container).map(([name, config]) => {
    const serverConfig = (config ?? {}) as Record<string, unknown>;
    const env = serverConfig.env && typeof serverConfig.env === "object" ? Object.keys(serverConfig.env) : [];
    const args = Array.isArray(serverConfig.args) ? serverConfig.args.filter((arg): arg is string => typeof arg === "string") : [];
    const command = typeof serverConfig.command === "string" ? serverConfig.command : undefined;
    return { name, command, args, envKeys: env.sort((a, b) => a.localeCompare(b)) };
  });
}

function isEnvFile(basename: string): boolean {
  return basename === ".env" || basename.startsWith(".env.");
}

function extractWorkflowTriggers(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string").sort((a, b) => a.localeCompare(b));
  }
  if (value && typeof value === "object") {
    return Object.keys(value as Record<string, unknown>).sort((a, b) => a.localeCompare(b));
  }
  return [];
}

function hasWritePermissions(value: unknown): boolean {
  if (typeof value === "string") return value === "write-all";
  if (!value || typeof value !== "object") return false;
  return Object.values(value as Record<string, unknown>).some((permission) => permission === "write");
}

const RUNTIME_CONFIG_BASENAMES = new Set([
  "config.json",
  "config.yaml",
  "config.yml",
  "config.toml",
  "settings.json",
  "settings.yaml",
  "settings.yml",
  "settings.toml",
  "runtime.json",
  "runtime.yaml",
  "runtime.yml",
  "runtime.toml"
]);

const TOP_LEVEL_RUNTIME_CONFIG_NAMES = new Set([
  "agent.config.json",
  "agent.config.yaml",
  "agent.config.yml",
  "agent.config.toml",
  "agents.config.json",
  "agents.config.yaml",
  "agents.config.yml",
  "agents.config.toml",
  "agent-runtime.json",
  "agent-runtime.yaml",
  "agent-runtime.yml",
  "agent-runtime.toml",
  "runtime.config.json",
  "runtime.config.yaml",
  "runtime.config.yml",
  "runtime.config.toml",
  "codex.toml",
  "codex.json",
  "codex.yaml",
  "codex.yml"
]);

interface RuntimeField {
  path: string;
  value: unknown;
}

interface RuntimePosture {
  runtime_fields: string[];
  sandbox_mode?: string;
  sandbox_disabled: boolean;
  workspace_write: boolean;
  approval_policy?: string;
  approval_bypass: boolean;
  network_access?: string;
  network_enabled: boolean;
  allowed_tools: string[];
  disabled_tools: string[];
  privileged_tools_allowed: boolean;
  privileged_tool_signals: string[];
  env_key_names: string[];
  secret_env_exposure: boolean;
}

function isRuntimeConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (TOP_LEVEL_RUNTIME_CONFIG_NAMES.has(lowerBase) && !normalized.includes("/")) return true;
  if (normalized.startsWith(".codex/") && RUNTIME_CONFIG_BASENAMES.has(lowerBase)) return true;
  if (normalized.startsWith(".agents/") && RUNTIME_CONFIG_BASENAMES.has(lowerBase)) return true;
  if (normalized.startsWith(".cursor/") && RUNTIME_CONFIG_BASENAMES.has(lowerBase)) return true;
  return false;
}

function parseRuntimeConfig(content: string, filePath: string): unknown | undefined {
  if (!content.trim()) return undefined;
  const lowerPath = filePath.toLowerCase();
  try {
    if (lowerPath.endsWith(".json")) return JSON.parse(content);
    if (lowerPath.endsWith(".toml")) return parseToml(content);
    if (lowerPath.endsWith(".yaml") || lowerPath.endsWith(".yml")) return YAML.parse(content);
  } catch {
    return undefined;
  }
  return undefined;
}

function classifyRuntimeConfig(value: unknown): RuntimePosture {
  const fields = flattenRuntimeFields(value);
  const sandboxMode = normalizeRuntimeScalar(findFirstField(fields, /(^|\.)sandbox(_mode|mode)?$|isolation|container/iu)?.value);
  const approvalPolicy = normalizeRuntimeScalar(
    findFirstField(fields, /approval|require_approval|tool_approval|human_approval|confirmation|confirm/iu)?.value
  );
  const networkAccess = normalizeRuntimeScalar(findFirstField(fields, /network|internet|web_access|allow_network|net_access/iu)?.value);
  const allowedTools = collectStringArrayFields(fields, /(^|\.)(allowed_tools|allow_tools|enabled_tools|tools_allowlist|tools)$/iu);
  const disabledTools = collectStringArrayFields(fields, /(^|\.)(disabled_tools|deny_tools|blocked_tools|tools_denylist)$/iu);
  const envKeys = collectEnvKeyNamesFromConfig(value);
  const privilegedSignals = classifyPrivilegedToolSignals(allowedTools);

  return {
    runtime_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isRuntimeSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    sandbox_mode: sandboxMode,
    sandbox_disabled: Boolean(sandboxMode && /danger|disable|none|off|false|unrestricted|full|host/iu.test(sandboxMode)),
    workspace_write: Boolean(sandboxMode && /workspace.*write|write.*workspace|project.*write/iu.test(sandboxMode)),
    approval_policy: approvalPolicy,
    approval_bypass: Boolean(
      approvalPolicy && /never|none|auto|always_allow|disabled|disable|off|false|unrestricted|no_approval|without/iu.test(approvalPolicy)
    ),
    network_access: networkAccess,
    network_enabled: Boolean(networkAccess && /true|yes|enabled|enable|on|full|unrestricted|allow/iu.test(networkAccess)),
    allowed_tools: allowedTools,
    disabled_tools: disabledTools,
    privileged_tools_allowed: privilegedSignals.length > 0,
    privileged_tool_signals: privilegedSignals,
    env_key_names: envKeys,
    secret_env_exposure: envKeys.some((key) => /token|secret|key|password|credential|auth/iu.test(key))
  };
}

function flattenRuntimeFields(value: unknown, prefix: string[] = []): RuntimeField[] {
  if (Array.isArray(value)) {
    const primitiveValues = value.filter((item) => ["string", "number", "boolean"].includes(typeof item));
    const nestedValues = value.flatMap((item, index) =>
      item && typeof item === "object" ? flattenRuntimeFields(item, [...prefix, String(index)]) : []
    );
    return primitiveValues.length > 0
      ? [{ path: prefix.join("."), value: primitiveValues.map((item) => String(item)) }, ...nestedValues]
      : nestedValues;
  }
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, item]) =>
      flattenRuntimeFields(item, [...prefix, key])
    );
  }
  if (prefix.length === 0) return [];
  return [{ path: prefix.join("."), value }];
}

function findFirstField(fields: RuntimeField[], pathPattern: RegExp): RuntimeField | undefined {
  return fields.find((field) => pathPattern.test(field.path));
}

function normalizeRuntimeScalar(value: unknown): string | undefined {
  if (typeof value === "string") return value.toLowerCase();
  if (typeof value === "boolean" || typeof value === "number") return String(value).toLowerCase();
  if (Array.isArray(value)) return value.map((item) => String(item).toLowerCase()).join(",");
  return undefined;
}

function collectStringArrayFields(fields: RuntimeField[], pathPattern: RegExp): string[] {
  const values = new Set<string>();
  for (const field of fields) {
    if (!pathPattern.test(field.path)) continue;
    if (Array.isArray(field.value)) {
      for (const value of field.value) values.add(String(value));
      continue;
    }
    if (typeof field.value === "string") values.add(field.value);
  }
  return [...values].sort((a, b) => a.localeCompare(b));
}

function collectEnvKeyNamesFromConfig(value: unknown, prefix: string[] = []): string[] {
  const keys = new Set<string>();
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const nextPrefix = [...prefix, key];
    const pathText = nextPrefix.join(".").toLowerCase();
    if (item && typeof item === "object" && !Array.isArray(item)) {
      if (/(^|\.)(env|environment|env_vars|secrets?)$/iu.test(pathText)) {
        for (const envKey of Object.keys(item as Record<string, unknown>)) keys.add(envKey);
      }
      for (const nestedKey of collectEnvKeyNamesFromConfig(item, nextPrefix)) keys.add(nestedKey);
      continue;
    }
    if (/token|secret|api[_-]?key|password|credential|auth/iu.test(key)) keys.add(key);
  }
  return [...keys].sort((a, b) => a.localeCompare(b));
}

function classifyPrivilegedToolSignals(tools: string[]): string[] {
  const signals = new Set<string>();
  const joined = tools.join(" ").toLowerCase();
  if (/(^|\s|\*)\*(\s|$)|all_tools|all-tools|all tools/iu.test(joined)) signals.add("all_tools");
  if (/shell|bash|zsh|terminal|command|exec|process/iu.test(joined)) signals.add("shell");
  if (/browser|web|playwright|puppeteer/iu.test(joined)) signals.add("browser");
  if (/filesystem|file|workspace|fs/iu.test(joined)) signals.add("filesystem");
  if (/github|gitlab|repo|pull|issue/iu.test(joined)) signals.add("github");
  if (/slack|email|smtp|webhook/iu.test(joined)) signals.add("external_messaging");
  return [...signals].sort((a, b) => a.localeCompare(b));
}

function isRuntimeSecurityField(fieldPath: string): boolean {
  return /sandbox|approval|confirm|network|internet|web_access|tool|env|environment|secret|token|credential/iu.test(fieldPath);
}

interface ExtractedToolDefinition {
  name: string;
  description: string;
  schemaProperties: string[];
  requiredProperties: string[];
  annotations?: {
    readOnlyHint?: boolean;
    idempotentHint?: boolean;
  };
  openWorldSchema: boolean;
}

function extractToolDefinitions(content: string): ExtractedToolDefinition[] {
  if (!content.trim()) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    try {
      parsed = YAML.parse(content);
    } catch {
      return [];
    }
  }
  const candidates = toolCandidates(parsed);
  return candidates
    .map((candidate) => normalizeToolDefinition(candidate))
    .filter((candidate): candidate is ExtractedToolDefinition => Boolean(candidate))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function toolCandidates(value: unknown): unknown[] {
  if (!value || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  if (Array.isArray(record.tools)) return record.tools;
  if (Array.isArray(record.functions)) return record.functions;
  if (typeof record.name === "string" && (typeof record.description === "string" || record.inputSchema)) return [record];
  return [];
}

function normalizeToolDefinition(value: unknown): ExtractedToolDefinition | undefined {
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  const name = typeof record.name === "string" ? record.name : undefined;
  if (!name) return undefined;
  const description = typeof record.description === "string" ? record.description : "";
  const schema = (record.inputSchema ?? record.parameters ?? record.schema) as Record<string, unknown> | undefined;
  const properties = schema && typeof schema.properties === "object" ? Object.keys(schema.properties as Record<string, unknown>) : [];
  const required = Array.isArray(schema?.required) ? schema.required.filter((item): item is string => typeof item === "string") : [];
  const annotations = record.annotations && typeof record.annotations === "object" ? (record.annotations as Record<string, unknown>) : undefined;
  const additionalProperties = schema?.additionalProperties;
  return {
    name,
    description,
    schemaProperties: properties.sort((a, b) => a.localeCompare(b)),
    requiredProperties: required.sort((a, b) => a.localeCompare(b)),
    annotations: annotations
      ? {
          readOnlyHint: typeof annotations.readOnlyHint === "boolean" ? annotations.readOnlyHint : undefined,
          idempotentHint: typeof annotations.idempotentHint === "boolean" ? annotations.idempotentHint : undefined
        }
      : undefined,
    openWorldSchema: additionalProperties !== false
  };
}

function classifyToolAuthority(definition: ExtractedToolDefinition): {
  authority_classes: string[];
  actions: Array<"read" | "write" | "execute" | "publish" | "send" | "delete" | "remember" | "call">;
  side_effect: boolean;
  external_reach: boolean;
  secret_exposure: boolean;
  accepts_secret_like_input: boolean;
  accepts_path_input: boolean;
  accepts_url_input: boolean;
  external_write: boolean;
  destructive_action: boolean;
} {
  const text = normalizeAuthorityText(
    `${definition.name} ${definition.description} ${definition.schemaProperties.join(" ")} ${definition.requiredProperties.join(" ")}`
  );
  const classes = new Set<string>();
  const actions = new Set<"read" | "write" | "execute" | "publish" | "send" | "delete" | "remember" | "call">(["call"]);
  const acceptsSecret = /secret|token|api[\s_-]?key|password|credential|auth/i.test(text);
  const acceptsPath = /(^|[_\W])(path|file|directory|dir|folder|repo|repository|workspace|glob)([_\W]|$)/i.test(text);
  const acceptsUrl = /\b(url|uri|webhook|endpoint|host|domain|http)\b/i.test(text);
  const destructive = /\b(delete|remove|drop|truncate|destroy|purge|wipe)\b/i.test(text);
  const externalWrite = /\b(publish|post|send|webhook|slack|email|release|deploy|comment|issue|pull\s+request|upload)\b/i.test(
    text
  );

  if (/\b(shell|command|exec|bash|process|terminal|script)\b/i.test(text)) {
    classes.add("shell_execution");
    actions.add("execute");
  }
  if (/\b(browser|navigate|click|page|dom|screenshot)\b/i.test(text)) {
    classes.add("browser_control");
    actions.add("call");
  }
  if (acceptsUrl || /\b(fetch|request|http|api|network)\b/i.test(text)) {
    classes.add("network_access");
  }
  if (acceptsPath || /\b(read\s+file|write\s+file|filesystem|fs)\b/i.test(text)) {
    classes.add("filesystem_access");
    actions.add(/\b(write|save|update|modify)\b/i.test(text) ? "write" : "read");
  }
  if (/\b(memory|remember|store|recall)\b/i.test(text)) {
    classes.add("memory_access");
    actions.add("remember");
  }
  if (acceptsSecret) {
    classes.add("credential_input");
  }
  if (externalWrite) {
    classes.add("external_write");
    actions.add("send");
    actions.add("publish");
  }
  if (destructive) {
    classes.add("destructive_action");
    actions.add("delete");
  }
  if (definition.openWorldSchema) {
    classes.add("open_world_schema");
  }

  const readOnly = definition.annotations?.readOnlyHint === true;
  const explicitSideEffectHint = definition.annotations?.readOnlyHint === false;
  const sideEffect =
    explicitSideEffectHint ||
    (!readOnly &&
      [...actions].some((action) => ["write", "execute", "publish", "send", "delete", "remember"].includes(action)));

  return {
    authority_classes: [...classes].sort((a, b) => a.localeCompare(b)),
    actions: [...actions].sort((a, b) => a.localeCompare(b)),
    side_effect: sideEffect,
    external_reach: acceptsUrl || externalWrite,
    secret_exposure: acceptsSecret,
    accepts_secret_like_input: acceptsSecret,
    accepts_path_input: acceptsPath,
    accepts_url_input: acceptsUrl,
    external_write: externalWrite,
    destructive_action: destructive
  };
}

function normalizeAuthorityText(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}
