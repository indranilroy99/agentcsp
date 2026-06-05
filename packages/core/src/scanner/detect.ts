import path from "node:path";
import { parse as parseToml } from "smol-toml";
import YAML from "yaml";
import {
  DEFAULT_MCP_CONFIG_NAMES,
  GENERATED_STATE_DIR_NAMES,
  INSTRUCTION_FILE_NAMES,
  LOG_DIR_NAMES,
  MEMORY_DIR_NAMES,
  RAG_DIR_NAMES
} from "./defaults.js";
import type { ActionType, ScanDiagnostic, SurfaceObject } from "../schemas/index.js";
import type { WalkedFile } from "./walk.js";
import { stableId } from "../utils/ids.js";
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
  diagnostics: ScanDiagnostic[];
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
    automations: [],
    diagnostics: []
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

    const contextSurface = contextSurfaceType(file.relativePath);
    if (contextSurface === "rag_source") {
      detectRagContentFile(file, text, surfaces);
      continue;
    }
    if (contextSurface === "memory") {
      detectMemoryContentFile(file, text, surfaces);
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

function detectRagContentFile(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const content = text ?? "";
  const signals = classifyContextContent(content);
  const generatedState = classifyGeneratedState(file.relativePath, content);
  const actions = contextActions(signals, "rag_source");
  const object = createSurfaceObject({
    type: "rag_source",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: "unknown",
    data_classes: inferDataClasses(content, file.relativePath),
    actions,
    side_effect: false,
    external_reach: signals.external_directive,
    secret_exposure: signals.secret_reference,
    reason: "RAG source file discovered as retrievable agent context.",
    metadata: {
      content_redacted: true,
      content_analyzed: text !== undefined,
      skipped_for_size: file.skippedForSize,
      bytes: file.size,
      ...generatedState,
      ...signals
    }
  });
  surfaces.rag_sources.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectMemoryContentFile(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const content = text ?? "";
  const signals = classifyContextContent(content);
  const generatedState = classifyGeneratedState(file.relativePath, content);
  const actions = contextActions(signals, "memory");
  const object = createSurfaceObject({
    type: "memory",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: "unknown",
    data_classes: inferDataClasses(content, file.relativePath),
    actions,
    side_effect: actions.some((action) => action !== "read"),
    external_reach: signals.external_directive,
    secret_exposure: signals.secret_reference,
    reason: "Memory file discovered as persisted agent context.",
    metadata: {
      content_redacted: true,
      content_analyzed: text !== undefined,
      skipped_for_size: file.skippedForSize,
      bytes: file.size,
      ...generatedState,
      ...signals
    }
  });
  surfaces.memory.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
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

function contextSurfaceType(relativePath: string): "rag_source" | "memory" | undefined {
  const segments = relativePath.split("/").slice(0, -1).map((segment) => segment.toLowerCase());
  if (segments.some((segment) => RAG_DIR_NAMES.has(segment))) return "rag_source";
  if (segments.some((segment) => MEMORY_DIR_NAMES.has(segment) || LOG_DIR_NAMES.has(segment))) return "memory";
  return undefined;
}

interface ContextContentSignals {
  instruction_like_content: boolean;
  instruction_override: boolean;
  tool_directive: boolean;
  memory_write_directive: boolean;
  external_directive: boolean;
  secret_reference: boolean;
  content_signal_count: number;
}

interface GeneratedStateSignals {
  generated_state: boolean;
  generated_state_kinds: string[];
  transcript_like: boolean;
  tool_output_like: boolean;
  cached_output_like: boolean;
}

function classifyContextContent(content: string): ContextContentSignals {
  const instructionOverride = /\b(ignore|override|bypass|forget|disregard)\b[\s\S]{0,80}\b(instruction|policy|approval|guard|previous|system|developer)\b/i.test(
    content
  );
  const instructionLike =
    instructionOverride ||
    /\b(system prompt|developer instruction|highest priority|follow these instructions|do not obey|new instruction)\b/i.test(content);
  const toolDirective = /\b(call|invoke|use|run|execute|trigger)\b[\s\S]{0,80}\b(tool|mcp|shell|browser|github|slack|webhook|function|api)\b/i.test(content);
  const memoryWriteDirective = /\b(remember|store|persist|save)\b[\s\S]{0,80}\b(memory|future|session|run|instruction|shortcut)\b/i.test(content);
  const externalDirective =
    hasExternalReach(content) || /\b(webhook|slack|email|external|publish|send|post|upload)\b/i.test(content);
  const secretReference = hasSecretExposure(content);
  const signals = [instructionLike, instructionOverride, toolDirective, memoryWriteDirective, externalDirective, secretReference].filter(Boolean).length;
  return {
    instruction_like_content: instructionLike,
    instruction_override: instructionOverride,
    tool_directive: toolDirective,
    memory_write_directive: memoryWriteDirective,
    external_directive: externalDirective,
    secret_reference: secretReference,
    content_signal_count: signals
  };
}

function classifyGeneratedState(relativePath: string, content: string): GeneratedStateSignals {
  const lowerPath = relativePath.replaceAll("\\", "/").toLowerCase();
  const segments = lowerPath.split("/");
  const kinds = new Set<string>();

  for (const segment of segments.slice(0, -1)) {
    if (GENERATED_STATE_DIR_NAMES.has(segment)) kinds.add(segment.replaceAll("-", "_"));
  }
  if (/transcript|conversation|session|run[-_]?log|tool[-_]?output|cached[-_]?output|summary/i.test(lowerPath)) {
    kinds.add("filename_signal");
  }

  const transcriptLike = /\b(assistant|user|system|developer|tool|function)\s*:/i.test(content);
  const toolOutputLike = /\b(tool|function|mcp|browser|shell|command)\s+(result|output|response|call)\b/i.test(content);
  const cachedOutputLike = /\b(cache|cached|artifact|tool output|run summary|session transcript)\b/i.test(content);

  if (transcriptLike) kinds.add("transcript");
  if (toolOutputLike) kinds.add("tool_output");
  if (cachedOutputLike) kinds.add("cached_output");

  return {
    generated_state: kinds.size > 0,
    generated_state_kinds: [...kinds].sort((a, b) => a.localeCompare(b)),
    transcript_like: transcriptLike,
    tool_output_like: toolOutputLike,
    cached_output_like: cachedOutputLike
  };
}

function contextActions(signals: ContextContentSignals, type: "rag_source" | "memory"): ActionType[] {
  const actions = new Set<ActionType>(["read"]);
  if (type === "memory" || signals.memory_write_directive) actions.add("remember");
  if (signals.tool_directive) actions.add("call");
  if (signals.external_directive) actions.add("send");
  return [...actions].sort((a, b) => a.localeCompare(b));
}

function addDiagnostic(
  surfaces: DetectedSurfaces,
  file: WalkedFile,
  diagnostic: Omit<ScanDiagnostic, "id" | "file_path" | "severity" | "content_redacted"> & {
    severity?: ScanDiagnostic["severity"];
  }
): void {
  surfaces.diagnostics.push({
    id: stableId("diagnostic", [diagnostic.code, file.relativePath]),
    severity: diagnostic.severity ?? "warning",
    code: diagnostic.code,
    file_path: file.relativePath,
    parser: diagnostic.parser,
    reason: diagnostic.reason,
    content_redacted: true
  });
}

async function detectMcpConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): Promise<void> {
  const raw = text ?? "{}";
  let parsed: unknown;
  let parseFailed = false;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parseFailed = raw.trim().length > 0;
    parsed = {};
  }
  if (parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: "json",
      code: "MCP_CONFIG_PARSE_FAILED",
      reason: "MCP configuration could not be parsed as JSON. Raw content was redacted."
    });
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
        metadata: { content_redacted: true, server_count: 0, parse_error: parseFailed }
      })
    );
    return;
  }

  for (const server of servers) {
    const signalText = `${server.command ?? ""} ${(server.args ?? []).join(" ")} ${server.transport ?? ""} ${server.remoteHost ?? ""} ${(server.envKeys ?? []).join(" ")} ${(server.headerNames ?? []).join(" ")} ${(server.secretRefKeys ?? []).join(" ")}`;
    const actions = detectActions(signalText);
    const externalRemote = Boolean(server.remote && server.remoteHost && !isLocalHost(server.remoteHost));
    const secretKeys = [...(server.envKeys ?? []), ...(server.secretRefKeys ?? []), ...(server.authHeaderNames ?? [])];
    const baseActions: ActionType[] = actions.length > 0 ? actions : ["call"];
    const packageRunner = server.packageRunner;
    const mcpActions: ActionType[] = [
      ...baseActions,
      ...(externalRemote ? (["send"] as ActionType[]) : []),
      ...(packageRunner ? (["execute"] as ActionType[]) : [])
    ];
    const object = createSurfaceObject({
      type: "mcp_server",
      name: server.name,
      path: file.relativePath,
      trust_level: externalRemote || packageRunner ? "third_party" : inferTrustLevel(file.relativePath),
      data_classes: secretKeys.length > 0 ? ["credential"] : ["unknown"],
      actions: uniqueActions(mcpActions),
      side_effect: true,
      external_reach: externalRemote || Boolean(packageRunner) || hasExternalReach(signalText),
      secret_exposure: secretKeys.some((key) => /authorization|token|secret|key|password|credential|auth/i.test(key)),
      reversible: isReversible(signalText),
      reason: "MCP server configuration exposes agent-callable tools and authority.",
      metadata: {
        command_name: server.command ? path.basename(server.command) : undefined,
        args_count: server.args?.length ?? 0,
        transport: server.transport,
        remote: server.remote,
        remote_host: server.remoteHost,
        remote_scheme: server.remoteScheme,
        url_redacted: Boolean(server.remote),
        header_names: server.headerNames ?? [],
        auth_header_names: server.authHeaderNames ?? [],
        env_key_names: server.envKeys ?? [],
        secret_ref_key_names: server.secretRefKeys ?? [],
        package_runner: Boolean(packageRunner),
        package_runner_name: packageRunner?.runner,
        package_name: packageRunner?.packageName,
        package_version_pinned: packageRunner?.versionPinned,
        package_reference_redacted: packageRunner?.packageReferenceRedacted ?? false,
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
    addDiagnostic(surfaces, file, {
      parser: "json",
      code: "PACKAGE_JSON_PARSE_FAILED",
      reason: "package.json could not be parsed as JSON, so package script authority may be incomplete. Raw content was redacted."
    });
    return;
  }
}

function detectWorkflow(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const content = text ?? "";
  let parsed: Record<string, unknown> = {};
  let parseFailed = false;
  try {
    parsed = (YAML.parse(content) ?? {}) as Record<string, unknown>;
  } catch {
    parseFailed = content.trim().length > 0;
    parsed = {};
  }
  if (parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: "yaml",
      code: "WORKFLOW_PARSE_FAILED",
      reason: "GitHub Actions workflow could not be parsed as YAML. Text heuristics still ran with raw content redacted."
    });
  }
  const permissions = parsed.permissions;
  const actions = detectActions(content);
  const triggerNames = extractWorkflowTriggers(parsed.on);
  const writePermissions = hasWritePermissions(permissions);
  const mentionsSecretsContext = /secrets\./i.test(content);
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
      trigger_names: triggerNames,
      parse_error: parseFailed,
      pull_request_trigger: triggerNames.some((trigger) => ["pull_request", "pull_request_target"].includes(trigger)),
      write_permissions: writePermissions,
      mentions_secrets_context: mentionsSecretsContext
    }
  });
  surfaces.ci_cd.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
  detectWorkflowAutomation(file, content, triggerNames, {
    actions,
    writePermissions,
    mentionsSecretsContext,
    permissions
  }, surfaces);
}

function detectWorkflowAutomation(
  file: WalkedFile,
  content: string,
  triggerNames: string[],
  workflow: {
    actions: ActionType[];
    writePermissions: boolean;
    mentionsSecretsContext: boolean;
    permissions: unknown;
  },
  surfaces: DetectedSurfaces
): void {
  const automationTriggers = triggerNames.filter((trigger) =>
    ["schedule", "workflow_dispatch", "repository_dispatch", "workflow_run", "workflow_call"].includes(trigger)
  );
  if (automationTriggers.length === 0) return;

  const actions = uniqueActions([
    ...(workflow.actions.length > 0 ? workflow.actions : (["execute"] as ActionType[])),
    ...(workflow.writePermissions ? (["write"] as ActionType[]) : []),
    ...(workflow.mentionsSecretsContext ? (["call"] as ActionType[]) : [])
  ]);
  const object = createSurfaceObject({
    type: "automation",
    name: `workflow:${path.basename(file.relativePath)}`,
    path: file.relativePath,
    trust_level: "project",
    data_classes: workflow.mentionsSecretsContext ? ["credential"] : inferDataClasses(content, file.relativePath),
    actions,
    side_effect: true,
    external_reach: hasExternalReach(content) || automationTriggers.includes("repository_dispatch"),
    secret_exposure: workflow.mentionsSecretsContext,
    reversible: isReversible(content),
    reason: "GitHub Actions workflow trigger discovered as agent-relevant automation.",
    metadata: {
      content_redacted: true,
      trigger_names: triggerNames,
      automation_triggers: automationTriggers,
      scheduled: automationTriggers.includes("schedule"),
      manual_dispatch: automationTriggers.includes("workflow_dispatch"),
      external_dispatch: automationTriggers.includes("repository_dispatch"),
      workflow_run_trigger: automationTriggers.includes("workflow_run"),
      write_permissions: workflow.writePermissions,
      mentions_secrets_context: workflow.mentionsSecretsContext,
      has_permissions_block: Boolean(workflow.permissions)
    }
  });
  surfaces.automations.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectToolDefinition(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const content = text ?? "";
  const extraction = extractToolDefinitions(content);
  const toolDefinitions = extraction.definitions;
  if (extraction.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: "json_or_yaml",
      code: "TOOL_DEFINITION_PARSE_FAILED",
      reason: "Tool definition file could not be parsed as JSON or YAML. Text heuristics still ran with raw content redacted."
    });
  }
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
      metadata: { content_redacted: true, parsed_tool_schema: false, parse_error: extraction.parseFailed }
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
        read_only_hint_conflict: authority.read_only_hint_conflict,
        open_world_authority: authority.open_world_authority,
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
  const parseResult = parseRuntimeConfig(text ?? "", file.relativePath);
  if (parseResult.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parseResult.parser ?? "runtime_config",
      code: "RUNTIME_CONFIG_PARSE_FAILED",
      reason: "Agent runtime configuration could not be parsed. Raw content was redacted."
    });
  }
  if (!parseResult.value) {
    const object = createSurfaceObject({
      type: "runtime_config",
      name: path.basename(file.relativePath),
      path: file.relativePath,
      actions: ["call"],
      reason: "Agent runtime configuration file discovered but not parsed.",
      metadata: {
        content_redacted: true,
        parsed_runtime_config: false,
        parse_error: parseResult.parseFailed,
        skipped_for_size: file.skippedForSize
      }
    });
    surfaces.runtime_config.push(object);
    return;
  }

  const posture = classifyRuntimeConfig(parseResult.value);
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

function extractMcpServers(value: unknown): Array<{
  name: string;
  command?: string;
  args?: string[];
  envKeys?: string[];
  transport?: string;
  remote: boolean;
  remoteHost?: string;
  remoteScheme?: string;
  headerNames?: string[];
  authHeaderNames?: string[];
  secretRefKeys?: string[];
  packageRunner?: McpPackageRunnerSignal;
}> {
  if (!value || typeof value !== "object") return [];
  const root = value as Record<string, unknown>;
  const container = (root.mcpServers ?? root.servers) as Record<string, unknown> | undefined;
  if (!container || typeof container !== "object") return [];
  return Object.entries(container).map(([name, config]) => {
    const serverConfig = (config ?? {}) as Record<string, unknown>;
    const env = serverConfig.env && typeof serverConfig.env === "object" ? Object.keys(serverConfig.env) : [];
    const args = Array.isArray(serverConfig.args) ? serverConfig.args.filter((arg): arg is string => typeof arg === "string") : [];
    const command = typeof serverConfig.command === "string" ? serverConfig.command : undefined;
    const url = typeof serverConfig.url === "string" ? serverConfig.url : typeof serverConfig.endpoint === "string" ? serverConfig.endpoint : undefined;
    const remoteUrl = parseMcpRemoteUrl(url);
    const transport = typeof serverConfig.transport === "string" ? serverConfig.transport : remoteUrl ? "http" : undefined;
    const headers = serverConfig.headers && typeof serverConfig.headers === "object" ? (serverConfig.headers as Record<string, unknown>) : {};
    const headerNames = Object.keys(headers).sort((a, b) => a.localeCompare(b));
    const authHeaderNames = headerNames.filter((header) => /authorization|api[-_]?key|token|secret|credential|cookie/i.test(header));
    const packageRunner = classifyMcpPackageRunner(command, args);
    const secretRefKeys = [
      ...extractSecretReferenceKeys(Object.values(headers)),
      ...extractSecretReferenceKeys([url, ...args])
    ].sort((a, b) => a.localeCompare(b));
    return {
      name,
      command,
      args,
      envKeys: env.sort((a, b) => a.localeCompare(b)),
      transport,
      remote: Boolean(remoteUrl),
      remoteHost: remoteUrl?.host,
      remoteScheme: remoteUrl?.scheme,
      headerNames,
      authHeaderNames,
      secretRefKeys,
      packageRunner
    };
  });
}

interface McpPackageRunnerSignal {
  runner: string;
  packageName?: string;
  versionPinned: boolean;
  packageReferenceRedacted: boolean;
}

function classifyMcpPackageRunner(command: string | undefined, args: string[]): McpPackageRunnerSignal | undefined {
  if (!command) return undefined;
  const runner = path.basename(command).toLowerCase();
  let packageSpec: string | undefined;

  if (["npx", "bunx", "uvx"].includes(runner)) {
    packageSpec = firstPackageLikeArg(args);
  }
  if (runner === "pnpm" && args[0] === "dlx") {
    packageSpec = firstPackageLikeArg(args.slice(1));
  }
  if (runner === "yarn" && args[0] === "dlx") {
    packageSpec = firstPackageLikeArg(args.slice(1));
  }
  if (runner === "npm" && ["exec", "x"].includes(args[0] ?? "")) {
    packageSpec = firstPackageLikeArg(args.slice(1));
  }
  if (runner === "pipx" && args[0] === "run") {
    packageSpec = firstPackageLikeArg(args.slice(1));
  }

  if (!packageSpec) return undefined;
  const normalized = normalizePackageReference(packageSpec);
  return {
    runner,
    packageName: normalized.name,
    versionPinned: normalized.versionPinned,
    packageReferenceRedacted: true
  };
}

function firstPackageLikeArg(args: string[]): string | undefined {
  const skipNextValueFor = new Set(["--package", "--from", "-p"]);
  let skipNext = false;
  for (const arg of args) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (arg === "--") continue;
    if (skipNextValueFor.has(arg)) {
      skipNext = true;
      continue;
    }
    if (arg.startsWith("-")) continue;
    return arg;
  }
  return undefined;
}

function normalizePackageReference(spec: string): { name?: string; versionPinned: boolean } {
  const trimmed = spec.trim();
  if (!trimmed) return { versionPinned: false };

  const pythonExactVersionIndex = trimmed.indexOf("==");
  if (pythonExactVersionIndex > 0) {
    const version = trimmed.slice(pythonExactVersionIndex + 2);
    return {
      name: trimmed.slice(0, pythonExactVersionIndex),
      versionPinned: Boolean(version && !/^latest$/iu.test(version))
    };
  }

  const versionMarker = npmVersionMarkerIndex(trimmed);
  if (versionMarker > 0) {
    const version = trimmed.slice(versionMarker + 1);
    return {
      name: trimmed.slice(0, versionMarker),
      versionPinned: Boolean(version && !/^latest$/iu.test(version))
    };
  }

  return {
    name: trimmed,
    versionPinned: false
  };
}

function npmVersionMarkerIndex(spec: string): number {
  if (spec.startsWith("@")) {
    const slashIndex = spec.indexOf("/");
    if (slashIndex === -1) return -1;
    return spec.indexOf("@", slashIndex + 1);
  }
  return spec.indexOf("@");
}

function parseMcpRemoteUrl(value: string | undefined): { host: string; scheme: string } | undefined {
  if (!value) return undefined;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
    return { host: parsed.hostname.toLowerCase(), scheme: parsed.protocol.replace(":", "") };
  } catch {
    return undefined;
  }
}

function extractSecretReferenceKeys(values: unknown[]): string[] {
  const keys = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") continue;
    for (const match of value.matchAll(/\$\{?([A-Z_][A-Z0-9_]*)\}?/g)) {
      if (match[1] && /token|secret|key|password|credential|auth/i.test(match[1])) keys.add(match[1]);
    }
  }
  return [...keys];
}

function isLocalHost(host: string): boolean {
  return ["localhost", "127.0.0.1", "::1", "0.0.0.0"].includes(host);
}

function uniqueActions(actions: ActionType[]): ActionType[] {
  return [...new Set(actions)].sort((a, b) => a.localeCompare(b));
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

function parseRuntimeConfig(content: string, filePath: string): { value?: unknown; parseFailed: boolean; parser?: string } {
  if (!content.trim()) return { parseFailed: false };
  const lowerPath = filePath.toLowerCase();
  const parser = lowerPath.endsWith(".json")
    ? "json"
    : lowerPath.endsWith(".toml")
      ? "toml"
      : lowerPath.endsWith(".yaml") || lowerPath.endsWith(".yml")
        ? "yaml"
        : undefined;
  try {
    if (parser === "json") return { value: JSON.parse(content), parseFailed: false, parser };
    if (parser === "toml") return { value: parseToml(content), parseFailed: false, parser };
    if (parser === "yaml") return { value: YAML.parse(content), parseFailed: false, parser };
  } catch {
    return { parseFailed: true, parser };
  }
  return { parseFailed: false, parser };
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

function extractToolDefinitions(content: string): { definitions: ExtractedToolDefinition[]; parseFailed: boolean } {
  if (!content.trim()) return { definitions: [], parseFailed: false };
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    try {
      parsed = YAML.parse(content);
    } catch {
      return { definitions: [], parseFailed: true };
    }
  }
  const candidates = toolCandidates(parsed);
  return {
    definitions: candidates
      .map((candidate) => normalizeToolDefinition(candidate))
      .filter((candidate): candidate is ExtractedToolDefinition => Boolean(candidate))
      .sort((a, b) => a.name.localeCompare(b.name)),
    parseFailed: false
  };
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
  open_world_authority: boolean;
  read_only_hint_conflict: boolean;
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
  const privilegedAction = [...actions].some((action) =>
    ["write", "execute", "publish", "send", "delete", "remember"].includes(action)
  );
  const readOnlyHintConflict = readOnly && (externalWrite || destructive || privilegedAction);
  const openWorldAuthority =
    definition.openWorldSchema &&
    (externalWrite ||
      destructive ||
      acceptsSecret ||
      acceptsPath ||
      acceptsUrl ||
      classes.has("shell_execution") ||
      classes.has("filesystem_access") ||
      classes.has("network_access"));
  const sideEffect =
    readOnlyHintConflict ||
    explicitSideEffectHint ||
    (!readOnly && privilegedAction);

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
    destructive_action: destructive,
    open_world_authority: openWorldAuthority,
    read_only_hint_conflict: readOnlyHintConflict
  };
}

function normalizeAuthorityText(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}
