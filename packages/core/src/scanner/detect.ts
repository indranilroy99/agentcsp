import path from "node:path";
import { parse as parseToml } from "smol-toml";
import YAML from "yaml";
import {
  DEFAULT_MCP_CONFIG_NAMES,
  GENERATED_STATE_DIR_NAMES,
  INSTRUCTION_FILE_NAMES,
  LOG_DIR_NAMES,
  MEMORY_DIR_NAMES,
  PROMPT_DIR_NAMES,
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
  const projectFilePaths = new Set(files.map((file) => normalizeProjectPath(file.relativePath)));
  const contextContentByPath = new Map<string, string>();

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

    if (isPromptTemplatePath(file.relativePath, basename)) {
      recordContextContent(contextContentByPath, file, text);
      detectPromptTemplateFile(file, text, surfaces);
      continue;
    }

    if (isAgentContextComposerConfigPath(file.relativePath, basename)) {
      detectAgentContextComposerConfig(file, text, surfaces);
      continue;
    }

    if (isAgentApprovalGateConfigPath(file.relativePath, basename)) {
      detectAgentApprovalGateConfig(file, text, surfaces);
      continue;
    }

    if (isAiModelEndpointConfigPath(file.relativePath, basename)) {
      detectAiModelEndpointConfig(file, text, surfaces);
      continue;
    }

    if (isAiEvalHarnessConfigPath(file.relativePath, basename)) {
      detectAiEvalHarnessConfig(file, text, surfaces);
      continue;
    }

    if (isAiTelemetryConfigPath(file.relativePath, basename)) {
      detectAiTelemetryConfig(file, text, surfaces);
      continue;
    }

    if (isAgentMemoryStoreConfigPath(file.relativePath, basename)) {
      detectAgentMemoryStoreConfig(file, text, surfaces);
      continue;
    }

    if (isRagConnectorConfigPath(file.relativePath, basename)) {
      detectRagConnectorConfig(file, text, surfaces);
      continue;
    }

    if (isBrowserSessionConfigPath(file.relativePath, basename)) {
      detectBrowserSessionConfig(file, text, surfaces);
      continue;
    }

    if (isInboundAgentTriggerConfigPath(file.relativePath, basename)) {
      detectInboundAgentTriggerConfig(file, text, surfaces);
      continue;
    }

    if (isAgentOrchestrationConfigPath(file.relativePath, basename)) {
      detectAgentOrchestrationConfig(file, text, surfaces);
      continue;
    }

    if (isAgentSafetyConfigPath(file.relativePath, basename)) {
      detectAgentSafetyConfig(file, text, surfaces);
      continue;
    }

    if (isAgentIdentityConfigPath(file.relativePath, basename)) {
      detectAgentIdentityConfig(file, text, surfaces);
      continue;
    }

    if (isAgentExtensionLoaderConfigPath(file.relativePath, basename)) {
      detectAgentExtensionLoaderConfig(file, text, surfaces);
      continue;
    }

    if (isAgentSelfModificationConfigPath(file.relativePath, basename)) {
      detectAgentSelfModificationConfig(file, text, surfaces);
      continue;
    }

    if (isSaasConnectorConfigPath(file.relativePath, basename)) {
      detectSaasConnectorConfig(file, text, surfaces);
      continue;
    }

    if (isSecretManagerConfigPath(file.relativePath, basename)) {
      detectSecretManagerConfig(file, text, surfaces);
      continue;
    }

    if (isAgentDatabaseConnectorConfigPath(file.relativePath, basename)) {
      detectDatabaseConnectorConfig(file, text, surfaces);
      continue;
    }

    if (INSTRUCTION_FILE_NAMES.has(basename) || isCursorRulePath(lowerPath)) {
      const content = text ?? "";
      const cursorRule = isCursorRulePath(lowerPath) ? classifyCursorRule(file, content, surfaces) : undefined;
      const analyzedContent = cursorRule?.analyzedContent ?? content;
      recordContextContent(contextContentByPath, file, text);
      const signals = classifyContextContent(analyzedContent);
      const actions = detectActions(analyzedContent);
      const dataClasses = contextualDataClasses(inferDataClasses(analyzedContent, file.relativePath), signals);
      const externalReach = hasExternalReach(analyzedContent) || signals.external_directive;
      const secretExposure = hasSecretExposure(analyzedContent) || signals.secret_reference;
      const base = {
        trust_level: inferTrustLevel(file.relativePath),
        actions,
        data_classes: dataClasses,
        external_reach: externalReach,
        secret_exposure: secretExposure
      };
      const instructionContextBridge = signals.untrusted_context_reference && signals.context_bridge_privileged;
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
          untrusted_to_privileged: instructionContextBridge || isUntrustedToPrivileged(base),
          reason: "Instruction file discovered as agent-consumable context.",
          metadata: {
            content_analyzed: text !== undefined,
            bytes: file.size,
            skipped_for_size: file.skippedForSize,
            content_redacted: true,
            ...cursorRule?.metadata,
            ...signals
          }
        })
      );
      continue;
    }

    const contextSurface = contextSurfaceType(file.relativePath);
    if (contextSurface === "rag_source") {
      recordContextContent(contextContentByPath, file, text);
      detectRagContentFile(file, text, surfaces);
      continue;
    }
    if (contextSurface === "memory") {
      recordContextContent(contextContentByPath, file, text);
      detectMemoryContentFile(file, text, surfaces);
      continue;
    }

    if (basename === "SKILL.md") {
      const content = text ?? "";
      recordContextContent(contextContentByPath, file, text);
      const actions = detectActions(content);
      const externalReach = hasExternalReach(content);
      const dataClasses = inferDataClasses(content, file.relativePath);
      const dataFlow = classifySkillDataFlow(content);
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
            content_redacted: true,
            content_analyzed: text !== undefined,
            skipped_for_size: file.skippedForSize,
            bytes: file.size,
            ...dataFlow
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
      await detectMcpConfig(file, text, surfaces, projectFilePaths);
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

  annotateToolNameCollisions(surfaces);
  annotateRuntimeCapabilityReferences(surfaces);
  annotateRuntimePackageScriptReferences(surfaces);
  annotateWorkflowPackageScriptReferences(surfaces);
  annotateContextCallableReferences(surfaces, contextContentByPath);
  return surfaces;
}

function recordContextContent(contentByPath: Map<string, string>, file: WalkedFile, text: string | undefined): void {
  if (text !== undefined) contentByPath.set(file.relativePath, text);
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
    data_classes: contextualDataClasses(inferDataClasses(content, file.relativePath), signals),
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

function detectRagConnectorConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const content = text ?? "";
  const parsed = parseStructuredConfig(content, file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "RAG_CONNECTOR_CONFIG_PARSE_FAILED",
      reason: "RAG or vector-store connector configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyRagConnectorConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.vector_store_write_enabled || posture.vector_store_sync_enabled) {
    actions.add("write");
    actions.add("remember");
  }
  if (posture.vector_store_remote) actions.add("send");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.secret_ref_key_names.length > 0 || posture.env_key_names.some(isCredentialLikeKeyName)) {
    dataClasses.add("credential");
  }
  if (posture.vector_store_sensitive_collection || posture.vector_store_ingests_untrusted_sources) {
    dataClasses.add("confidential");
  }
  if (posture.vector_store_pii_collection) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "rag_source",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.vector_store_remote ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect: posture.vector_store_write_enabled || posture.vector_store_sync_enabled,
    reversible: !posture.vector_store_write_enabled && !posture.vector_store_sync_enabled,
    external_reach: posture.vector_store_remote,
    secret_exposure: posture.secret_ref_key_names.length > 0 || posture.env_key_names.some(isCredentialLikeKeyName),
    reason: "RAG or vector-store connector configuration discovered as retrieval authority.",
    metadata: {
      content_redacted: true,
      content_analyzed: false,
      values_collected: false,
      parsed_rag_connector_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.rag_sources.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectAgentMemoryStoreConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AGENT_MEMORY_STORE_CONFIG_PARSE_FAILED",
      reason: "Agent memory-store configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAgentMemoryStoreConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "remember", "call"]);
  if (posture.agent_memory_store_write_enabled || posture.agent_memory_store_sync_enabled) actions.add("write");
  if (posture.agent_memory_store_remote) actions.add("send");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0 || posture.agent_memory_store_secret_capture) {
    dataClasses.add("credential");
  }
  if (
    posture.agent_memory_store_sensitive_data ||
    posture.agent_memory_store_untrusted_write ||
    posture.agent_memory_store_tool_output_capture ||
    posture.agent_memory_store_prompt_capture ||
    posture.agent_memory_store_retrieval_capture
  ) {
    dataClasses.add("confidential");
  }
  if (posture.agent_memory_store_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "memory",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.agent_memory_store_remote ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.agent_memory_store_persistent ||
      posture.agent_memory_store_shared ||
      posture.agent_memory_store_write_enabled ||
      posture.agent_memory_store_sync_enabled ||
      posture.agent_memory_store_output_replay_enabled,
    reversible: !posture.agent_memory_store_persistent && !posture.agent_memory_store_write_enabled && !posture.agent_memory_store_sync_enabled,
    external_reach: posture.agent_memory_store_remote,
    secret_exposure:
      posture.agent_memory_store_secret_capture ||
      posture.env_key_names.some(isCredentialLikeKeyName) ||
      posture.secret_ref_key_names.length > 0,
    reason: "Agent memory-store configuration discovered as durable context retention posture.",
    metadata: {
      content_redacted: true,
      content_analyzed: false,
      values_collected: false,
      parsed_agent_memory_store_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.memory.push({
    ...object,
    untrusted_to_privileged:
      (posture.agent_memory_store_untrusted_write &&
        (posture.agent_memory_store_write_enabled || posture.agent_memory_store_sync_enabled || posture.agent_memory_store_persistent) &&
        (posture.agent_memory_store_output_replay_enabled || posture.agent_memory_store_shared || posture.agent_memory_store_remote)) ||
      isUntrustedToPrivileged(object)
  });
}

function detectAiTelemetryConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AI_TELEMETRY_CONFIG_PARSE_FAILED",
      reason: "AI telemetry or trace-export configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAiTelemetryConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.ai_telemetry_remote_export) actions.add("send");
  if (posture.ai_telemetry_retention_enabled) actions.add("remember");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) dataClasses.add("credential");
  if (posture.ai_telemetry_sensitive_capture) dataClasses.add("confidential");
  if (posture.ai_telemetry_pii_capture) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.ai_telemetry_remote_export ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect: posture.ai_telemetry_export_enabled || posture.ai_telemetry_retention_enabled,
    reversible: !posture.ai_telemetry_remote_export && !posture.ai_telemetry_retention_enabled,
    external_reach: posture.ai_telemetry_remote_export,
    secret_exposure: posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "AI telemetry or trace-export configuration discovered as runtime data egress posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_ai_telemetry_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectAiModelEndpointConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AI_MODEL_CONFIG_PARSE_FAILED",
      reason: "AI model endpoint configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAiModelEndpointConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.ai_model_remote_endpoint) actions.add("send");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) dataClasses.add("credential");
  if (posture.ai_model_sensitive_context) dataClasses.add("confidential");
  if (posture.ai_model_pii_context) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.ai_model_remote_endpoint ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect: posture.ai_model_remote_endpoint,
    reversible: !posture.ai_model_remote_endpoint,
    external_reach: posture.ai_model_remote_endpoint,
    secret_exposure: posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "AI model endpoint configuration discovered as runtime prompt and context egress posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_ai_model_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectAiEvalHarnessConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AI_EVAL_HARNESS_CONFIG_PARSE_FAILED",
      reason: "AI eval or red-team harness configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAiEvalHarnessConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.ai_eval_live_execution || posture.ai_eval_invokes_agent || posture.ai_eval_invokes_tools) actions.add("execute");
  if (posture.ai_eval_external_write_authority || posture.ai_eval_write_authority) actions.add("write");
  if (posture.ai_eval_remote_target || posture.ai_eval_production_target || posture.ai_eval_external_write_authority) actions.add("send");
  if (posture.ai_eval_external_write_authority) actions.add("publish");
  if (posture.ai_eval_records_outputs) actions.add("remember");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.ai_eval_secret_exposure || posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) {
    dataClasses.add("credential");
  }
  if (posture.ai_eval_sensitive_data || posture.ai_eval_production_target) dataClasses.add("confidential");
  if (posture.ai_eval_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.ai_eval_remote_target || posture.ai_eval_production_target ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.ai_eval_live_execution ||
      posture.ai_eval_invokes_tools ||
      posture.ai_eval_write_authority ||
      posture.ai_eval_external_write_authority ||
      posture.ai_eval_records_outputs,
    reversible: !posture.ai_eval_write_authority && !posture.ai_eval_external_write_authority,
    external_reach: posture.ai_eval_remote_target || posture.ai_eval_external_write_authority || posture.ai_eval_production_target,
    secret_exposure: posture.ai_eval_secret_exposure || posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "AI eval or red-team harness configuration discovered as live agent test authority.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_ai_eval_harness_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      ((posture.ai_eval_adversarial_cases || posture.ai_eval_untrusted_prompts) &&
        (posture.ai_eval_live_execution || posture.ai_eval_invokes_agent) &&
        (posture.ai_eval_invokes_tools ||
          posture.ai_eval_write_authority ||
          posture.ai_eval_external_write_authority ||
          posture.ai_eval_secret_exposure)) ||
      isUntrustedToPrivileged(object)
  });
}

function detectDatabaseConnectorConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "DATABASE_CONNECTOR_CONFIG_PARSE_FAILED",
      reason: "Database connector configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyDatabaseConnectorConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.database_query_execution_enabled) actions.add("execute");
  if (posture.database_write_enabled) actions.add("write");
  if (posture.database_delete_enabled) actions.add("delete");
  if (posture.database_remote) actions.add("send");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) dataClasses.add("credential");
  if (posture.database_sensitive_data) dataClasses.add("confidential");
  if (posture.database_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.database_remote ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect: posture.database_write_enabled || posture.database_delete_enabled || posture.database_query_execution_enabled,
    reversible: !posture.database_write_enabled && !posture.database_delete_enabled,
    external_reach: posture.database_remote,
    secret_exposure: posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "Database connector configuration discovered as runtime data authority.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_database_connector_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectBrowserSessionConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "BROWSER_SESSION_CONFIG_PARSE_FAILED",
      reason: "Browser session configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyBrowserSessionConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.browser_network_remote) actions.add("send");
  if (posture.browser_click_or_form_authority || posture.browser_download_upload_enabled) actions.add("write");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (
    posture.browser_authenticated_session ||
    posture.env_key_names.some(isCredentialLikeKeyName) ||
    posture.secret_ref_key_names.length > 0
  ) {
    dataClasses.add("credential");
  }
  if (posture.browser_sensitive_data) dataClasses.add("confidential");
  if (posture.browser_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.browser_network_remote ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect: posture.browser_click_or_form_authority || posture.browser_download_upload_enabled,
    reversible: !posture.browser_click_or_form_authority && !posture.browser_download_upload_enabled,
    external_reach: posture.browser_network_remote,
    secret_exposure:
      posture.browser_authenticated_session ||
      posture.env_key_names.some(isCredentialLikeKeyName) ||
      posture.secret_ref_key_names.length > 0,
    reason: "Browser session configuration discovered as authenticated agent browsing authority.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_browser_session_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectInboundAgentTriggerConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "INBOUND_TRIGGER_CONFIG_PARSE_FAILED",
      reason: "Inbound agent trigger configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyInboundAgentTriggerConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.inbound_trigger_external_source) actions.add("send");
  if (posture.inbound_trigger_invokes_tools) actions.add("execute");
  if (posture.inbound_trigger_write_authority) actions.add("write");
  if (posture.inbound_trigger_external_response) actions.add("publish");
  if (posture.inbound_trigger_memory_write) actions.add("remember");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) dataClasses.add("credential");
  if (posture.inbound_trigger_sensitive_context) dataClasses.add("confidential");
  if (posture.inbound_trigger_pii_context) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.inbound_trigger_external_source ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.inbound_trigger_invokes_tools ||
      posture.inbound_trigger_write_authority ||
      posture.inbound_trigger_external_response ||
      posture.inbound_trigger_memory_write,
    reversible: !posture.inbound_trigger_write_authority && !posture.inbound_trigger_external_response,
    external_reach: posture.inbound_trigger_external_source || posture.inbound_trigger_external_response,
    secret_exposure: posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "Inbound agent trigger configuration discovered as external context-to-authority posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_inbound_trigger_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      (posture.inbound_trigger_external_source &&
        posture.inbound_trigger_invokes_agent &&
        (posture.inbound_trigger_invokes_tools ||
          posture.inbound_trigger_write_authority ||
          posture.inbound_trigger_external_response ||
          posture.inbound_trigger_memory_write)) ||
      isUntrustedToPrivileged(object)
  });
}

function detectAgentOrchestrationConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AGENT_ORCHESTRATION_CONFIG_PARSE_FAILED",
      reason: "Multi-agent orchestration configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAgentOrchestrationConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.agent_orchestration_invokes_tools) actions.add("execute");
  if (posture.agent_orchestration_write_authority) actions.add("write");
  if (posture.agent_orchestration_external_authority) {
    actions.add("send");
    actions.add("publish");
  }
  if (posture.agent_orchestration_shared_memory) actions.add("remember");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) dataClasses.add("credential");
  if (posture.agent_orchestration_sensitive_data) dataClasses.add("confidential");
  if (posture.agent_orchestration_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.agent_orchestration_delegation_enabled ||
      posture.agent_orchestration_invokes_tools ||
      posture.agent_orchestration_write_authority ||
      posture.agent_orchestration_external_authority ||
      posture.agent_orchestration_shared_memory,
    reversible: !posture.agent_orchestration_write_authority && !posture.agent_orchestration_external_authority,
    external_reach: posture.agent_orchestration_external_authority,
    secret_exposure: posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "Multi-agent orchestration configuration discovered as delegation and authority posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_agent_orchestration_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      (posture.agent_orchestration_delegation_enabled &&
        posture.agent_orchestration_untrusted_input &&
        (posture.agent_orchestration_invokes_tools ||
          posture.agent_orchestration_write_authority ||
          posture.agent_orchestration_external_authority ||
          posture.agent_orchestration_shared_memory)) ||
      isUntrustedToPrivileged(object)
  });
}

function detectAgentSafetyConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AGENT_SAFETY_CONFIG_PARSE_FAILED",
      reason: "Agent safety or guardrail configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAgentSafetyConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.agent_safety_privileged_tool_authority) actions.add("execute");
  if (posture.agent_safety_write_authority) actions.add("write");
  if (posture.agent_safety_external_authority) {
    actions.add("send");
    actions.add("publish");
  }
  if (posture.agent_safety_memory_write_authority) actions.add("remember");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (
    posture.agent_safety_secret_exposure ||
    posture.env_key_names.some(isCredentialLikeKeyName) ||
    posture.secret_ref_key_names.length > 0
  ) {
    dataClasses.add("credential");
  }
  if (posture.agent_safety_sensitive_data) dataClasses.add("confidential");
  if (posture.agent_safety_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.agent_safety_controls_disabled ||
      posture.agent_safety_privileged_tool_authority ||
      posture.agent_safety_write_authority ||
      posture.agent_safety_external_authority ||
      posture.agent_safety_memory_write_authority,
    reversible: !posture.agent_safety_write_authority && !posture.agent_safety_external_authority,
    external_reach: posture.agent_safety_external_authority,
    secret_exposure:
      posture.agent_safety_secret_exposure ||
      posture.env_key_names.some(isCredentialLikeKeyName) ||
      posture.secret_ref_key_names.length > 0,
    reason: "Agent safety or guardrail configuration discovered as runtime control posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_agent_safety_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      (posture.agent_safety_controls_disabled &&
        posture.agent_safety_untrusted_input &&
        (posture.agent_safety_privileged_tool_authority ||
          posture.agent_safety_write_authority ||
          posture.agent_safety_external_authority ||
          posture.agent_safety_memory_write_authority)) ||
      isUntrustedToPrivileged(object)
  });
}

function detectAgentIdentityConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AGENT_IDENTITY_CONFIG_PARSE_FAILED",
      reason: "Agent identity or credential delegation configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAgentIdentityConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.agent_identity_remote) actions.add("send");
  if (posture.agent_identity_credential_issuance_enabled || posture.agent_identity_impersonation_enabled) actions.add("approve");
  if (posture.agent_identity_write_scope || posture.agent_identity_admin_scope) actions.add("write");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (
    posture.agent_identity_credential_issuance_enabled ||
    posture.agent_identity_impersonation_enabled ||
    posture.env_key_names.some(isCredentialLikeKeyName) ||
    posture.secret_ref_key_names.length > 0
  ) {
    dataClasses.add("credential");
  }
  if (posture.agent_identity_sensitive_data || posture.agent_identity_untrusted_input) dataClasses.add("confidential");
  if (posture.agent_identity_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.agent_identity_remote ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.agent_identity_credential_issuance_enabled ||
      posture.agent_identity_impersonation_enabled ||
      posture.agent_identity_write_scope ||
      posture.agent_identity_admin_scope ||
      posture.agent_identity_tool_injection,
    reversible:
      !posture.agent_identity_credential_issuance_enabled &&
      !posture.agent_identity_impersonation_enabled &&
      !posture.agent_identity_write_scope &&
      !posture.agent_identity_admin_scope,
    external_reach: posture.agent_identity_remote || posture.agent_identity_external_authority,
    secret_exposure:
      posture.agent_identity_credential_issuance_enabled ||
      posture.agent_identity_impersonation_enabled ||
      posture.env_key_names.some(isCredentialLikeKeyName) ||
      posture.secret_ref_key_names.length > 0,
    reason: "Agent identity delegation configuration discovered as credential issuance and impersonation posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_agent_identity_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      (posture.agent_identity_untrusted_input &&
        (posture.agent_identity_credential_issuance_enabled || posture.agent_identity_impersonation_enabled) &&
        (posture.agent_identity_broad_scope || posture.agent_identity_write_scope || posture.agent_identity_admin_scope || posture.agent_identity_tool_injection)) ||
      isUntrustedToPrivileged(object)
  });
}

function detectAgentExtensionLoaderConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AGENT_EXTENSION_LOADER_CONFIG_PARSE_FAILED",
      reason: "Agent extension loader configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAgentExtensionLoaderConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.agent_extension_loader_remote) actions.add("send");
  if (
    posture.agent_extension_loader_auto_install_enabled ||
    posture.agent_extension_loader_auto_update_enabled ||
    posture.agent_extension_loader_privileged_authority
  ) {
    actions.add("execute");
  }
  if (posture.agent_extension_loader_privileged_authority) actions.add("write");
  if (posture.agent_extension_loader_external_authority) actions.add("publish");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) dataClasses.add("credential");
  if (posture.agent_extension_loader_sensitive_data || posture.agent_extension_loader_untrusted_input) dataClasses.add("confidential");
  if (posture.agent_extension_loader_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.agent_extension_loader_remote ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.agent_extension_loader_auto_install_enabled ||
      posture.agent_extension_loader_auto_update_enabled ||
      posture.agent_extension_loader_privileged_authority ||
      posture.agent_extension_loader_external_authority,
    reversible: !posture.agent_extension_loader_auto_install_enabled && !posture.agent_extension_loader_auto_update_enabled,
    external_reach: posture.agent_extension_loader_remote || posture.agent_extension_loader_external_authority,
    secret_exposure: posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "Agent extension loader configuration discovered as dynamic capability loading posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_agent_extension_loader_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      (posture.agent_extension_loader_untrusted_input &&
        (posture.agent_extension_loader_auto_install_enabled || posture.agent_extension_loader_auto_update_enabled) &&
        posture.agent_extension_loader_privileged_authority) ||
      isUntrustedToPrivileged(object)
  });
}

function detectAgentSelfModificationConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AGENT_SELF_MODIFICATION_CONFIG_PARSE_FAILED",
      reason: "Agent self-modification configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAgentSelfModificationConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.agent_self_modification_write_enabled || posture.agent_self_modification_auto_apply) actions.add("write");
  if (posture.agent_self_modification_executes_after_update) actions.add("execute");
  if (posture.agent_self_modification_external_authority) {
    actions.add("send");
    actions.add("publish");
  }
  if (posture.agent_self_modification_memory_target) actions.add("remember");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) dataClasses.add("credential");
  if (posture.agent_self_modification_sensitive_data || posture.agent_self_modification_untrusted_input) dataClasses.add("confidential");
  if (posture.agent_self_modification_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.agent_self_modification_write_enabled ||
      posture.agent_self_modification_auto_apply ||
      posture.agent_self_modification_persistent_change ||
      posture.agent_self_modification_executes_after_update,
    reversible: posture.agent_self_modification_rollback_enabled,
    external_reach: posture.agent_self_modification_external_authority,
    secret_exposure: posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "Agent self-modification configuration discovered as persistent control-plane mutation posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_agent_self_modification_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      (posture.agent_self_modification_untrusted_input &&
        posture.agent_self_modification_write_enabled &&
        (posture.agent_self_modification_instruction_target ||
          posture.agent_self_modification_policy_target ||
          posture.agent_self_modification_tool_target ||
          posture.agent_self_modification_runtime_target) &&
        posture.agent_self_modification_auto_apply) ||
      isUntrustedToPrivileged(object)
  });
}

function detectAgentApprovalGateConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AGENT_APPROVAL_GATE_CONFIG_PARSE_FAILED",
      reason: "Agent approval-gate configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAgentApprovalGateConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["approve", "call", "read"]);
  if (posture.agent_approval_auto_execute_after_approval) actions.add("execute");
  if (posture.agent_approval_write_actions || posture.agent_approval_destructive_actions) actions.add("write");
  if (posture.agent_approval_external_actions) {
    actions.add("send");
    actions.add("publish");
  }
  if (posture.agent_approval_memory_write) actions.add("remember");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (
    posture.agent_approval_secret_access ||
    posture.env_key_names.some(isCredentialLikeKeyName) ||
    posture.secret_ref_key_names.length > 0
  ) {
    dataClasses.add("credential");
  }
  if (posture.agent_approval_sensitive_data || posture.agent_approval_context_untrusted) dataClasses.add("confidential");
  if (posture.agent_approval_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.agent_approval_auto_execute_after_approval ||
      posture.agent_approval_privileged_actions ||
      posture.agent_approval_default_allow ||
      posture.agent_approval_decision_model_driven,
    reversible: !posture.agent_approval_destructive_actions && !posture.agent_approval_external_actions,
    external_reach: posture.agent_approval_external_actions,
    secret_exposure:
      posture.agent_approval_secret_access ||
      posture.env_key_names.some(isCredentialLikeKeyName) ||
      posture.secret_ref_key_names.length > 0,
    reason: "Agent approval-gate configuration discovered as privileged decision posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_agent_approval_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      posture.agent_approval_context_untrusted &&
      posture.agent_approval_privileged_actions &&
      posture.agent_approval_auto_execute_after_approval &&
      (posture.agent_approval_decision_model_driven ||
        posture.agent_approval_uses_untrusted_summary ||
        posture.agent_approval_default_allow ||
        !posture.agent_approval_human_required)
  });
}

function detectAgentContextComposerConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "AGENT_CONTEXT_COMPOSER_CONFIG_PARSE_FAILED",
      reason: "Agent context-composer configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifyAgentContextComposerConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["call", "read"]);
  if (posture.agent_context_composer_write_authority || posture.agent_context_composer_privileged_tool_authority) actions.add("write");
  if (posture.agent_context_composer_external_authority) {
    actions.add("send");
    actions.add("publish");
  }
  if (posture.agent_context_composer_memory_write) actions.add("remember");
  if (posture.agent_context_composer_shell_authority) actions.add("execute");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (
    posture.agent_context_composer_secret_access ||
    posture.env_key_names.some(isCredentialLikeKeyName) ||
    posture.secret_ref_key_names.length > 0
  ) {
    dataClasses.add("credential");
  }
  if (posture.agent_context_composer_sensitive_data || posture.agent_context_composer_untrusted_sources) dataClasses.add("confidential");
  if (posture.agent_context_composer_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect:
      posture.agent_context_composer_privileged_tool_authority ||
      posture.agent_context_composer_write_authority ||
      posture.agent_context_composer_external_authority ||
      posture.agent_context_composer_memory_write,
    reversible: !posture.agent_context_composer_external_authority && !posture.agent_context_composer_destructive_authority,
    external_reach: posture.agent_context_composer_external_authority,
    secret_exposure:
      posture.agent_context_composer_secret_access ||
      posture.env_key_names.some(isCredentialLikeKeyName) ||
      posture.secret_ref_key_names.length > 0,
    reason: "Agent context-composer configuration discovered as prompt assembly and role-boundary posture.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_agent_context_composer_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged:
      posture.agent_context_composer_untrusted_sources &&
      posture.agent_context_composer_privileged_role_injection &&
      posture.agent_context_composer_privileged_tool_authority &&
      (posture.agent_context_composer_sanitization_disabled || posture.agent_context_composer_delimiter_disabled)
  });
}

function detectSaasConnectorConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "SAAS_CONNECTOR_CONFIG_PARSE_FAILED",
      reason: "SaaS or API connector configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifySaasConnectorConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.saas_connector_external_reach) actions.add("send");
  if (posture.saas_connector_external_write_enabled) {
    actions.add("write");
    actions.add("publish");
  }
  if (posture.saas_connector_admin_scope) actions.add("approve");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["unknown"]);
  if (posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0) dataClasses.add("credential");
  if (posture.saas_connector_sensitive_data) dataClasses.add("confidential");
  if (posture.saas_connector_pii_data) dataClasses.add("pii");
  if (dataClasses.size > 1) dataClasses.delete("unknown");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.saas_connector_external_reach ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect: posture.saas_connector_external_write_enabled || posture.saas_connector_admin_scope,
    reversible: !posture.saas_connector_external_write_enabled && !posture.saas_connector_admin_scope,
    external_reach: posture.saas_connector_external_reach,
    secret_exposure: posture.env_key_names.some(isCredentialLikeKeyName) || posture.secret_ref_key_names.length > 0,
    reason: "SaaS or API connector configuration discovered as external agent authority.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_saas_connector_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
    ...object,
    untrusted_to_privileged: isUntrustedToPrivileged(object)
  });
}

function detectSecretManagerConfig(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const parsed = parseStructuredConfig(text ?? "", file.relativePath);
  if (parsed.parseFailed) {
    addDiagnostic(surfaces, file, {
      parser: parsed.parser ?? "structured_config",
      code: "SECRET_MANAGER_CONFIG_PARSE_FAILED",
      reason: "Secret manager connector configuration could not be parsed. Raw content was redacted."
    });
  }

  const posture = classifySecretManagerConfig(parsed.value, file.relativePath);
  const actions = new Set<ActionType>(["read", "call"]);
  if (posture.secret_manager_remote) actions.add("send");
  if (posture.secret_manager_write_enabled) actions.add("write");
  if (posture.secret_manager_injects_into_tools) actions.add("execute");

  const dataClasses = new Set<SurfaceObject["data_classes"][number]>(["credential", "secret"]);
  if (posture.secret_manager_sensitive_scope) dataClasses.add("confidential");
  if (posture.secret_manager_pii_scope) dataClasses.add("pii");

  const object = createSurfaceObject({
    type: "runtime_config",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: posture.secret_manager_remote ? "third_party" : inferTrustLevel(file.relativePath),
    data_classes: uniqueDataClasses([...dataClasses] as SurfaceObject["data_classes"]),
    actions: uniqueActions([...actions]),
    side_effect: posture.secret_manager_write_enabled || posture.secret_manager_injects_into_tools,
    reversible: !posture.secret_manager_write_enabled,
    external_reach: posture.secret_manager_remote,
    secret_exposure: true,
    reason: "Secret manager connector configuration discovered as credential-broker authority.",
    metadata: {
      content_redacted: true,
      values_collected: false,
      parsed_secret_manager_config: Boolean(parsed.value) && !parsed.parseFailed,
      parse_error: parsed.parseFailed,
      ...posture
    }
  });
  surfaces.runtime_config.push({
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
    data_classes: contextualDataClasses(inferDataClasses(content, file.relativePath), signals),
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

function detectPromptTemplateFile(file: WalkedFile, text: string | undefined, surfaces: DetectedSurfaces): void {
  const content = text ?? "";
  const signals = classifyContextContent(content);
  const template = classifyPromptTemplate(content);
  const bridge = classifyPromptTemplateBridge(template, signals);
  const actions = promptActions(signals);
  const object = createSurfaceObject({
    type: "prompt",
    name: path.basename(file.relativePath),
    path: file.relativePath,
    trust_level: inferTrustLevel(file.relativePath),
    data_classes: contextualDataClasses(inferDataClasses(content, file.relativePath), signals),
    actions,
    side_effect: actions.some((action) => action !== "read"),
    reversible: isReversible(content),
    external_reach: signals.external_directive,
    secret_exposure: signals.secret_reference,
    reason: "Prompt template discovered as agent-consumable context.",
    metadata: {
      content_redacted: true,
      content_analyzed: text !== undefined,
      skipped_for_size: file.skippedForSize,
      bytes: file.size,
      ...template,
      ...bridge,
      ...signals
    }
  });
  surfaces.prompts.push({
    ...object,
    untrusted_to_privileged: bridge.template_bridge_privileged || isUntrustedToPrivileged(object)
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

function isAiTelemetryConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  const segments = normalized.split("/").slice(0, -1);
  const telemetryDirectory = segments.some((segment) =>
    /^(observability|telemetry|tracing|traces|evals|evaluations|langsmith|langfuse|helicone|braintrust|phoenix|arize|traceloop|opentelemetry|otel)$/iu.test(
      segment
    )
  );
  const telemetryName = /(?:observability|telemetry|tracing|trace|langsmith|langfuse|helicone|braintrust|phoenix|arize|traceloop|opentelemetry|otel)/iu.test(
    lowerBase
  );
  return telemetryDirectory || telemetryName;
}

function isAiEvalHarnessConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  if (normalized.startsWith("rules/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const evalDirectory = segments.some((segment) =>
    /^(evals?|evaluations?|red[-_]?team|redteam|adversarial|scenarios?|test-harness|test_harness|promptfoo|garak|deepeval|agent-tests?|agent_tests?|ai-tests?|ai_tests?)$/iu.test(
      segment
    )
  );
  const evalName = /(?:eval|evaluation|red[-_]?team|redteam|adversarial|scenario|promptfoo|garak|deepeval|jailbreak|agent-test|agent_test|test-harness|test_harness)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|suite|scenarios?|tests?|evals?|evaluation|red[-_]?team|promptfoo|garak|deepeval|harness)/iu.test(
    lowerBase
  );
  return evalName || (evalDirectory && configName);
}

function isAgentMemoryStoreConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  if (normalized.startsWith("rules/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const memoryDirectory = segments.some((segment) =>
    /^(memory|memories|memory-store|memory_store|long-term-memory|long_term_memory|checkpoints?|checkpointers?|state|states|session-store|session_store|thread-store|thread_store|agent-memory|agent_memory)$/iu.test(
      segment
    )
  );
  const memoryName = /(?:memory|memories|checkpointer|checkpoint|thread-store|thread_store|session-store|session_store|long-term|long_term|mem0|zep|langgraph|redis-memory|redis_memory|memory-store|memory_store)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|store|stores|memory|memories|checkpoint|checkpointer|state|session|thread|persistence|retention)/iu.test(
    lowerBase
  );
  return memoryName || (memoryDirectory && configName);
}

function isAiModelEndpointConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  const segments = normalized.split("/").slice(0, -1);
  const modelDirectory = segments.some((segment) =>
    /^(models?|llms?|ai|inference|providers?|model-providers?|model-gateway|gateways?|litellm|openai|anthropic)$/iu.test(segment)
  );
  const modelConfigName = /(?:model|llm|inference|provider|gateway|router|proxy|openai|anthropic|litellm|completion|chat)/iu.test(lowerBase);
  const configName = /(?:config|settings|provider|gateway|endpoint|llm|model|inference|router|proxy|openai|anthropic|litellm|completion|chat)/iu.test(
    lowerBase
  );
  return modelConfigName || (modelDirectory && configName);
}

function isAgentDatabaseConnectorConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  const segments = normalized.split("/").slice(0, -1);
  const databaseDirectory = segments.some((segment) =>
    /^(database|databases|db|sql|warehouse|warehouses|datastore|datastores|connectors?|data-sources?|datasources)$/iu.test(segment)
  );
  const databaseName = /(?:database|db|sql|postgres|postgresql|mysql|mariadb|mssql|sqlserver|sqlite|snowflake|bigquery|redshift|databricks|warehouse|connector|datasource|data-source)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|connector|datasource|data-source|database|db|sql|warehouse|source)/iu.test(lowerBase);
  return databaseName || (databaseDirectory && configName);
}

function isBrowserSessionConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  const segments = normalized.split("/").slice(0, -1);
  const browserDirectory = segments.some((segment) =>
    /^(browser|browsers|browser-agent|web-agent|playwright|puppeteer|selenium|stagehand|browserbase|browser-use|browser_use)$/iu.test(segment)
  );
  const browserName = /(?:browser|playwright|puppeteer|selenium|stagehand|browserbase|browser-use|browser_use|browser-session|browser_session|browser-profile|browser_profile)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|session|profile|auth|cookies?|storage-state|storage_state|context)/iu.test(lowerBase);
  return browserName || (browserDirectory && configName);
}

function isInboundAgentTriggerConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  const segments = normalized.split("/").slice(0, -1);
  const triggerDirectory = segments.some((segment) =>
    /^(inbox|inbound|triggers?|events?|webhooks?|listeners?|receivers?|mail|email|messages?|chat|queue|queues|tickets?)$/iu.test(segment)
  );
  const triggerName = /(?:inbound|inbox|trigger|event|webhook|listener|receiver|mail|email|message|chat|ticket|triage|intake)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|connector|trigger|event|webhook|listener|receiver|inbox|source|intake|triage|agent)/iu.test(
    lowerBase
  );
  return triggerName || (triggerDirectory && configName);
}

function isAgentOrchestrationConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  if (normalized.startsWith("rules/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const orchestrationDirectory = segments.some((segment) =>
    /^(agents?|subagents?|multi-agent|multi_agent|orchestration|orchestrators?|crews?|teams?|graphs?|langgraph|crewai|autogen|semantic-kernel|swarm)$/iu.test(
      segment
    )
  );
  const orchestrationName = /(?:crew|crewai|autogen|langgraph|semantic-kernel|semantic_kernel|swarm|multi-agent|multi_agent|subagent|orchestrat|delegate|handoff|supervisor|agent-team|agent_team|agent-graph|agent_graph)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|agents?|crew|team|graph|workflow|orchestrat|delegate|handoff|supervisor|runtime)/iu.test(
    lowerBase
  );
  return orchestrationName || (orchestrationDirectory && configName);
}

function isAgentSafetyConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const safetyDirectory = segments.some((segment) =>
    /^(guardrails?|safety|safety-controls|safety_controls|policy|policies|runtime-policy|runtime_policy|evaluators?|validators?|moderation|controls)$/iu.test(
      segment
    )
  );
  const safetyName = /(?:guardrail|safety|moderation|content-filter|content_filter|prompt-injection|prompt_injection|injection-filter|injection_filter|output-validator|output_validator|tool-result|tool_result|redaction|sanitize|sanitizer|validator|runtime-policy|runtime_policy)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|policy|policies|controls?|guardrails?|safety|moderation|validator|redaction|sanitiz)/iu.test(
    lowerBase
  );
  return safetyName || (safetyDirectory && configName);
}

function isAgentIdentityConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  if (normalized.startsWith("rules/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const identityDirectory = segments.some((segment) =>
    /^(identity|identities|auth|authorization|oauth|oidc|workload-identity|workload_identity|service-accounts?|service_accounts?|iam|federation|credential-delegation|credential_delegation)$/iu.test(
      segment
    )
  );
  const identityName = /(?:identity|auth|oauth|oidc|workload-identity|workload_identity|service-account|service_account|iam|impersonat|delegat|federat|token-broker|token_broker|credential-delegation|credential_delegation)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|identity|auth|oauth|oidc|iam|service|account|token|credential|delegat|impersonat|broker|federat)/iu.test(
    lowerBase
  );
  return identityName || (identityDirectory && configName);
}

function isAgentExtensionLoaderConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (lowerBase === "plugin.json") return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  if (normalized.startsWith("rules/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const extensionDirectory = segments.some((segment) =>
    /^(extensions?|extension-registry|extension_registry|marketplaces?|registries|registry|skill-registry|skill_registry|plugin-registry|plugin_registry|remote-skills|remote_skills|capability-registry|capability_registry)$/iu.test(
      segment
    )
  );
  const extensionName = /(?:extension|marketplace|registry|catalog|remote-skill|remote_skill|remote-plugin|remote_plugin|skill-registry|skill_registry|plugin-registry|plugin_registry|capability-loader|capability_loader|extension-loader|extension_loader)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|registry|marketplace|catalog|loader|extensions?|skills?|plugins?|capabilities|install|autoload|auto-load|remote)/iu.test(
    lowerBase
  );
  return extensionName || (extensionDirectory && configName);
}

function isAgentSelfModificationConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  if (normalized.startsWith("rules/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const mutationDirectory = segments.some((segment) =>
    /^(self-modification|self_modification|self-update|self_update|agent-updates?|agent_updates?|policy-writers?|policy_writers?|mutation|mutations|patches|autofix|auto-fix|codemods?)$/iu.test(
      segment
    )
  );
  const mutationName = /(?:self-modification|self_modification|self-update|self_update|agent-update|agent_update|policy-writer|policy_writer|prompt-writer|prompt_writer|instruction-writer|instruction_writer|runtime-writer|runtime_writer|autofix|auto-fix|codemod|mutation)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|policy|prompt|instruction|runtime|mutation|patch|update|writer|autofix|codemod|self)/iu.test(
    lowerBase
  );
  return mutationName || (mutationDirectory && configName);
}

function isAgentApprovalGateConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  if (normalized.startsWith("rules/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const approvalDirectory = segments.some((segment) =>
    /^(approvals?|approval-gates?|approval_gates?|review-gates?|review_gates?|human-review|human_review|hitl|human-in-the-loop|human_in_the_loop|decision-gates?|decision_gates?)$/iu.test(
      segment
    )
  );
  const approvalName = /(?:approval|approve|approver|review|reviewer|human-review|human_review|hitl|human-in-the-loop|human_in_the_loop|decision-gate|decision_gate|approval-gate|approval_gate|model-reviewer|model_reviewer)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|policy|approval|review|gate|decision|workflow|runtime|human|model)/iu.test(lowerBase);
  return approvalName || (approvalDirectory && configName);
}

function isAgentContextComposerConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  if (normalized.startsWith(".github/workflows/")) return false;
  if (normalized.startsWith("rules/")) return false;
  const segments = normalized.split("/").slice(0, -1);
  const contextDirectory = segments.some((segment) =>
    /^(context|contexts|context-composer|context_composer|prompt-composer|prompt_composer|prompt-assembly|prompt_assembly|prompt-router|prompt_router|context-router|context_router|context-policy|context_policy)$/iu.test(
      segment
    )
  );
  const contextName = /(?:context-composer|context_composer|prompt-composer|prompt_composer|prompt-assembly|prompt_assembly|context-router|context_router|prompt-router|prompt_router|context-policy|context_policy|role-map|role_map|message-builder|message_builder|context-builder|context_builder)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|policy|context|prompt|role|message|composer|assembly|builder|router|sources?)/iu.test(lowerBase);
  return contextName || (contextDirectory && configName);
}

function isSaasConnectorConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  const segments = normalized.split("/").slice(0, -1);
  const connectorDirectory = segments.some((segment) =>
    /^(integrations?|connectors?|api-connectors?|apis?|saas|services?|slack|github|email|gmail|jira|linear|zendesk|salesforce|hubspot|notion|ticketing|crm)$/iu.test(
      segment
    )
  );
  const providerName = /(?:slack|github|gitlab|email|gmail|outlook|smtp|jira|linear|zendesk|salesforce|hubspot|notion|servicenow|ticketing|crm|webhook|api-connector|api_connector|saas-connector|saas_connector)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|connector|integration|service|client|oauth|api|webhook|destination|sink)/iu.test(lowerBase);
  return providerName || (connectorDirectory && configName);
}

function isSecretManagerConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;
  const segments = normalized.split("/").slice(0, -1);
  const secretDirectory = segments.some((segment) =>
    /^(secrets?|secret-manager|secret_managers?|vault|vaults|credentials?|credential-broker|credential_broker|kms|keyvault|key-vault)$/iu.test(
      segment
    )
  );
  const secretManagerName = /(?:secret-manager|secret_manager|secrets-manager|secrets_manager|vault|keyvault|key-vault|aws-secrets|gcp-secret|azure-keyvault|credential-broker|credential_broker|kms)/iu.test(
    lowerBase
  );
  const configName = /(?:config|settings|connector|broker|vault|secret|secrets|policy|access|auth)/iu.test(lowerBase);
  return secretManagerName || (secretDirectory && configName);
}

function isRagConnectorConfigPath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  if (!/\.(json|ya?ml|toml)$/iu.test(lowerBase)) return false;

  const segments = normalized.split("/").slice(0, -1);
  const inRagDirectory = segments.some((segment) => RAG_DIR_NAMES.has(segment));
  const connectorName = /(?:rag|retriev|vector|embedding|embed|knowledge|corpus|index|connector|source|store)/iu.test(lowerBase);
  const configName = /(?:config|settings|store|index|source|connector|vector|embedding|retrieval)/iu.test(lowerBase);
  return (inRagDirectory && configName) || connectorName;
}

function isPromptTemplatePath(relativePath: string, basename: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/").toLowerCase();
  const lowerBase = basename.toLowerCase();
  const segments = normalized.split("/").slice(0, -1);
  if (segments.some((segment) => PROMPT_DIR_NAMES.has(segment))) {
    return /\.(md|txt|yaml|yml|json|prompt)$/iu.test(lowerBase);
  }
  return (
    lowerBase.endsWith(".prompt.md") ||
    lowerBase.endsWith(".prompt.txt") ||
    lowerBase.endsWith(".prompt.yaml") ||
    lowerBase.endsWith(".prompt.yml") ||
    lowerBase.endsWith(".prompt.json")
  );
}

interface ContextContentSignals {
  instruction_like_content: boolean;
  instruction_override: boolean;
  untrusted_context_reference: boolean;
  tool_directive: boolean;
  memory_write_directive: boolean;
  external_directive: boolean;
  secret_reference: boolean;
  sensitive_context_reference: boolean;
  data_egress_directive: boolean;
  context_bridge_tool: boolean;
  context_bridge_memory: boolean;
  context_bridge_external: boolean;
  context_bridge_data_egress: boolean;
  context_bridge_privileged: boolean;
  content_signal_count: number;
}

interface GeneratedStateSignals {
  generated_state: boolean;
  generated_state_kinds: string[];
  transcript_like: boolean;
  tool_output_like: boolean;
  cached_output_like: boolean;
}

interface PromptTemplateSignals {
  prompt_template: boolean;
  template_variable_names: string[];
  template_variable_count: number;
  untrusted_template_variables: string[];
  untrusted_template_input: boolean;
  privileged_prompt_role: boolean;
  privileged_template_roles: string[];
  privileged_role_untrusted_variables: string[];
  privileged_role_untrusted_variable_count: number;
  privileged_role_untrusted_template_input: boolean;
}

interface PromptTemplateBridgeSignals {
  template_bridge_tool: boolean;
  template_bridge_memory: boolean;
  template_bridge_external: boolean;
  template_bridge_secret: boolean;
  template_bridge_privileged: boolean;
}

interface SkillDataFlowSignals {
  retrieved_context_input: boolean;
  tool_output_input: boolean;
  memory_input: boolean;
  prompt_input: boolean;
  context_input_sources: string[];
  context_input_count: number;
  external_output: boolean;
  local_write_output: boolean;
  context_bridge_external_output: boolean;
}

interface RagConnectorPosture {
  rag_connector_fields: string[];
  vector_store: boolean;
  vector_store_provider?: string;
  vector_store_remote: boolean;
  vector_store_destination_redacted: boolean;
  vector_store_remote_destination_count: number;
  vector_store_remote_destination_kinds: string[];
  vector_store_write_enabled: boolean;
  vector_store_sync_enabled: boolean;
  vector_store_ingests_untrusted_sources: boolean;
  vector_store_sensitive_collection: boolean;
  vector_store_pii_collection: boolean;
  vector_store_namespace_redacted: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AgentMemoryStorePosture {
  agent_memory_store_fields: string[];
  agent_memory_store_provider?: string;
  agent_memory_store_remote: boolean;
  agent_memory_store_destination_redacted: boolean;
  agent_memory_store_destination_count: number;
  agent_memory_store_destination_kinds: string[];
  agent_memory_store_persistent: boolean;
  agent_memory_store_shared: boolean;
  agent_memory_store_write_enabled: boolean;
  agent_memory_store_sync_enabled: boolean;
  agent_memory_store_untrusted_write: boolean;
  agent_memory_store_tool_output_capture: boolean;
  agent_memory_store_prompt_capture: boolean;
  agent_memory_store_retrieval_capture: boolean;
  agent_memory_store_secret_capture: boolean;
  agent_memory_store_output_replay_enabled: boolean;
  agent_memory_store_sensitive_data: boolean;
  agent_memory_store_pii_data: boolean;
  agent_memory_store_namespace_redacted: boolean;
  agent_memory_store_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface DatabaseConnectorPosture {
  database_fields: string[];
  database_provider?: string;
  database_remote: boolean;
  database_destination_redacted: boolean;
  database_remote_destination_count: number;
  database_remote_destination_kinds: string[];
  database_read_enabled: boolean;
  database_write_enabled: boolean;
  database_delete_enabled: boolean;
  database_query_execution_enabled: boolean;
  database_untrusted_query_input: boolean;
  database_sensitive_data: boolean;
  database_pii_data: boolean;
  database_table_names_redacted: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface BrowserSessionPosture {
  browser_fields: string[];
  browser_provider?: string;
  browser_persistent_profile: boolean;
  browser_cookie_storage: boolean;
  browser_session_storage: boolean;
  browser_authenticated_session: boolean;
  browser_remote_debugging: boolean;
  browser_untrusted_navigation: boolean;
  browser_click_or_form_authority: boolean;
  browser_download_upload_enabled: boolean;
  browser_network_remote: boolean;
  browser_broad_origin_access: boolean;
  browser_destination_redacted: boolean;
  browser_destination_count: number;
  browser_destination_kinds: string[];
  browser_path_references_redacted: boolean;
  browser_sensitive_data: boolean;
  browser_pii_data: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface InboundAgentTriggerPosture {
  inbound_trigger_fields: string[];
  inbound_trigger_provider?: string;
  inbound_trigger_external_source: boolean;
  inbound_trigger_source_redacted: boolean;
  inbound_trigger_source_count: number;
  inbound_trigger_source_categories: string[];
  inbound_trigger_payload_redacted: boolean;
  inbound_trigger_payload_categories: string[];
  inbound_trigger_invokes_agent: boolean;
  inbound_trigger_invokes_tools: boolean;
  inbound_trigger_tool_authority_categories: string[];
  inbound_trigger_write_authority: boolean;
  inbound_trigger_external_response: boolean;
  inbound_trigger_memory_write: boolean;
  inbound_trigger_sensitive_context: boolean;
  inbound_trigger_pii_context: boolean;
  inbound_trigger_attachment_context: boolean;
  inbound_trigger_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AgentOrchestrationPosture {
  agent_orchestration_fields: string[];
  agent_orchestration_framework?: string;
  agent_orchestration_multi_agent: boolean;
  agent_orchestration_agent_count: number;
  agent_orchestration_agent_names_redacted: boolean;
  agent_orchestration_delegation_enabled: boolean;
  agent_orchestration_delegation_categories: string[];
  agent_orchestration_untrusted_input: boolean;
  agent_orchestration_shared_memory: boolean;
  agent_orchestration_memory_redacted: boolean;
  agent_orchestration_invokes_tools: boolean;
  agent_orchestration_tool_authority_categories: string[];
  agent_orchestration_privileged_agent: boolean;
  agent_orchestration_write_authority: boolean;
  agent_orchestration_external_authority: boolean;
  agent_orchestration_secret_authority: boolean;
  agent_orchestration_sensitive_data: boolean;
  agent_orchestration_pii_data: boolean;
  agent_orchestration_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AgentSafetyPosture {
  agent_safety_fields: string[];
  agent_safety_framework?: string;
  agent_safety_controls_declared: boolean;
  agent_safety_controls_disabled: boolean;
  agent_safety_disabled_controls: string[];
  agent_safety_prompt_injection_filter_disabled: boolean;
  agent_safety_output_validation_disabled: boolean;
  agent_safety_tool_result_sanitization_disabled: boolean;
  agent_safety_content_moderation_disabled: boolean;
  agent_safety_pii_redaction_disabled: boolean;
  agent_safety_secret_redaction_disabled: boolean;
  agent_safety_untrusted_input: boolean;
  agent_safety_privileged_tool_authority: boolean;
  agent_safety_tool_authority_categories: string[];
  agent_safety_write_authority: boolean;
  agent_safety_external_authority: boolean;
  agent_safety_memory_write_authority: boolean;
  agent_safety_secret_exposure: boolean;
  agent_safety_sensitive_data: boolean;
  agent_safety_pii_data: boolean;
  agent_safety_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AgentIdentityPosture {
  agent_identity_fields: string[];
  agent_identity_provider?: string;
  agent_identity_remote: boolean;
  agent_identity_destination_redacted: boolean;
  agent_identity_destination_count: number;
  agent_identity_destination_kinds: string[];
  agent_identity_issuer_redacted: boolean;
  agent_identity_subject_redacted: boolean;
  agent_identity_scope_redacted: boolean;
  agent_identity_scope_categories: string[];
  agent_identity_broad_scope: boolean;
  agent_identity_admin_scope: boolean;
  agent_identity_write_scope: boolean;
  agent_identity_credential_issuance_enabled: boolean;
  agent_identity_impersonation_enabled: boolean;
  agent_identity_token_refresh_enabled: boolean;
  agent_identity_tool_injection: boolean;
  agent_identity_external_authority: boolean;
  agent_identity_untrusted_input: boolean;
  agent_identity_sensitive_data: boolean;
  agent_identity_pii_data: boolean;
  agent_identity_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AgentExtensionLoaderPosture {
  agent_extension_loader_fields: string[];
  agent_extension_loader_provider?: string;
  agent_extension_loader_remote: boolean;
  agent_extension_loader_destination_redacted: boolean;
  agent_extension_loader_destination_count: number;
  agent_extension_loader_destination_kinds: string[];
  agent_extension_loader_extension_refs_redacted: boolean;
  agent_extension_loader_extension_ref_count: number;
  agent_extension_loader_extension_kinds: string[];
  agent_extension_loader_unpinned_reference: boolean;
  agent_extension_loader_auto_install_enabled: boolean;
  agent_extension_loader_auto_update_enabled: boolean;
  agent_extension_loader_signature_verification_disabled: boolean;
  agent_extension_loader_provenance_verification_missing: boolean;
  agent_extension_loader_untrusted_input: boolean;
  agent_extension_loader_tool_authority_categories: string[];
  agent_extension_loader_privileged_authority: boolean;
  agent_extension_loader_external_authority: boolean;
  agent_extension_loader_sensitive_data: boolean;
  agent_extension_loader_pii_data: boolean;
  agent_extension_loader_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AgentSelfModificationPosture {
  agent_self_modification_fields: string[];
  agent_self_modification_target_redacted: boolean;
  agent_self_modification_target_count: number;
  agent_self_modification_target_categories: string[];
  agent_self_modification_instruction_target: boolean;
  agent_self_modification_prompt_target: boolean;
  agent_self_modification_policy_target: boolean;
  agent_self_modification_tool_target: boolean;
  agent_self_modification_runtime_target: boolean;
  agent_self_modification_memory_target: boolean;
  agent_self_modification_workflow_target: boolean;
  agent_self_modification_write_enabled: boolean;
  agent_self_modification_auto_apply: boolean;
  agent_self_modification_persistent_change: boolean;
  agent_self_modification_executes_after_update: boolean;
  agent_self_modification_rollback_enabled: boolean;
  agent_self_modification_untrusted_input: boolean;
  agent_self_modification_authority_categories: string[];
  agent_self_modification_external_authority: boolean;
  agent_self_modification_sensitive_data: boolean;
  agent_self_modification_pii_data: boolean;
  agent_self_modification_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AgentApprovalGatePosture {
  agent_approval_fields: string[];
  agent_approval_prompt_redacted: boolean;
  agent_approval_prompt_source_categories: string[];
  agent_approval_context_untrusted: boolean;
  agent_approval_decision_model_driven: boolean;
  agent_approval_uses_untrusted_summary: boolean;
  agent_approval_human_required: boolean;
  agent_approval_default_allow: boolean;
  agent_approval_auto_execute_after_approval: boolean;
  agent_approval_action_categories: string[];
  agent_approval_privileged_actions: boolean;
  agent_approval_write_actions: boolean;
  agent_approval_destructive_actions: boolean;
  agent_approval_external_actions: boolean;
  agent_approval_memory_write: boolean;
  agent_approval_secret_access: boolean;
  agent_approval_sensitive_data: boolean;
  agent_approval_pii_data: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AgentContextComposerPosture {
  agent_context_composer_fields: string[];
  agent_context_composer_source_redacted: boolean;
  agent_context_composer_source_categories: string[];
  agent_context_composer_untrusted_sources: boolean;
  agent_context_composer_privileged_role_injection: boolean;
  agent_context_composer_system_role: boolean;
  agent_context_composer_developer_role: boolean;
  agent_context_composer_role_boundary_redacted: boolean;
  agent_context_composer_delimiter_disabled: boolean;
  agent_context_composer_sanitization_disabled: boolean;
  agent_context_composer_raw_context_enabled: boolean;
  agent_context_composer_tool_authority_categories: string[];
  agent_context_composer_privileged_tool_authority: boolean;
  agent_context_composer_write_authority: boolean;
  agent_context_composer_external_authority: boolean;
  agent_context_composer_memory_write: boolean;
  agent_context_composer_shell_authority: boolean;
  agent_context_composer_destructive_authority: boolean;
  agent_context_composer_secret_access: boolean;
  agent_context_composer_sensitive_data: boolean;
  agent_context_composer_pii_data: boolean;
  agent_context_composer_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface SaasConnectorPosture {
  saas_connector_fields: string[];
  saas_connector_provider?: string;
  saas_connector_external_reach: boolean;
  saas_connector_destination_redacted: boolean;
  saas_connector_destination_count: number;
  saas_connector_destination_kinds: string[];
  saas_connector_scope_redacted: boolean;
  saas_connector_scope_categories: string[];
  saas_connector_broad_scope: boolean;
  saas_connector_admin_scope: boolean;
  saas_connector_read_enabled: boolean;
  saas_connector_external_write_enabled: boolean;
  saas_connector_untrusted_input: boolean;
  saas_connector_sensitive_data: boolean;
  saas_connector_pii_data: boolean;
  saas_connector_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface SecretManagerPosture {
  secret_manager_fields: string[];
  secret_manager_provider?: string;
  secret_manager_remote: boolean;
  secret_manager_destination_redacted: boolean;
  secret_manager_destination_count: number;
  secret_manager_destination_kinds: string[];
  secret_manager_scope_redacted: boolean;
  secret_manager_scope_categories: string[];
  secret_manager_path_references_redacted: boolean;
  secret_manager_read_enabled: boolean;
  secret_manager_list_enabled: boolean;
  secret_manager_write_enabled: boolean;
  secret_manager_broad_scope: boolean;
  secret_manager_injects_into_tools: boolean;
  secret_manager_untrusted_input: boolean;
  secret_manager_sensitive_scope: boolean;
  secret_manager_pii_scope: boolean;
  secret_manager_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AiTelemetryPosture {
  ai_telemetry_fields: string[];
  ai_telemetry_provider?: string;
  ai_telemetry_export_enabled: boolean;
  ai_telemetry_remote_export: boolean;
  ai_telemetry_destination_redacted: boolean;
  ai_telemetry_remote_destination_count: number;
  ai_telemetry_remote_destination_kinds: string[];
  ai_telemetry_captures_prompts: boolean;
  ai_telemetry_captures_completions: boolean;
  ai_telemetry_captures_tool_outputs: boolean;
  ai_telemetry_captures_retrieval: boolean;
  ai_telemetry_captures_memory: boolean;
  ai_telemetry_sensitive_capture: boolean;
  ai_telemetry_pii_capture: boolean;
  ai_telemetry_secret_capture_signal: boolean;
  ai_telemetry_redaction_disabled: boolean;
  ai_telemetry_retention_enabled: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AiEvalHarnessPosture {
  ai_eval_fields: string[];
  ai_eval_framework?: string;
  ai_eval_live_execution: boolean;
  ai_eval_adversarial_cases: boolean;
  ai_eval_untrusted_prompts: boolean;
  ai_eval_dataset_redacted: boolean;
  ai_eval_dataset_count: number;
  ai_eval_invokes_agent: boolean;
  ai_eval_invokes_tools: boolean;
  ai_eval_tool_authority_categories: string[];
  ai_eval_write_authority: boolean;
  ai_eval_external_write_authority: boolean;
  ai_eval_remote_target: boolean;
  ai_eval_production_target: boolean;
  ai_eval_records_outputs: boolean;
  ai_eval_sensitive_data: boolean;
  ai_eval_pii_data: boolean;
  ai_eval_secret_exposure: boolean;
  ai_eval_approval_required: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface AiModelEndpointPosture {
  ai_model_fields: string[];
  ai_model_provider?: string;
  ai_model_remote_endpoint: boolean;
  ai_model_custom_endpoint: boolean;
  ai_model_destination_redacted: boolean;
  ai_model_remote_destination_count: number;
  ai_model_remote_destination_kinds: string[];
  ai_model_plaintext_endpoint: boolean;
  ai_model_encrypted_endpoint: boolean;
  ai_model_sends_prompts: boolean;
  ai_model_sends_tool_outputs: boolean;
  ai_model_sends_retrieval_context: boolean;
  ai_model_sends_memory: boolean;
  ai_model_sensitive_context: boolean;
  ai_model_pii_context: boolean;
  env_key_names: string[];
  secret_ref_key_names: string[];
}

interface CursorRuleClassification {
  analyzedContent: string;
  metadata: Record<string, unknown>;
}

function classifyDatabaseConnectorConfig(value: unknown, filePath: string): DatabaseConnectorPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferDatabaseProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const remote = classifyDatabaseRemote(fields, provider);
  const envKeys = extractEnvironmentReferenceKeys(stringValues);
  const secretRefKeys = extractDatabaseSecretReferenceKeys(fields);

  return {
    database_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isDatabaseSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    database_provider: provider,
    database_remote: remote.remote,
    database_destination_redacted: remote.destinationCount > 0,
    database_remote_destination_count: remote.destinationCount,
    database_remote_destination_kinds: remote.destinationKinds,
    database_read_enabled: hasDatabaseReadSignal(fields),
    database_write_enabled: hasDatabaseWriteSignal(fields),
    database_delete_enabled: hasDatabaseDeleteSignal(fields),
    database_query_execution_enabled: hasDatabaseQueryExecutionSignal(fields),
    database_untrusted_query_input: hasDatabaseUntrustedQueryInputSignal(fields),
    database_sensitive_data: hasDatabaseSensitiveDataSignal(fields),
    database_pii_data: hasDatabasePiiDataSignal(fields),
    database_table_names_redacted: hasDatabaseTableNameSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferDatabaseProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["postgres", /\b(postgres|postgresql|pgvector)\b/iu],
    ["mysql", /\b(mysql|mariadb)\b/iu],
    ["mssql", /\b(mssql|sql\s*server|sqlserver)\b/iu],
    ["sqlite", /\bsqlite\b/iu],
    ["snowflake", /\bsnowflake\b/iu],
    ["bigquery", /\bbigquery\b/iu],
    ["redshift", /\bredshift\b/iu],
    ["databricks", /\bdatabricks\b/iu],
    ["supabase", /\bsupabase\b/iu],
    ["neon", /\bneon\b/iu],
    ["planetscale", /\bplanetscale\b/iu],
    ["clickhouse", /\bclickhouse\b/iu],
    ["oracle", /\boracle\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifyDatabaseRemote(
  fields: RuntimeField[],
  provider: string | undefined
): { remote: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  const managedProviders = new Set(["snowflake", "bigquery", "redshift", "databricks", "supabase", "neon", "planetscale"]);
  if (provider && managedProviders.has(provider)) {
    destinationKinds.add("managed_database");
    destinationCount += 1;
  }

  for (const field of fields) {
    const values = Array.isArray(field.value) ? field.value.map(String) : [String(field.value ?? "")];
    for (const value of values) {
      const destination = parseRemoteDatabaseDestination(value);
      if (destination) {
        destinationKinds.add(destination.kind);
        destinationCount += 1;
      }
    }
    if (/(^|\.)(host|hostname|server|endpoint|dsn|connection|connection_string|url|uri)$/iu.test(field.path)) {
      const text = values.join(" ");
      if (looksLikeRemoteDatabaseHost(text)) {
        destinationKinds.add("database_host");
        destinationCount += 1;
      }
    }
  }

  return {
    remote: destinationCount > 0,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b))
  };
}

function parseRemoteDatabaseDestination(value: string): { kind: string } | undefined {
  try {
    const parsed = new URL(value);
    const protocol = parsed.protocol.replace(":", "").toLowerCase();
    if (!/^(postgres|postgresql|mysql|mariadb|mssql|sqlserver|snowflake|redshift|clickhouse|oracle|jdbc)$/iu.test(protocol)) {
      return undefined;
    }
    if (isLocalHost(parsed.hostname.toLowerCase())) return undefined;
    return { kind: "connection_string" };
  } catch {
    return undefined;
  }
}

function looksLikeRemoteDatabaseHost(value: string): boolean {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || trimmed.startsWith("${")) return false;
  if (isLocalHost(trimmed)) return false;
  return /\b(rds\.amazonaws\.com|database\.windows\.net|cloudsql|snowflakecomputing\.com|bigquery|redshift|databricks|supabase|neon\.tech|planetscale|db\.|database|warehouse)\b/iu.test(
    trimmed
  ) || /^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?$/iu.test(trimmed);
}

function hasDatabaseReadSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(select|read|readonly|read_only|read-only|query|queries)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasDatabaseWriteSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(write|read_write|read-write|insert|update|upsert|merge|mutate|create|alter|drop|truncate|delete|ddl|dml|writable)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasDatabaseDeleteSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(delete|drop|truncate|purge|destroy)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasDatabaseQueryExecutionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(sql|query|queries|execute[_\s-]?queries?|query[_\s-]?execution|natural[_\s-]?language[_\s-]?sql|text[_\s-]?to[_\s-]?sql|nl2sql|agent[_\s-]?queries?)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasDatabaseUntrustedQueryInputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|natural[_\s-]?language|retrieved|rag|document|chat|email|slack)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasDatabaseSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|order|record|case|profile|note)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasDatabasePiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasDatabaseTableNameSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /(^|\.)(tables?|schemas?|collections?|datasets?|views?)$/iu.test(field.path));
}

function isDatabaseSecurityField(fieldPath: string): boolean {
  return /provider|database|db|sql|query|host|hostname|server|endpoint|dsn|connection|url|uri|credential|secret|token|password|api[_-]?key|auth|env|user|role|permission|access|read|write|insert|update|delete|table|schema|dataset|view|source|input/iu.test(
    fieldPath
  );
}

function extractDatabaseSecretReferenceKeys(fields: RuntimeField[]): string[] {
  const keys = new Set(extractSecretReferenceKeys(collectFieldStringValues(fields)));
  for (const field of fields) {
    if (!/(^|\.)(connection[_-]?url|database[_-]?url|db[_-]?url|dsn|uri|url)$/iu.test(field.path)) continue;
    for (const key of extractEnvironmentReferenceKeys([fieldValueText(field)])) keys.add(key);
  }
  return [...keys].sort((a, b) => a.localeCompare(b));
}

function classifyBrowserSessionConfig(value: unknown, filePath: string): BrowserSessionPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferBrowserProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const destinations = classifyBrowserDestinations(fields);
  const envKeys = extractEnvironmentReferenceKeys(stringValues);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);
  const cookieStorage = hasBrowserCookieStorageSignal(fields);
  const sessionStorage = hasBrowserSessionStorageSignal(fields);
  const persistentProfile = hasBrowserPersistentProfileSignal(fields);
  const authenticatedSession = cookieStorage || sessionStorage || hasBrowserAuthenticationSignal(fields);

  return {
    browser_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isBrowserSessionSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    browser_provider: provider,
    browser_persistent_profile: persistentProfile,
    browser_cookie_storage: cookieStorage,
    browser_session_storage: sessionStorage,
    browser_authenticated_session: authenticatedSession,
    browser_remote_debugging: hasBrowserRemoteDebuggingSignal(fields),
    browser_untrusted_navigation: hasBrowserUntrustedNavigationSignal(fields),
    browser_click_or_form_authority: hasBrowserClickOrFormAuthoritySignal(fields),
    browser_download_upload_enabled: hasBrowserDownloadUploadSignal(fields),
    browser_network_remote: destinations.remote,
    browser_broad_origin_access: destinations.broadOrigin,
    browser_destination_redacted: destinations.destinationCount > 0,
    browser_destination_count: destinations.destinationCount,
    browser_destination_kinds: destinations.destinationKinds,
    browser_path_references_redacted: hasBrowserPathReferenceSignal(fields),
    browser_sensitive_data: hasBrowserSensitiveDataSignal(fields),
    browser_pii_data: hasBrowserPiiDataSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferBrowserProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["playwright", /\bplaywright\b/iu],
    ["puppeteer", /\bpuppeteer\b/iu],
    ["browser_use", /\bbrowser[-_\s]?use\b/iu],
    ["browserbase", /\bbrowserbase\b/iu],
    ["stagehand", /\bstagehand\b/iu],
    ["selenium", /\bselenium|webdriver\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifyBrowserDestinations(
  fields: RuntimeField[]
): { remote: boolean; broadOrigin: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  let broadOrigin = false;

  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/(^|\.)(allowed[_-]?origins?|allowed[_-]?hosts?|domains?|hosts?|urls?|scope|scopes|permissions?)$/iu.test(field.path)) {
      if (/(^|[\s,])\*(?=[$\s,])|\ball[_\s-]?(origins?|domains?|hosts?|urls?|sites?)\b/iu.test(text)) {
        broadOrigin = true;
        destinationKinds.add("wildcard_origin");
        destinationCount += 1;
      }
    }
    for (const value of browserFieldStringValues(field)) {
      const destination = parseRemoteBrowserDestination(value);
      if (destination) {
        destinationKinds.add(destination.kind);
        destinationCount += 1;
      }
    }
  }

  return {
    remote: destinationCount > 0 || broadOrigin,
    broadOrigin,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b))
  };
}

function parseRemoteBrowserDestination(value: string): { kind: string } | undefined {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:" && parsed.protocol !== "wss:" && parsed.protocol !== "ws:") {
      return undefined;
    }
    if (isLocalHost(parsed.hostname.toLowerCase())) return undefined;
    return { kind: parsed.protocol === "http:" || parsed.protocol === "ws:" ? "plaintext_browser_endpoint" : "browser_endpoint" };
  } catch {
    return undefined;
  }
}

function browserFieldStringValues(field: RuntimeField): string[] {
  if (Array.isArray(field.value)) return field.value.map(String);
  if (typeof field.value === "string") return [field.value];
  return [];
}

function hasBrowserPersistentProfileSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(persistent|persist|user[_-]?data[_-]?dir|profile|profile[_-]?dir|browser[_-]?profile|keep[_-]?session|reuse[_-]?session|storage[_-]?state)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasBrowserCookieStorageSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(cookie|cookies|cookie[_-]?jar|cookie[_-]?store)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasBrowserSessionStorageSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(storage[_-]?state|session[_-]?storage|local[_-]?storage|auth[_-]?state|authenticated[_-]?state)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasBrowserAuthenticationSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(auth|authenticated|login|session|bearer|cookie|token|credential|password|sso|oauth)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasBrowserRemoteDebuggingSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(remote[_-]?debugging|debug[_-]?port|cdp|devtools|browser[_-]?ws|websocket[_-]?endpoint)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasBrowserUntrustedNavigationSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|browser[_-]?output|web[_-]?page|email|slack)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasBrowserClickOrFormAuthoritySignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(click|submit|fill|type|press|form|approve|confirm|checkout|purchase|post|send|save|update|delete|navigate|goto|visit)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasBrowserDownloadUploadSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(upload|download|attach|screenshot|file[_-]?chooser|save[_-]?as)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasBrowserPathReferenceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(user[_-]?data[_-]?dir|profile|profile[_-]?dir|storage[_-]?state|cookie[_-]?jar|cookies?|download[_-]?path|upload[_-]?path|auth[_-]?state|path|file)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasBrowserSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|order|record|case|profile|note)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasBrowserPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function isBrowserSessionSecurityField(fieldPath: string): boolean {
  return /provider|browser|playwright|puppeteer|selenium|profile|user[_-]?data|storage|session|cookie|auth|token|credential|password|origin|domain|host|url|debug|cdp|devtools|navigation|action|click|form|submit|upload|download|source|input|data|scope|permission|approval/iu.test(
    fieldPath
  );
}

function classifyInboundAgentTriggerConfig(value: unknown, filePath: string): InboundAgentTriggerPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferInboundTriggerProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const sourceCategories = collectInboundTriggerSourceCategories(fields, provider);
  const payloadCategories = collectInboundTriggerPayloadCategories(fields);
  const toolAuthorityCategories = collectInboundTriggerToolAuthorityCategories(fields);
  const envKeys = extractEnvironmentReferenceKeys(stringValues);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);

  return {
    inbound_trigger_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isInboundTriggerSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    inbound_trigger_provider: provider,
    inbound_trigger_external_source: sourceCategories.length > 0,
    inbound_trigger_source_redacted: sourceCategories.length > 0,
    inbound_trigger_source_count: sourceCategories.length,
    inbound_trigger_source_categories: sourceCategories,
    inbound_trigger_payload_redacted: payloadCategories.length > 0,
    inbound_trigger_payload_categories: payloadCategories,
    inbound_trigger_invokes_agent: hasInboundTriggerAgentInvocationSignal(fields),
    inbound_trigger_invokes_tools: toolAuthorityCategories.length > 0 || hasInboundTriggerToolInvocationSignal(fields),
    inbound_trigger_tool_authority_categories: toolAuthorityCategories,
    inbound_trigger_write_authority: hasInboundTriggerWriteAuthoritySignal(fields, toolAuthorityCategories),
    inbound_trigger_external_response: hasInboundTriggerExternalResponseSignal(fields, toolAuthorityCategories),
    inbound_trigger_memory_write: hasInboundTriggerMemoryWriteSignal(fields, toolAuthorityCategories),
    inbound_trigger_sensitive_context: hasInboundTriggerSensitiveContextSignal(fields),
    inbound_trigger_pii_context: hasInboundTriggerPiiContextSignal(fields),
    inbound_trigger_attachment_context: hasInboundTriggerAttachmentSignal(fields),
    inbound_trigger_approval_required: hasInboundTriggerApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferInboundTriggerProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["gmail", /\bgmail\b|googleapis\.com\/auth\/gmail/iu],
    ["outlook", /\boutlook\b|graph\.microsoft\.com|microsoft graph/iu],
    ["slack", /\bslack\b|slack\.com/iu],
    ["teams", /\bteams\b|microsoft teams/iu],
    ["jira", /\bjira\b|atlassian/iu],
    ["zendesk", /\bzendesk\b/iu],
    ["github", /\bgithub\b|api\.github\.com/iu],
    ["linear", /\blinear\b/iu],
    ["servicenow", /\bservice[-_\s]?now\b/iu],
    ["webhook", /\bwebhook\b|https?:\/\//iu],
    ["queue", /\b(queue|sqs|pubsub|kafka|rabbitmq|nats)\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function collectInboundTriggerSourceCategories(fields: RuntimeField[], provider: string | undefined): string[] {
  const categories = new Set<string>();
  if (provider) {
    if (["gmail", "outlook"].includes(provider)) categories.add("email_message");
    if (["slack", "teams"].includes(provider)) categories.add("chat_message");
    if (["jira", "zendesk", "linear", "servicenow"].includes(provider)) categories.add("ticket_comment");
    if (provider === "github") categories.add("issue_or_pr_comment");
    if (provider === "webhook") categories.add("webhook_payload");
    if (provider === "queue") categories.add("message_queue");
  }
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(email|mailbox|imap|smtp|gmail|outlook|message[_\s-]?body)\b/iu.test(text)) categories.add("email_message");
    if (/\b(slack|teams|discord|chat|channel|dm|direct[_\s-]?message)\b/iu.test(text)) categories.add("chat_message");
    if (/\b(ticket|jira|zendesk|linear|servicenow|support[_\s-]?case|case[_\s-]?comment)\b/iu.test(text)) {
      categories.add("ticket_comment");
    }
    if (/\b(github|gitlab|issue[_\s-]?comment|pull[_\s-]?request|pr[_\s-]?comment|review[_\s-]?comment)\b/iu.test(text)) {
      categories.add("issue_or_pr_comment");
    }
    if (/\b(webhook|http[_\s-]?event|callback|receiver|listener)\b/iu.test(text) || fieldStringValues(field).some(parseRemoteHttpUrl)) {
      categories.add("webhook_payload");
    }
    if (/\b(queue|sqs|pubsub|kafka|rabbitmq|nats|topic|subscription)\b/iu.test(text)) categories.add("message_queue");
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function fieldStringValues(field: RuntimeField): string[] {
  if (Array.isArray(field.value)) return field.value.map(String);
  if (typeof field.value === "string") return [field.value];
  return [];
}

function collectInboundTriggerPayloadCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(body|text|message|content|prompt|comment|description|summary|transcript)\b/iu.test(text)) categories.add("message_body");
    if (/\b(subject|title|headline)\b/iu.test(text)) categories.add("message_title");
    if (/\b(sender|from|author|user|customer|client|requester)\b/iu.test(text)) categories.add("sender_identity");
    if (/\b(headers?|metadata|properties)\b/iu.test(text)) categories.add("message_metadata");
    if (/(?:^|[_\W])(attachment|attachments|file|files|upload|document|image|pdf|csv)(?:[_\W]|$)/iu.test(text)) {
      categories.add("attachment");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function collectInboundTriggerToolAuthorityCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(tool|tools|mcp|function|function_call|call_tools|invoke_tools)\b/iu.test(text)) categories.add("tool_call");
    if (/\b(browser|playwright|puppeteer|web[_\s-]?agent|click|form|navigate)\b/iu.test(text)) categories.add("browser_action");
    if (/\b(database|db|sql|query|support_db|warehouse)\b/iu.test(text)) categories.add("database_access");
    if (/(?:^|[_\W])(vault|secret|secrets|secret[_\s-]?manager|key[_\s-]?vault|credential)(?:[_\W]|$)/iu.test(text)) {
      categories.add("secret_manager_access");
    }
    if (/\b(reply|respond|send|email|message|slack|post|publish|comment|ticket[_\s-]?update)\b/iu.test(text)) {
      categories.add("external_response");
    }
    if (/(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state)(?:[_\W]|$)/iu.test(text)) categories.add("memory_write");
    if (/(?:^|[_\W])(write|update|create|delete|assign|close|escalate|merge|approve)(?:[_\W]|$)/iu.test(text)) {
      categories.add("state_write");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasInboundTriggerAgentInvocationSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(agent|assistant|bot|autogen|crew|langgraph|codex|claude|run[_\s-]?agent|invoke[_\s-]?agent|triage[_\s-]?agent)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasInboundTriggerToolInvocationSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(call[_\s-]?tools?|invoke[_\s-]?tools?|tool[_\s-]?access|mcp|function[_\s-]?call|browser|database|vault|secret[_\s-]?manager)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasInboundTriggerWriteAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.some((category) => ["database_access", "external_response", "memory_write", "state_write"].includes(category)) ||
    fields.some((field) =>
      /\b(write|update|create|delete|reply|respond|send|post|publish|comment|close|assign|escalate|remember|persist)\b/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasInboundTriggerExternalResponseSignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("external_response") ||
    fields.some((field) => /\b(reply|respond|send|post|publish|comment|email|slack|message|webhook)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasInboundTriggerMemoryWriteSignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("memory_write") ||
    fields.some((field) =>
      /(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state|transcript)(?:[_\W]|$)/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasInboundTriggerSensitiveContextSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|order|record|case|profile|note|incident)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasInboundTriggerPiiContextSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasInboundTriggerAttachmentSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(attachment|attachments|file|files|upload|document|image|pdf|csv|spreadsheet)\b/iu.test(`${field.path} ${fieldValueText(field)}`)
  );
}

function hasInboundTriggerApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|moderation|review/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isInboundTriggerSecurityField(fieldPath: string): boolean {
  return /provider|source|input|event|trigger|webhook|listener|receiver|mail|email|message|chat|ticket|issue|comment|payload|body|attachment|agent|assistant|bot|tool|mcp|browser|database|secret|memory|reply|respond|send|write|post|publish|approval|auth|token|credential|scope|permission|url|host|endpoint|queue|topic|subscription/iu.test(
    fieldPath
  );
}

function classifyAgentOrchestrationConfig(value: unknown, filePath: string): AgentOrchestrationPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const framework = inferAgentOrchestrationFramework([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const agentCount = countConfiguredAgents(value, fields);
  const delegationCategories = collectAgentOrchestrationDelegationCategories(fields);
  const toolAuthorityCategories = collectAgentOrchestrationToolAuthorityCategories(fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);

  return {
    agent_orchestration_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAgentOrchestrationSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    agent_orchestration_framework: framework,
    agent_orchestration_multi_agent: agentCount >= 2 || hasMultiAgentSignal(fields),
    agent_orchestration_agent_count: agentCount,
    agent_orchestration_agent_names_redacted: agentCount > 0 || hasAgentNameSignal(fields),
    agent_orchestration_delegation_enabled: delegationCategories.length > 0,
    agent_orchestration_delegation_categories: delegationCategories,
    agent_orchestration_untrusted_input: hasAgentOrchestrationUntrustedInputSignal(fields),
    agent_orchestration_shared_memory: hasAgentOrchestrationSharedMemorySignal(fields),
    agent_orchestration_memory_redacted: hasAgentOrchestrationMemoryReferenceSignal(fields),
    agent_orchestration_invokes_tools: toolAuthorityCategories.length > 0 || hasAgentOrchestrationToolSignal(fields),
    agent_orchestration_tool_authority_categories: toolAuthorityCategories,
    agent_orchestration_privileged_agent: isAgentOrchestrationPrivileged(toolAuthorityCategories),
    agent_orchestration_write_authority: hasAgentOrchestrationWriteAuthoritySignal(fields, toolAuthorityCategories),
    agent_orchestration_external_authority: hasAgentOrchestrationExternalAuthoritySignal(fields, toolAuthorityCategories),
    agent_orchestration_secret_authority: toolAuthorityCategories.includes("secret_manager_access") || hasAgentOrchestrationSecretSignal(fields),
    agent_orchestration_sensitive_data: hasAgentOrchestrationSensitiveDataSignal(fields),
    agent_orchestration_pii_data: hasAgentOrchestrationPiiDataSignal(fields),
    agent_orchestration_approval_required: hasAgentOrchestrationApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferAgentOrchestrationFramework(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const frameworks: Array<[string, RegExp]> = [
    ["crewai", /\b(crewai|crew ai|crew)\b/iu],
    ["autogen", /\b(autogen|auto gen|autogenstudio)\b/iu],
    ["langgraph", /\blanggraph\b/iu],
    ["semantic_kernel", /\b(semantic[-_\s]?kernel|sk[-_\s]?agent)\b/iu],
    ["openai_swarm", /\bswarm\b/iu],
    ["langchain_agents", /\b(langchain|agentexecutor|agent executor)\b/iu]
  ];
  return frameworks.find(([, pattern]) => pattern.test(text))?.[0];
}

function countConfiguredAgents(value: unknown, fields: RuntimeField[]): number {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    for (const key of ["agents", "workers", "subagents", "team", "crew", "roles", "nodes"]) {
      const candidate = record[key];
      if (Array.isArray(candidate)) return candidate.length;
      if (candidate && typeof candidate === "object") return Object.keys(candidate as Record<string, unknown>).length;
    }
  }

  const pathPrefixes = new Set<string>();
  for (const field of fields) {
    const match = field.path.match(/(?:^|\.)(agents?|workers?|subagents?|team|crew|roles?|nodes?)\.(\d+|[A-Za-z][\w-]*)/u);
    if (match?.[1] && match[2]) pathPrefixes.add(`${match[1]}.${match[2]}`);
  }
  return pathPrefixes.size;
}

function hasMultiAgentSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(multi[-_\s]?agent|crew|team|subagent|worker|supervisor|manager|router|orchestrator)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentNameSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /(?:^|\.)(agents?|workers?|subagents?|team|crew|roles?|nodes?)\.[^.]+\.name$/iu.test(field.path));
}

function collectAgentOrchestrationDelegationCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(delegate|delegation|can[_\s-]?delegate|handoff|hand[-_\s]?off|transfer)\b/iu.test(text)) categories.add("agent_delegation");
    if (/\b(supervisor|manager|router|planner|coordinator|orchestrator)\b/iu.test(text)) categories.add("supervisor_routing");
    if (/\b(peer|worker|subagent|specialist|role)\b/iu.test(text)) categories.add("peer_handoff");
    if (/\b(auto|automatic|without[_\s-]?approval|no[_\s-]?approval|autonomous)\b/iu.test(text)) categories.add("automatic_delegation");
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasAgentOrchestrationUntrustedInputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|chat|inbound|web[_-]?page|external)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentOrchestrationSharedMemorySignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(shared[_\s-]?memory|memory[_\s-]?shared|team[_\s-]?memory|crew[_\s-]?memory|cross[-_\s]?agent|global[_\s-]?memory|persistent[_\s-]?memory)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) || (/memory/iu.test(field.path) && truthyConfigValue(field.value))
  );
}

function hasAgentOrchestrationMemoryReferenceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(memory|vector|state|scratchpad|transcript|summary|session|history|store|namespace)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function collectAgentOrchestrationToolAuthorityCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(tool|tools|function|mcp|connector|capability)\b/iu.test(text)) categories.add("tool_call");
    if (/\b(browser|playwright|puppeteer|web[_\s-]?agent|click|form|navigate)\b/iu.test(text)) categories.add("browser_action");
    if (/\b(database|db|sql|query|support_db|warehouse)\b/iu.test(text)) categories.add("database_access");
    if (/(?:^|[_\W])(vault|secret|secrets|secret[_\s-]?manager|key[_\s-]?vault|credential)(?:[_\W]|$)/iu.test(text)) {
      categories.add("secret_manager_access");
    }
    if (/\b(slack|email|webhook|message|ticket|issue|comment|reply|send|post|publish)\b/iu.test(text)) categories.add("external_response");
    if (/(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state)(?:[_\W]|$)/iu.test(text)) categories.add("memory_write");
    if (/\b(shell|bash|command|exec|terminal|python|node|subprocess)\b/iu.test(text)) categories.add("shell_execution");
    if (/\b(filesystem|file[_\s-]?write|workspace|repo|repository|github|gitlab|pull[_\s-]?request)\b/iu.test(text)) {
      categories.add("repo_or_filesystem_write");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasAgentOrchestrationToolSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(call[_\s-]?tools?|invoke[_\s-]?tools?|tool[_\s-]?access|mcp|function[_\s-]?call|browser|database|vault|shell)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function isAgentOrchestrationPrivileged(categories: string[]): boolean {
  return categories.some((category) =>
    [
      "browser_action",
      "database_access",
      "external_response",
      "repo_or_filesystem_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ].includes(category)
  );
}

function hasAgentOrchestrationWriteAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.some((category) => ["database_access", "external_response", "repo_or_filesystem_write", "shell_execution"].includes(category)) ||
    fields.some((field) =>
      /\b(write|update|create|delete|reply|respond|send|post|publish|comment|commit|push|merge|deploy|remember|persist)\b/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasAgentOrchestrationExternalAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("external_response") ||
    fields.some((field) => /\b(slack|email|webhook|send|post|publish|reply|respond|ticket|issue|external)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasAgentOrchestrationSecretSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(secret|token|credential|api[_-]?key|password|vault|key[_\s-]?vault)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasAgentOrchestrationSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|order|record|case|profile|note|incident)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentOrchestrationPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentOrchestrationApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|review|human[_-]?in[_-]?the[_-]?loop/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isAgentOrchestrationSecurityField(fieldPath: string): boolean {
  return /framework|provider|agent|agents|subagent|crew|team|worker|role|task|graph|node|edge|handoff|delegate|delegation|supervisor|manager|router|tool|mcp|browser|database|secret|memory|input|source|customer|ticket|email|chat|write|send|reply|approval|auth|token|credential|env|scope|permission|state|vector|namespace/iu.test(
    fieldPath
  );
}

function classifyAgentSafetyConfig(value: unknown, filePath: string): AgentSafetyPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const framework = inferAgentSafetyFramework([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const disabledControls = collectAgentSafetyDisabledControls(fields);
  const toolAuthorityCategories = collectAgentSafetyToolAuthorityCategories(fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);

  return {
    agent_safety_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAgentSafetySecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    agent_safety_framework: framework,
    agent_safety_controls_declared: disabledControls.length > 0 || hasAgentSafetyControlSignal(fields),
    agent_safety_controls_disabled: disabledControls.length > 0,
    agent_safety_disabled_controls: disabledControls,
    agent_safety_prompt_injection_filter_disabled: disabledControls.includes("prompt_injection_filter"),
    agent_safety_output_validation_disabled: disabledControls.includes("output_validation"),
    agent_safety_tool_result_sanitization_disabled: disabledControls.includes("tool_result_sanitization"),
    agent_safety_content_moderation_disabled: disabledControls.includes("content_moderation"),
    agent_safety_pii_redaction_disabled: disabledControls.includes("pii_redaction"),
    agent_safety_secret_redaction_disabled: disabledControls.includes("secret_redaction"),
    agent_safety_untrusted_input: hasAgentSafetyUntrustedInputSignal(fields),
    agent_safety_privileged_tool_authority: isAgentSafetyPrivileged(toolAuthorityCategories) || hasAgentSafetyToolAuthoritySignal(fields),
    agent_safety_tool_authority_categories: toolAuthorityCategories,
    agent_safety_write_authority: hasAgentSafetyWriteAuthoritySignal(fields, toolAuthorityCategories),
    agent_safety_external_authority: hasAgentSafetyExternalAuthoritySignal(fields, toolAuthorityCategories),
    agent_safety_memory_write_authority: hasAgentSafetyMemoryWriteSignal(fields, toolAuthorityCategories),
    agent_safety_secret_exposure:
      toolAuthorityCategories.includes("secret_manager_access") ||
      hasAgentSafetySecretSignal(fields) ||
      envKeys.some(isCredentialLikeKeyName) ||
      secretRefKeys.length > 0,
    agent_safety_sensitive_data: hasAgentSafetySensitiveDataSignal(fields),
    agent_safety_pii_data: hasAgentSafetyPiiDataSignal(fields),
    agent_safety_approval_required: hasAgentSafetyApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferAgentSafetyFramework(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const frameworks: Array<[string, RegExp]> = [
    ["nemo_guardrails", /\b(nemo[-_\s]?guardrails?|guardrails?\.ai)\b/iu],
    ["langchain", /\blangchain\b/iu],
    ["llamaindex", /\b(llama[-_\s]?index|llamaindex)\b/iu],
    ["openai", /\bopenai\b/iu],
    ["anthropic", /\banthropic\b/iu],
    ["pydantic_ai", /\bpydantic[-_\s]?ai\b/iu]
  ];
  return frameworks.find(([, pattern]) => pattern.test(text))?.[0];
}

function collectAgentSafetyDisabledControls(fields: RuntimeField[]): string[] {
  const controls = new Set<string>();
  for (const field of fields) {
    if (isAgentSafetyGlobalDisabledSignal(field)) controls.add("all_controls");
    if (isAgentSafetyControlDisabled(field, /prompt[_\s-]?injection|injection[_\s-]?filter|jailbreak|instruction[_\s-]?override/iu)) {
      controls.add("prompt_injection_filter");
    }
    if (isAgentSafetyControlDisabled(field, /output[_\s-]?validation|response[_\s-]?validation|schema[_\s-]?validation|validator/iu)) {
      controls.add("output_validation");
    }
    if (isAgentSafetyControlDisabled(field, /tool[_\s-]?(result|output|response)|function[_\s-]?(result|output|response)|observation|sanitize|sanitiz/iu)) {
      controls.add("tool_result_sanitization");
    }
    if (isAgentSafetyControlDisabled(field, /content[_\s-]?moderation|moderation|harm[_\s-]?filter|unsafe[_\s-]?content|content[_\s-]?filter/iu)) {
      controls.add("content_moderation");
    }
    if (isAgentSafetyControlDisabled(field, /pii|personal[_\s-]?data|email|phone|ssn|privacy|redact|mask/iu)) {
      controls.add("pii_redaction");
    }
    if (isAgentSafetyControlDisabled(field, /secret|token|credential|api[_\s-]?key|password|redact|mask|scrub/iu)) {
      controls.add("secret_redaction");
    }
  }
  return [...controls].sort((a, b) => a.localeCompare(b));
}

function isAgentSafetyGlobalDisabledSignal(field: RuntimeField): boolean {
  const text = `${field.path} ${fieldValueText(field)}`;
  const mentionsSafety = /\b(guardrails?|safety|controls?|policy|policies|moderation|validation|filter|sanitiz|redaction)\b/iu.test(text);
  if (!mentionsSafety) return false;
  if (/(^|\.)(enabled|enforced|required|active)$/iu.test(field.path)) return disabledConfigValue(field.value);
  if (/\b(disabled|disable|bypass|skip|passthrough|allow_all|allow-all|raw|warn_only|warn-only|log_only|log-only|report_only|report-only|monitor_only|monitor-only)\b/iu.test(field.path)) {
    return truthyConfigValue(field.value);
  }
  return /\b(disabled|disable|bypass|skip|passthrough|allow_all|allow-all|raw|warn_only|warn-only|log_only|log-only|report_only|report-only|monitor_only|monitor-only)\b/iu.test(
    fieldValueText(field)
  );
}

function isAgentSafetyControlDisabled(field: RuntimeField, controlPattern: RegExp): boolean {
  const text = `${field.path} ${fieldValueText(field)}`;
  if (!controlPattern.test(text)) return false;
  if (/(^|\.)(enabled|enforced|required|active)$/iu.test(field.path)) return disabledConfigValue(field.value);
  if (/\b(disabled|disable|bypass|skip|passthrough|allow_all|allow-all|raw|warn_only|warn-only|log_only|log-only|report_only|report-only|monitor_only|monitor-only)\b/iu.test(field.path)) {
    return truthyConfigValue(field.value);
  }
  return disabledConfigValue(field.value);
}

function disabledConfigValue(value: unknown): boolean {
  if (typeof value === "boolean") return !value;
  if (typeof value === "number") return value === 0;
  if (typeof value === "string") {
    return /^(false|no|off|disabled|disable|none|raw|passthrough|bypass|skip|unchecked|allow_all|allow-all|warn_only|warn-only|log_only|log-only|report_only|report-only|monitor_only|monitor-only|0)$/iu.test(
      value.trim()
    );
  }
  return false;
}

function hasAgentSafetyControlSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(guardrails?|safety|moderation|prompt[_\s-]?injection|jailbreak|validation|validator|sanitize|sanitiz|redaction|mask|filter)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentSafetyUntrustedInputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|chat|inbound|web[_-]?page|browser[_-]?output|tool[_-]?output|external)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function collectAgentSafetyToolAuthorityCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(tool|tools|function|function_call|mcp|connector|capability)\b/iu.test(text)) categories.add("tool_call");
    if (/\b(browser|playwright|puppeteer|web[_\s-]?agent|click|form|navigate)\b/iu.test(text)) categories.add("browser_action");
    if (/\b(database|db|sql|query|support_db|warehouse)\b/iu.test(text)) categories.add("database_access");
    if (/(?:^|[_\W])(vault|secret|secrets|secret[_\s-]?manager|key[_\s-]?vault|credential)(?:[_\W]|$)/iu.test(text)) {
      categories.add("secret_manager_access");
    }
    if (/\b(slack|email|webhook|message|ticket|issue|comment|reply|send|post|publish)\b/iu.test(text)) categories.add("external_response");
    if (/(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state)(?:[_\W]|$)/iu.test(text)) categories.add("memory_write");
    if (/\b(shell|bash|command|exec|terminal|python|node|subprocess)\b/iu.test(text)) categories.add("shell_execution");
    if (/\b(filesystem|file[_\s-]?write|workspace|repo|repository|github|gitlab|pull[_\s-]?request)\b/iu.test(text)) {
      categories.add("repo_or_filesystem_write");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasAgentSafetyToolAuthoritySignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(call[_\s-]?tools?|invoke[_\s-]?tools?|tool[_\s-]?access|function[_\s-]?call|mcp|browser|database|vault|shell|filesystem|write[_\s-]?tool)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function isAgentSafetyPrivileged(categories: string[]): boolean {
  return categories.some((category) =>
    [
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ].includes(category)
  );
}

function hasAgentSafetyWriteAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.some((category) => ["database_access", "external_response", "repo_or_filesystem_write", "shell_execution"].includes(category)) ||
    fields.some((field) =>
      /\b(write|update|create|delete|reply|respond|send|post|publish|comment|commit|push|merge|deploy|remember|persist|approve|close|assign)\b/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasAgentSafetyExternalAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("external_response") ||
    fields.some((field) => /\b(slack|email|webhook|send|post|publish|reply|respond|ticket|issue|external)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasAgentSafetyMemoryWriteSignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("memory_write") ||
    fields.some((field) =>
      /(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state|long[_\s-]?term[_\s-]?memory)(?:[_\W]|$)/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasAgentSafetySecretSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(secret|token|credential|api[_-]?key|password|vault|key[_\s-]?vault)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasAgentSafetySensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|order|record|case|profile|note|incident)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentSafetyPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentSafetyApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|review|human[_-]?in[_-]?the[_-]?loop/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isAgentSafetySecurityField(fieldPath: string): boolean {
  return /framework|provider|guardrail|safety|policy|control|moderation|filter|injection|jailbreak|validation|validator|sanitize|sanitiz|redact|mask|secret|pii|tool|mcp|function|output|input|source|customer|ticket|email|browser|database|memory|write|send|publish|approval|auth|token|credential|env|permission|scope/iu.test(
    fieldPath
  );
}

function isLikelyEnvKeyName(value: string): boolean {
  return /^[A-Z][A-Z0-9_]{2,}$/u.test(value);
}

function classifyAgentIdentityConfig(value: unknown, filePath: string): AgentIdentityPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferAgentIdentityProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const destinations = classifyAgentIdentityDestinations(fields, provider);
  const scopeCategories = collectAgentIdentityScopeCategories(fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);

  return {
    agent_identity_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAgentIdentitySecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    agent_identity_provider: provider,
    agent_identity_remote: destinations.remote,
    agent_identity_destination_redacted: destinations.destinationCount > 0,
    agent_identity_destination_count: destinations.destinationCount,
    agent_identity_destination_kinds: destinations.destinationKinds,
    agent_identity_issuer_redacted: hasAgentIdentityIssuerSignal(fields),
    agent_identity_subject_redacted: hasAgentIdentitySubjectSignal(fields),
    agent_identity_scope_redacted: scopeCategories.length > 0,
    agent_identity_scope_categories: scopeCategories,
    agent_identity_broad_scope: isAgentIdentityBroadScope(scopeCategories),
    agent_identity_admin_scope: scopeCategories.some((scope) => scope === "admin_scope" || scope === "iam_admin" || scope === "wildcard_scope"),
    agent_identity_write_scope: scopeCategories.some((scope) =>
      ["cloud_write", "email_modify", "repo_write", "storage_write", "ticket_write", "workspace_write"].includes(scope)
    ),
    agent_identity_credential_issuance_enabled: hasAgentIdentityCredentialIssuanceSignal(fields),
    agent_identity_impersonation_enabled: hasAgentIdentityImpersonationSignal(fields),
    agent_identity_token_refresh_enabled: hasAgentIdentityTokenRefreshSignal(fields),
    agent_identity_tool_injection: hasAgentIdentityToolInjectionSignal(fields),
    agent_identity_external_authority: hasAgentIdentityExternalAuthoritySignal(fields, scopeCategories),
    agent_identity_untrusted_input: hasAgentIdentityUntrustedInputSignal(fields),
    agent_identity_sensitive_data: hasAgentIdentitySensitiveDataSignal(fields),
    agent_identity_pii_data: hasAgentIdentityPiiDataSignal(fields),
    agent_identity_approval_required: hasAgentIdentityApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferAgentIdentityProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["google_workload_identity", /\b(google[_\s-]?workload[_\s-]?identity|gcp[_\s-]?workload[_\s-]?identity|sts\.googleapis\.com|iamcredentials\.googleapis\.com)\b/iu],
    ["aws_sts", /\b(aws[_\s-]?sts|assume[_\s-]?role|web[_\s-]?identity|sts\.amazonaws\.com)\b/iu],
    ["azure_entra", /\b(azure[_\s-]?entra|azure[_\s-]?ad|microsoft[_\s-]?identity|login\.microsoftonline\.com)\b/iu],
    ["github_app", /\b(github[_\s-]?app|installation[_\s-]?token|github\.com\/login\/oauth|api\.github\.com\/app)\b/iu],
    ["oauth2", /\b(oauth2?|oidc|openid[_\s-]?connect|authorization[_\s-]?server|token[_\s-]?endpoint)\b/iu],
    ["service_account", /\b(service[_\s-]?account|impersonat|delegat|token[_\s-]?broker|credential[_\s-]?broker)\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifyAgentIdentityDestinations(
  fields: RuntimeField[],
  provider: string | undefined
): { remote: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  if (provider && provider !== "service_account") {
    destinationKinds.add("managed_identity_provider");
    destinationCount += 1;
  }

  for (const field of fields) {
    const values = fieldStringValues(field);
    for (const value of values) {
      const destination = parseAgentIdentityDestination(value);
      if (destination) {
        destinationKinds.add(destination.kind);
        destinationCount += 1;
      }
    }
    if (/(^|\.)(issuer|issuer_url|authority|authorization_server|token_endpoint|sts_endpoint|endpoint|url|uri|host|audience)$/iu.test(field.path)) {
      const text = values.join(" ");
      if (looksLikeRemoteIdentityHost(text)) {
        destinationKinds.add("identity_provider_endpoint");
        destinationCount += 1;
      }
    }
  }

  return {
    remote: destinationCount > 0,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b))
  };
}

function parseAgentIdentityDestination(value: string): { kind: string } | undefined {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
    if (isLocalHost(parsed.hostname.toLowerCase())) return undefined;
    return { kind: parsed.protocol === "http:" ? "plaintext_identity_endpoint" : "identity_provider_endpoint" };
  } catch {
    return undefined;
  }
}

function looksLikeRemoteIdentityHost(value: string): boolean {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || trimmed.startsWith("${")) return false;
  if (isLocalHost(trimmed)) return false;
  return /\b(sts|iam|oauth|oidc|login|auth|accounts|identity|token|entra|okta|auth0|googleapis|amazonaws|microsoftonline)\b/iu.test(trimmed) ||
    /^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?$/iu.test(trimmed);
}

function collectAgentIdentityScopeCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    if (!/(^|\.)(scopes?|oauth[_-]?scopes?|permissions?|roles?|claims?|capabilities|access|resources?|allowed[_-]?actions?)$/iu.test(field.path)) {
      continue;
    }
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/(^|[\s,])\*(?=[$\s,])|\ball[_\s-]?(scopes?|roles?|permissions?|resources?)\b|full[_\s-]?access|cloud-platform/iu.test(text)) {
      categories.add("wildcard_scope");
    }
    if (/\b(admin|administrator|owner|superuser|root|org[_\s-]?admin|roles\/owner|roles\/editor)\b/iu.test(text)) {
      categories.add("admin_scope");
    }
    if (/iam\.serviceaccount|service[_\s-]?account[_\s-]?token[_\s-]?creator|token[_\s-]?creator|impersonat|assume[_\s-]?role|sts:assumerole|iam:passrole/iu.test(text)) {
      categories.add("iam_admin");
    }
    if (/repo\b|contents:write|pull[_-]?requests?:write|issues?:write|workflow|checks:write|deployments?:write/iu.test(text)) {
      categories.add("repo_write");
    }
    if (/gmail\.modify|gmail\.send|mail\.send|mail\.readwrite|email:send|email:write/iu.test(text)) {
      categories.add("email_modify");
    }
    if (/drive|storage|s3|blob|bucket|objects?:write|storage\.objects|s3:put|s3:delete/iu.test(text)) {
      categories.add("storage_write");
    }
    if (/jira.*write|write:jira|issue:write|tickets?:write|zendesk.*write|linear.*write|servicenow.*write/iu.test(text)) {
      categories.add("ticket_write");
    }
    if (/database|sql|cloudsql|rds|dynamodb|bigquery|datastore|firestore|spanner/iu.test(text)) {
      categories.add("cloud_write");
    }
    if (/workspace|directory|users?:write|groups?:write|admin\.directory/iu.test(text)) {
      categories.add("workspace_write");
    }
    if (/read|list|get|profile|metadata|openid|userinfo|email/iu.test(text)) categories.add("read_scope");
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function isAgentIdentityBroadScope(scopeCategories: string[]): boolean {
  return scopeCategories.some((scope) =>
    [
      "admin_scope",
      "cloud_write",
      "email_modify",
      "iam_admin",
      "repo_write",
      "storage_write",
      "ticket_write",
      "wildcard_scope",
      "workspace_write"
    ].includes(scope)
  );
}

function hasAgentIdentityIssuerSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /(^|\.)(issuer|issuer_url|authority|authorization_server|jwks_uri|audience|client_id)$/iu.test(field.path));
}

function hasAgentIdentitySubjectSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /subject|principal|service[_\s-]?account|client[_\s-]?id|installation[_\s-]?id|tenant|audience|allowed[_\s-]?subjects?|actor|identity/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentIdentityCredentialIssuanceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(issue|mint|exchange|token[_\s-]?endpoint|access[_\s-]?token|id[_\s-]?token|credential|session[_\s-]?token|sts|assume[_\s-]?role|installation[_\s-]?token)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentIdentityImpersonationSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(impersonat|delegate|delegation|assume[_\s-]?role|service[_\s-]?account|act[_\s-]?as|on[_\s-]?behalf|subject[_\s-]?mapping|workload[_\s-]?identity|federat)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentIdentityTokenRefreshSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(refresh|refresh[_\s-]?enabled|refresh[_\s-]?token|auto[_\s-]?refresh|renew|rotate|ttl|lifetime|duration)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentIdentityToolInjectionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(inject|export|materialize|hydrate|pass|forward|write[_-]?env|env[_-]?inject|tool|tools|mcp|runtime|browser|database|saas|connector|header|authorization)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentIdentityExternalAuthoritySignal(fields: RuntimeField[], scopeCategories: string[]): boolean {
  return scopeCategories.some((scope) => ["email_modify", "repo_write", "storage_write", "ticket_write", "workspace_write"].includes(scope)) ||
    fields.some((field) =>
      /\b(send|post|publish|write|update|create|delete|reply|email|slack|github|jira|zendesk|drive|storage|external|api)\b/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasAgentIdentityUntrustedInputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|slack|browser|web[_-]?page|chat|inbound|external)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentIdentitySensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|prod|production|admin|credential|token|api[_-]?key|secret)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentIdentityPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentIdentityApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|review|human[_-]?in[_-]?the[_-]?loop/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isAgentIdentitySecurityField(fieldPath: string): boolean {
  return /provider|identity|auth|oauth|oidc|issuer|audience|subject|principal|service|account|client|tenant|token|credential|secret|key|env|scope|permission|role|claim|capabilit|resource|impersonat|delegate|assume|federat|sts|refresh|ttl|lifetime|tool|mcp|browser|database|saas|connector|source|input|customer|ticket|email|approval|endpoint|url|host|authority|jwks/iu.test(
    fieldPath
  );
}

function classifyAgentExtensionLoaderConfig(value: unknown, filePath: string): AgentExtensionLoaderPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferAgentExtensionLoaderProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const destinations = classifyAgentExtensionLoaderDestinations(fields, provider);
  const extensionRefCount = countAgentExtensionReferences(fields);
  const extensionKinds = collectAgentExtensionKinds(fields);
  const authorityCategories = collectAgentExtensionAuthorityCategories(fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);

  return {
    agent_extension_loader_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAgentExtensionLoaderSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    agent_extension_loader_provider: provider,
    agent_extension_loader_remote: destinations.remote,
    agent_extension_loader_destination_redacted: destinations.destinationCount > 0,
    agent_extension_loader_destination_count: destinations.destinationCount,
    agent_extension_loader_destination_kinds: destinations.destinationKinds,
    agent_extension_loader_extension_refs_redacted: extensionRefCount > 0,
    agent_extension_loader_extension_ref_count: extensionRefCount,
    agent_extension_loader_extension_kinds: extensionKinds,
    agent_extension_loader_unpinned_reference: hasAgentExtensionUnpinnedReferenceSignal(fields),
    agent_extension_loader_auto_install_enabled: hasAgentExtensionAutoInstallSignal(fields),
    agent_extension_loader_auto_update_enabled: hasAgentExtensionAutoUpdateSignal(fields),
    agent_extension_loader_signature_verification_disabled: hasAgentExtensionSignatureVerificationDisabledSignal(fields),
    agent_extension_loader_provenance_verification_missing: hasAgentExtensionProvenanceVerificationMissingSignal(fields),
    agent_extension_loader_untrusted_input: hasAgentExtensionUntrustedInputSignal(fields),
    agent_extension_loader_tool_authority_categories: authorityCategories,
    agent_extension_loader_privileged_authority: isAgentExtensionPrivileged(authorityCategories),
    agent_extension_loader_external_authority: hasAgentExtensionExternalAuthoritySignal(fields, authorityCategories),
    agent_extension_loader_sensitive_data: hasAgentExtensionSensitiveDataSignal(fields),
    agent_extension_loader_pii_data: hasAgentExtensionPiiDataSignal(fields),
    agent_extension_loader_approval_required: hasAgentExtensionApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferAgentExtensionLoaderProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["agent_extension_marketplace", /\b(marketplace|registry|catalog|extension[_\s-]?loader|skill[_\s-]?registry|plugin[_\s-]?registry|agent[_\s-]?extension[_\s-]?marketplace)\b/iu],
    ["openai_gpts_actions", /\b(gpts?|actions?)\b[\s\S]{0,80}\b(extension|plugin|tool)\b/iu],
    ["github", /\bgithub\b|github\.com/iu],
    ["npm", /\b(npm|node[_\s-]?package|package\.json)\b|registry\.npmjs\.org/iu],
    ["pypi", /\b(pypi|python[_\s-]?package)\b|pypi\.org/iu],
    ["git", /\b(git|gitlab|bitbucket)\b|\.git\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifyAgentExtensionLoaderDestinations(
  fields: RuntimeField[],
  provider: string | undefined
): { remote: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  if (provider && provider !== "agent_extension_marketplace") {
    destinationKinds.add("managed_extension_provider");
    destinationCount += 1;
  }

  for (const field of fields) {
    const values = fieldStringValues(field);
    for (const value of values) {
      const destination = parseAgentExtensionDestination(value);
      if (destination) {
        destinationKinds.add(destination.kind);
        destinationCount += 1;
      }
    }
    if (/(^|\.)(registry|registry_url|marketplace|catalog|endpoint|url|uri|host|source|repository|repo)$/iu.test(field.path)) {
      const text = values.join(" ");
      if (looksLikeRemoteExtensionHost(text)) {
        destinationKinds.add("extension_registry_endpoint");
        destinationCount += 1;
      }
    }
  }

  return {
    remote: destinationCount > 0,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b))
  };
}

function parseAgentExtensionDestination(value: string): { kind: string } | undefined {
  try {
    const parsed = new URL(value);
    if (!["http:", "https:", "git:", "ssh:"].includes(parsed.protocol)) return undefined;
    if (isLocalHost(parsed.hostname.toLowerCase())) return undefined;
    if (parsed.protocol === "git:" || parsed.protocol === "ssh:" || /\.git$/iu.test(parsed.pathname)) return { kind: "git_repository" };
    return { kind: parsed.protocol === "http:" ? "plaintext_extension_registry" : "extension_registry_endpoint" };
  } catch {
    return undefined;
  }
}

function looksLikeRemoteExtensionHost(value: string): boolean {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || trimmed.startsWith("${")) return false;
  if (isLocalHost(trimmed)) return false;
  return /\b(registry|marketplace|catalog|extensions?|plugins?|skills?|npmjs|pypi|github|gitlab|bitbucket)\b/iu.test(trimmed) ||
    /^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?$/iu.test(trimmed);
}

function countAgentExtensionReferences(fields: RuntimeField[]): number {
  let count = 0;
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/(^|\.)(extensions?|skills?|plugins?|tools?|capabilities?|packages?|modules?)\.(\d+|[A-Za-z][\w-]*)/iu.test(field.path)) {
      count += 1;
      continue;
    }
    if (/(^|\.)(package|packages|module|modules|repository|repo|url|source|manifest|extension|skill|plugin)$/iu.test(field.path) && fieldStringValues(field).length > 0) {
      count += 1;
      continue;
    }
    if (/(?:^|[_\W])(@?[a-z0-9][\w.-]*\/[a-z0-9][\w.-]*|github:|git\+https?:|https?:\/\/|\.git)(?:[_\W]|$)/iu.test(text)) {
      count += 1;
    }
  }
  return count;
}

function collectAgentExtensionKinds(fields: RuntimeField[]): string[] {
  const kinds = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(skill|skills)\b/iu.test(text)) kinds.add("skill");
    if (/\b(plugin|plugins)\b/iu.test(text)) kinds.add("plugin");
    if (/\b(tool|tools|function|functions)\b/iu.test(text)) kinds.add("tool");
    if (/\b(mcp|server|servers)\b/iu.test(text)) kinds.add("mcp_server");
    if (/\b(prompt|prompts|template|templates)\b/iu.test(text)) kinds.add("prompt");
    if (/\b(agent|agents|subagent|subagents)\b/iu.test(text)) kinds.add("agent");
  }
  return [...kinds].sort((a, b) => a.localeCompare(b));
}

function hasAgentExtensionUnpinnedReferenceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/\b(unpinned|latest|allow[_\s-]?unpinned|floating|no[_\s-]?pin|any[_\s-]?version)\b/iu.test(text) && truthyConfigValue(field.value)) {
      return true;
    }
    return fieldStringValues(field).some((value) =>
      /(?:@latest|:\*|version\s*[:=]\s*(latest|\*)|\bmain\b|\bmaster\b|\bHEAD\b)/iu.test(value) ||
      (/(^|\/)(packages?|extensions?|skills?|plugins?)\b/iu.test(field.path) && looksLikeUnpinnedPackageReference(value))
    );
  });
}

function looksLikeUnpinnedPackageReference(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("${")) return false;
  if (/^https?:\/\//iu.test(trimmed)) return true;
  if (/^[a-z0-9_.-]+\/[a-z0-9_.-]+(?:\.git)?$/iu.test(trimmed)) return true;
  const npmLike = /^(@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/iu.test(trimmed);
  return npmLike && !/@\d+\.\d+\.\d+/u.test(trimmed);
}

function hasAgentExtensionAutoInstallSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(auto[_\s-]?(install|load|enable)|install[_\s-]?on[_\s-]?startup|load[_\s-]?on[_\s-]?startup|dynamic[_\s-]?load|autoload|auto-load|allow[_\s-]?install)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentExtensionAutoUpdateSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(auto[_\s-]?update|update[_\s-]?on[_\s-]?startup|pull[_\s-]?latest|refresh[_\s-]?catalog|sync[_\s-]?registry|floating[_\s-]?version)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentExtensionSignatureVerificationDisabledSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/\b(allow[_\s-]?unsigned|unsigned[_\s-]?allowed|skip[_\s-]?signature|signature[_\s-]?verification[_\s-]?disabled|no[_\s-]?signature)\b/iu.test(text)) {
      return truthyConfigValue(field.value);
    }
    if (/\b(signature|signing|verify[_\s-]?signature|signature[_\s-]?verification|signed)\b/iu.test(field.path)) {
      return disabledConfigValue(field.value);
    }
    return false;
  });
}

function hasAgentExtensionProvenanceVerificationMissingSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/\b(allow[_\s-]?untrusted|untrusted[_\s-]?registry|skip[_\s-]?provenance|provenance[_\s-]?verification[_\s-]?disabled|no[_\s-]?provenance)\b/iu.test(text)) {
      return truthyConfigValue(field.value);
    }
    if (/(^|[_\W])(provenance|attestation|checksum|digest|slsa|verified[_\s-]?publisher|trusted[_\s-]?publisher)([_\W]|$)/iu.test(field.path)) {
      return disabledConfigValue(field.value);
    }
    return false;
  });
}

function hasAgentExtensionUntrustedInputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|slack|browser|web[_-]?page|chat|inbound|external|selector|requested[_\s-]?extension)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function collectAgentExtensionAuthorityCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(tool|tools|function|function_call|mcp|capability|capabilities)\b/iu.test(text)) categories.add("tool_call");
    if (/\b(browser|playwright|puppeteer|web[_\s-]?agent|click|form|navigate)\b/iu.test(text)) categories.add("browser_action");
    if (/\b(database|db|sql|query|support_db|warehouse)\b/iu.test(text)) categories.add("database_access");
    if (/(?:^|[_\W])(vault|secret|secrets|secret[_\s-]?manager|key[_\s-]?vault|credential)(?:[_\W]|$)/iu.test(text)) {
      categories.add("secret_manager_access");
    }
    if (/\b(slack|email|webhook|message|ticket|issue|comment|reply|send|post|publish)\b/iu.test(text)) categories.add("external_response");
    if (/(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state)(?:[_\W]|$)/iu.test(text)) categories.add("memory_write");
    if (/\b(shell|bash|command|exec|terminal|python|node|subprocess)\b/iu.test(text)) categories.add("shell_execution");
    if (/\b(filesystem|file[_\s-]?write|workspace|repo|repository|github|gitlab|pull[_\s-]?request)\b/iu.test(text)) {
      categories.add("repo_or_filesystem_write");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function isAgentExtensionPrivileged(categories: string[]): boolean {
  return categories.some((category) =>
    [
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ].includes(category)
  );
}

function hasAgentExtensionExternalAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("external_response") ||
    fields.some((field) => /\b(slack|email|webhook|send|post|publish|reply|respond|ticket|issue|external|api)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasAgentExtensionSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|prod|production|admin|credential|token|api[_-]?key|secret)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentExtensionPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentExtensionApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|review|human[_-]?in[_-]?the[_-]?loop/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isAgentExtensionLoaderSecurityField(fieldPath: string): boolean {
  return /provider|registry|marketplace|catalog|extension|skill|plugin|tool|mcp|package|module|source|repository|repo|url|host|endpoint|install|load|autoload|update|pin|version|signature|signing|provenance|attestation|checksum|digest|trusted|untrusted|selector|input|customer|ticket|prompt|retrieved|browser|authority|permission|scope|capabilit|approval|secret|token|credential|auth|env|pii|sensitive/iu.test(
    fieldPath
  );
}

function classifyAgentSelfModificationConfig(value: unknown, filePath: string): AgentSelfModificationPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const targetCategories = collectAgentSelfModificationTargetCategories(fields);
  const authorityCategories = collectAgentSelfModificationAuthorityCategories(fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);

  return {
    agent_self_modification_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAgentSelfModificationSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    agent_self_modification_target_redacted: targetCategories.length > 0 || hasAgentSelfModificationTargetReferenceSignal(fields),
    agent_self_modification_target_count: countAgentSelfModificationTargets(fields),
    agent_self_modification_target_categories: targetCategories,
    agent_self_modification_instruction_target: targetCategories.includes("instruction_file"),
    agent_self_modification_prompt_target: targetCategories.includes("prompt_template"),
    agent_self_modification_policy_target: targetCategories.includes("policy_file"),
    agent_self_modification_tool_target: targetCategories.includes("tool_definition"),
    agent_self_modification_runtime_target: targetCategories.includes("runtime_config"),
    agent_self_modification_memory_target: targetCategories.includes("memory_store"),
    agent_self_modification_workflow_target: targetCategories.includes("workflow_file"),
    agent_self_modification_write_enabled: hasAgentSelfModificationWriteSignal(fields),
    agent_self_modification_auto_apply: hasAgentSelfModificationAutoApplySignal(fields),
    agent_self_modification_persistent_change: hasAgentSelfModificationPersistentChangeSignal(fields, targetCategories),
    agent_self_modification_executes_after_update: hasAgentSelfModificationExecuteAfterUpdateSignal(fields, authorityCategories),
    agent_self_modification_rollback_enabled: hasAgentSelfModificationRollbackSignal(fields),
    agent_self_modification_untrusted_input: hasAgentSelfModificationUntrustedInputSignal(fields),
    agent_self_modification_authority_categories: authorityCategories,
    agent_self_modification_external_authority: hasAgentSelfModificationExternalAuthoritySignal(fields, authorityCategories),
    agent_self_modification_sensitive_data: hasAgentSelfModificationSensitiveDataSignal(fields),
    agent_self_modification_pii_data: hasAgentSelfModificationPiiDataSignal(fields),
    agent_self_modification_approval_required: hasAgentSelfModificationApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function collectAgentSelfModificationTargetCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(agents?\.md|claude\.md|instructions?|system[_\s-]?prompt|developer[_\s-]?prompt|repo[_\s-]?instructions?)\b/iu.test(text)) {
      categories.add("instruction_file");
    }
    if (/\b(prompt|prompts|template|templates|prompt[_\s-]?registry)\b/iu.test(text)) categories.add("prompt_template");
    if (/\b(agentcsp\.ya?ml|policy|policies|guardrail|guardrails|safety|redaction|approval)\b/iu.test(text)) categories.add("policy_file");
    if (/\b(tool|tools|function|functions|schema|schemas|mcp|plugin|skill)\b/iu.test(text)) categories.add("tool_definition");
    if (/\b(runtime|settings|config|codex|claude|cursor|permissions?|allowlist|approval[_\s-]?policy)\b/iu.test(text)) {
      categories.add("runtime_config");
    }
    if (/\b(memory|memories|long[_\s-]?term|state|checkpoint|checkpointer)\b/iu.test(text)) categories.add("memory_store");
    if (/\b(workflow|workflows|github[_\s-]?actions|ci|cd|automation)\b/iu.test(text)) categories.add("workflow_file");
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasAgentSelfModificationTargetReferenceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(\.codex|\.claude|\.cursor|agents?\.md|claude\.md|agentcsp\.ya?ml|package\.json|mcp\.json|tools?\/|prompts?\/|memory\/|\.github\/workflows)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function countAgentSelfModificationTargets(fields: RuntimeField[]): number {
  let count = 0;
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/(^|\.)(targets?|target_files?|paths?|files?|write_targets?|patch_targets?|managed_files?)\.(\d+|[A-Za-z][\w-]*)/iu.test(field.path)) {
      count += 1;
      continue;
    }
    if (/(^|\.)(target|target_file|path|file|write_target|patch_target|managed_file)$/iu.test(field.path) && fieldStringValues(field).length > 0) {
      count += 1;
      continue;
    }
    if (/(?:^|[_\W])(\.codex|\.claude|\.cursor|agents?\.md|claude\.md|agentcsp\.ya?ml|package\.json|mcp\.json|tools?\/|prompts?\/|memory\/|\.github\/workflows)(?:[_\W]|$)/iu.test(text)) {
      count += 1;
    }
  }
  return count;
}

function hasAgentSelfModificationWriteSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(write|patch|modify|update|rewrite|edit|commit|save|persist|apply|replace|mutate|generate[_\s-]?patch|create)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentSelfModificationAutoApplySignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(auto[_\s-]?apply|apply[_\s-]?automatically|auto[_\s-]?commit|auto[_\s-]?merge|auto[_\s-]?save|without[_\s-]?approval|no[_\s-]?approval|autonomous|direct[_\s-]?write)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentSelfModificationPersistentChangeSignal(fields: RuntimeField[], targetCategories: string[]): boolean {
  return targetCategories.length > 0 ||
    fields.some((field) =>
      /\b(persist|permanent|durable|repo|repository|workspace|filesystem|git|commit|save|write[_\s-]?through|store)\b/iu.test(
        `${field.path} ${fieldValueText(field)}`
      ) && truthyConfigValue(field.value)
    );
}

function hasAgentSelfModificationExecuteAfterUpdateSignal(fields: RuntimeField[], authorityCategories: string[]): boolean {
  return authorityCategories.includes("shell_execution") ||
    fields.some((field) =>
      /(?:^|[_\W])(reload|restart|execute[_\s-]?after|run[_\s-]?after|hot[_\s-]?reload|apply[_\s-]?then[_\s-]?run|load[_\s-]?updated)(?:[_\W]|$)/iu.test(
        `${field.path} ${fieldValueText(field)}`
      ) && truthyConfigValue(field.value)
    );
}

function hasAgentSelfModificationRollbackSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(rollback|revert|backup|snapshot|restore|undo|approval[_\s-]?checkpoint)\b/iu.test(field.path) && truthyConfigValue(field.value)
  );
}

function hasAgentSelfModificationUntrustedInputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|slack|browser|web[_-]?page|chat|inbound|external|tool[_\s-]?output)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function collectAgentSelfModificationAuthorityCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/(?:^|[_\W])(shell|bash|command|exec|terminal|python|node|subprocess|script)(?:[_\W]|$)/iu.test(text)) categories.add("shell_execution");
    if (/(?:^|[_\W])(filesystem|file[_\s-]?write|workspace|repo|repository|git|commit|push|pull[_\s-]?request)(?:[_\W]|$)/iu.test(text)) {
      categories.add("repo_or_filesystem_write");
    }
    if (/(?:^|[_\W])(tool|tools|function|mcp|plugin|skill|capability)(?:[_\W]|$)/iu.test(text)) categories.add("tool_definition_write");
    if (/(?:^|[_\W])(prompt|instruction|system[_\s-]?prompt|developer[_\s-]?prompt|policy|guardrail|safety)(?:[_\W]|$)/iu.test(text)) {
      categories.add("control_plane_write");
    }
    if (/(?:^|[_\W])(slack|email|webhook|message|ticket|issue|comment|reply|send|post|publish)(?:[_\W]|$)/iu.test(text)) categories.add("external_response");
    if (/(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state)(?:[_\W]|$)/iu.test(text)) categories.add("memory_write");
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasAgentSelfModificationExternalAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("external_response") ||
    fields.some((field) => /\b(slack|email|webhook|send|post|publish|reply|respond|ticket|issue|external|api)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasAgentSelfModificationSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|prod|production|admin|credential|token|api[_-]?key|secret)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentSelfModificationPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentSelfModificationApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|review|human[_-]?in[_-]?the[_-]?loop/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isAgentSelfModificationSecurityField(fieldPath: string): boolean {
  return /self|modify|mutation|patch|update|write|target|prompt|instruction|policy|guardrail|runtime|config|tool|mcp|plugin|skill|memory|workflow|automation|apply|commit|persist|reload|execute|rollback|backup|approval|source|input|customer|ticket|retrieved|browser|authority|permission|secret|token|credential|auth|env|pii|sensitive/iu.test(
    fieldPath
  );
}

function classifyAgentApprovalGateConfig(value: unknown, filePath: string): AgentApprovalGatePosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const promptSourceCategories = collectAgentApprovalPromptSourceCategories(fields);
  const actionCategories = collectAgentApprovalActionCategories(fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);
  const secretAccess = hasAgentApprovalSecretAccessSignal(fields) || actionCategories.includes("secret_manager_access");

  return {
    agent_approval_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAgentApprovalGateSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    agent_approval_prompt_redacted: hasAgentApprovalPromptSignal(fields) || promptSourceCategories.length > 0,
    agent_approval_prompt_source_categories: promptSourceCategories,
    agent_approval_context_untrusted: hasAgentApprovalUntrustedContextSignal(fields) || promptSourceCategories.some((category) =>
      ["retrieval_context", "tool_output", "untrusted_user_input"].includes(category)
    ),
    agent_approval_decision_model_driven: hasAgentApprovalModelDrivenDecisionSignal(fields),
    agent_approval_uses_untrusted_summary: hasAgentApprovalUntrustedSummarySignal(fields, promptSourceCategories),
    agent_approval_human_required: hasAgentApprovalHumanRequiredSignal(fields),
    agent_approval_default_allow: hasAgentApprovalDefaultAllowSignal(fields),
    agent_approval_auto_execute_after_approval: hasAgentApprovalAutoExecuteSignal(fields),
    agent_approval_action_categories: actionCategories,
    agent_approval_privileged_actions: actionCategories.length > 0 || hasAgentApprovalPrivilegedActionSignal(fields),
    agent_approval_write_actions: hasAgentApprovalWriteActionSignal(fields, actionCategories),
    agent_approval_destructive_actions: hasAgentApprovalDestructiveActionSignal(fields, actionCategories),
    agent_approval_external_actions: actionCategories.includes("external_response") || hasAgentApprovalExternalActionSignal(fields),
    agent_approval_memory_write: actionCategories.includes("memory_write"),
    agent_approval_secret_access: secretAccess,
    agent_approval_sensitive_data: hasAgentApprovalSensitiveDataSignal(fields) || secretAccess,
    agent_approval_pii_data: hasAgentApprovalPiiDataSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function collectAgentApprovalPromptSourceCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/(?:^|[_\W])(user|customer|client|ticket|support|issue|comment|message|inbound|external|public|web[_\s-]?page|email|slack|chat)(?:[_\W]|$)/iu.test(text)) {
      categories.add("untrusted_user_input");
    }
    if (/(?:^|[_\W])(retrieved|retrieval|rag|documents?|vector|embedding|knowledge[_\s-]?base|customer[_\s-]?context)(?:[_\W]|$)/iu.test(text)) {
      categories.add("retrieval_context");
    }
    if (/(?:^|[_\W])(tool[_\s-]?outputs?|tool[_\s-]?results?|function[_\s-]?outputs?|mcp[_\s-]?results?|browser[_\s-]?outputs?|command[_\s-]?outputs?)(?:[_\W]|$)/iu.test(text)) {
      categories.add("tool_output");
    }
    if (/(?:^|[_\W])(memory|memories|session[_\s-]?state|conversation[_\s-]?history|transcript)(?:[_\W]|$)/iu.test(text)) {
      categories.add("memory_context");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function collectAgentApprovalActionCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/(?:^|[_\W])(shell|bash|command|exec|terminal|python|node|subprocess|script)(?:[_\W]|$)/iu.test(text)) categories.add("shell_execution");
    if (/(?:^|[_\W])(database|db|sql|query|support[_\s-]?db|warehouse|update[_\s-]?customer[_\s-]?record)(?:[_\W]|$)/iu.test(text)) {
      categories.add("database_write");
    }
    if (/(?:^|[_\W])(slack|email|webhook|message|ticket|issue|comment|reply|respond|send|post|publish)(?:[_\W]|$)/iu.test(text)) {
      categories.add("external_response");
    }
    if (/(?:^|[_\W])(browser|playwright|puppeteer|selenium|click|form|upload|download|navigate)(?:[_\W]|$)/iu.test(text)) categories.add("browser_action");
    if (/(?:^|[_\W])(vault|secret|secrets|secret[_\s-]?manager|key[_\s-]?vault|credential|token)(?:[_\W]|$)/iu.test(text)) {
      categories.add("secret_manager_access");
    }
    if (/(?:^|[_\W])(filesystem|file[_\s-]?write|workspace|repo|repository|git|commit|push|pull[_\s-]?request|merge)(?:[_\W]|$)/iu.test(text)) {
      categories.add("repo_or_filesystem_write");
    }
    if (/(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state|long[_\s-]?term)(?:[_\W]|$)/iu.test(text)) {
      categories.add("memory_write");
    }
    if (/(?:^|[_\W])(tool|tools|function|function[_\s-]?call|mcp|connector|capability)(?:[_\W]|$)/iu.test(text)) {
      categories.add("tool_call");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasAgentApprovalPromptSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|\.)(approval_prompt|prompt|template|summary|summarization|justification|reason|rubric|review_text|approval_request)(?:\.|$)/iu.test(
      field.path
    )
  );
}

function hasAgentApprovalUntrustedContextSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|slack|browser|web[_-]?page|chat|inbound|external|tool[_\s-]?output)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentApprovalModelDrivenDecisionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(llm|model|ai[_\s-]?judge|judge|classifier|critic|scorer|risk[_\s-]?score|auto[_\s-]?approve|autonomous|policy[_\s-]?model|decision[_\s-]?model)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentApprovalUntrustedSummarySignal(fields: RuntimeField[], promptSourceCategories: string[]): boolean {
  const hasUntrustedSource = promptSourceCategories.some((category) =>
    ["retrieval_context", "tool_output", "untrusted_user_input"].includes(category)
  );
  if (!hasUntrustedSource) return false;
  return fields.some((field) =>
    /(?:^|[_\W])(summary|summarize|summarization|justification|reason|approval[_\s-]?prompt|review[_\s-]?text|decision[_\s-]?context)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentApprovalHumanRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|\.)(human_required|human_review_required|human_approval_required|required_human_review|reviewer_required|human_in_the_loop|required_review|manual_review)(?:\.|$)/iu.test(
      field.path
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentApprovalDefaultAllowSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/(?:^|\.)(default_allow|allow_by_default|approve_by_default|default_approve|fail_open)(?:\.|$)/iu.test(field.path)) {
      return truthyConfigValue(field.value);
    }
    return /(?:^|[_\W])(default|fallback|timeout|on[_\s-]?error|fail[_\s-]?open)(?:[_\W]|$)/iu.test(field.path) &&
      /(?:^|[_\W])(allow|approve|execute|continue|run|send|post)(?:[_\W]|$)/iu.test(text) &&
      truthyConfigValue(field.value);
  });
}

function hasAgentApprovalAutoExecuteSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(auto[_\s-]?execute|execute[_\s-]?after[_\s-]?approval|on[_\s-]?approval|post[_\s-]?approval|after[_\s-]?approval|apply[_\s-]?approved|run[_\s-]?approved|send[_\s-]?approved|execute|run|invoke|call)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentApprovalPrivilegedActionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(privileged|admin|production|prod|write|delete|external|credential|secret|tool|mcp|browser|shell|database)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentApprovalWriteActionSignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.some((category) =>
    ["database_write", "external_response", "memory_write", "repo_or_filesystem_write", "shell_execution"].includes(category)
  ) || fields.some((field) =>
    /(?:^|[_\W])(write|update|create|delete|reply|respond|send|post|publish|comment|commit|push|merge|deploy|remember|persist|approve|close|assign)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentApprovalDestructiveActionSignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("shell_execution") ||
    fields.some((field) =>
      /(?:^|[_\W])(delete|drop|destroy|destructive|irreversible|overwrite|merge|deploy|charge|refund|close[_\s-]?account|remove|revoke)(?:[_\W]|$)/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasAgentApprovalExternalActionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(slack|email|webhook|send|post|publish|reply|respond|ticket|issue|external|api|customer[_\s-]?system)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentApprovalSecretAccessSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(secret|secrets|token|credential|api[_-]?key|password|vault|key[_\s-]?vault|authorization|oauth)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentApprovalSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|prod|production|admin|credential|token|api[_-]?key|secret)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentApprovalPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function isAgentApprovalGateSecurityField(fieldPath: string): boolean {
  return /approval|approve|review|reviewer|human|hitl|gate|decision|prompt|summary|justification|reason|model|llm|judge|classifier|score|default|fallback|timeout|execute|run|action|tool|mcp|browser|shell|database|db|secret|token|credential|auth|env|source|input|customer|ticket|retrieved|browser|memory|external|write|delete|pii|sensitive/iu.test(
    fieldPath
  );
}

function classifyAgentContextComposerConfig(value: unknown, filePath: string): AgentContextComposerPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const sourceCategories = collectAgentContextComposerSourceCategories(fields);
  const authorityCategories = collectAgentContextComposerToolAuthorityCategories(fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);
  const secretAccess = hasAgentContextComposerSecretAccessSignal(fields) || authorityCategories.includes("secret_manager_access");

  return {
    agent_context_composer_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAgentContextComposerSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    agent_context_composer_source_redacted: sourceCategories.length > 0 || hasAgentContextComposerSourceSignal(fields),
    agent_context_composer_source_categories: sourceCategories,
    agent_context_composer_untrusted_sources: hasAgentContextComposerUntrustedSourceSignal(fields) || sourceCategories.some((category) =>
      ["retrieval_context", "tool_output", "untrusted_user_input", "web_content"].includes(category)
    ),
    agent_context_composer_privileged_role_injection: hasAgentContextComposerPrivilegedRoleSignal(fields),
    agent_context_composer_system_role: hasAgentContextComposerSystemRoleSignal(fields),
    agent_context_composer_developer_role: hasAgentContextComposerDeveloperRoleSignal(fields),
    agent_context_composer_role_boundary_redacted: hasAgentContextComposerRoleBoundarySignal(fields),
    agent_context_composer_delimiter_disabled: hasAgentContextComposerDelimiterDisabledSignal(fields),
    agent_context_composer_sanitization_disabled: hasAgentContextComposerSanitizationDisabledSignal(fields),
    agent_context_composer_raw_context_enabled: hasAgentContextComposerRawContextSignal(fields),
    agent_context_composer_tool_authority_categories: authorityCategories,
    agent_context_composer_privileged_tool_authority: authorityCategories.length > 0 || hasAgentContextComposerPrivilegedToolSignal(fields),
    agent_context_composer_write_authority: hasAgentContextComposerWriteAuthoritySignal(fields, authorityCategories),
    agent_context_composer_external_authority: authorityCategories.includes("external_response") || hasAgentContextComposerExternalAuthoritySignal(fields),
    agent_context_composer_memory_write: authorityCategories.includes("memory_write"),
    agent_context_composer_shell_authority: authorityCategories.includes("shell_execution"),
    agent_context_composer_destructive_authority: hasAgentContextComposerDestructiveAuthoritySignal(fields, authorityCategories),
    agent_context_composer_secret_access: secretAccess,
    agent_context_composer_sensitive_data: hasAgentContextComposerSensitiveDataSignal(fields) || secretAccess,
    agent_context_composer_pii_data: hasAgentContextComposerPiiDataSignal(fields),
    agent_context_composer_approval_required: hasAgentContextComposerApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function collectAgentContextComposerSourceCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/(?:^|[_\W])(user|customer|client|ticket|support|issue|comment|message|inbound|external|public|email|slack|chat)(?:[_\W]|$)/iu.test(text)) {
      categories.add("untrusted_user_input");
    }
    if (/(?:^|[_\W])(retrieved|retrieval|rag|documents?|vector|embedding|knowledge[_\s-]?base|account[_\s-]?context|customer[_\s-]?context)(?:[_\W]|$)/iu.test(text)) {
      categories.add("retrieval_context");
    }
    if (/(?:^|[_\W])(tool[_\s-]?outputs?|tool[_\s-]?results?|function[_\s-]?outputs?|mcp[_\s-]?results?|browser[_\s-]?outputs?|command[_\s-]?outputs?|observation)(?:[_\W]|$)/iu.test(text)) {
      categories.add("tool_output");
    }
    if (/(?:^|[_\W])(memory|memories|session[_\s-]?state|conversation[_\s-]?history|transcript|long[_\s-]?term)(?:[_\W]|$)/iu.test(text)) {
      categories.add("memory_context");
    }
    if (/(?:^|[_\W])(web[_\s-]?page|browser|html|dom|url|website|crawl|scrape)(?:[_\W]|$)/iu.test(text)) categories.add("web_content");
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function collectAgentContextComposerToolAuthorityCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    const authorityField = /(?:^|\.)(tool_authority|runtime_authority|authority|tools?|actions?|allowed_tools|permissions?|capabilities?|connectors?)(?:\.|$)/iu.test(
      field.path
    );
    if (
      !authorityField &&
      /(?:^|\.)(sources?|inputs?|context_sources|include_sources|context|data_scope)(?:\.|$)/iu.test(field.path)
    ) {
      continue;
    }
    if (/(?:^|[_\W])(tool|tools|function|function[_\s-]?call|mcp|connector|capability)(?:[_\W]|$)/iu.test(text)) categories.add("tool_call");
    if (/(?:^|[_\W])(database|db|sql|query|support[_\s-]?db|warehouse|update[_\s-]?customer[_\s-]?record)(?:[_\W]|$)/iu.test(text)) {
      categories.add("database_access");
    }
    if (/(?:^|[_\W])(slack|email|webhook|message|ticket|issue|comment|reply|respond|send|post|publish)(?:[_\W]|$)/iu.test(text)) {
      categories.add("external_response");
    }
    if (/(?:^|[_\W])(browser|playwright|puppeteer|selenium|click|form|upload|download|navigate|submit)(?:[_\W]|$)/iu.test(text)) {
      categories.add("browser_action");
    }
    if (/(?:^|[_\W])(vault|secret|secrets|secret[_\s-]?manager|key[_\s-]?vault|credential|token)(?:[_\W]|$)/iu.test(text)) {
      categories.add("secret_manager_access");
    }
    if (/(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state|long[_\s-]?term)(?:[_\W]|$)/iu.test(text)) {
      categories.add("memory_write");
    }
    if (/(?:^|[_\W])(shell|bash|command|exec|terminal|python|node|subprocess|script)(?:[_\W]|$)/iu.test(text)) categories.add("shell_execution");
    if (/(?:^|[_\W])(filesystem|file[_\s-]?write|workspace|repo|repository|git|commit|push|pull[_\s-]?request|merge)(?:[_\W]|$)/iu.test(text)) {
      categories.add("repo_or_filesystem_write");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasAgentContextComposerSourceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|\.)(sources?|inputs?|context|context_sources|include_sources|retrieval|memory|tool_outputs?|browser_outputs?)(?:\.|$)/iu.test(
      field.path
    )
  );
}

function hasAgentContextComposerUntrustedSourceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|slack|browser|web[_-]?page|chat|inbound|external|tool[_\s-]?output)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerPrivilegedRoleSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(system|developer|instruction|instructions|privileged[_\s-]?role|role[_\s-]?system|role[_\s-]?developer)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerSystemRoleSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(system|system[_\s-]?prompt|role[_\s-]?system)(?:[_\W]|$)/iu.test(`${field.path} ${fieldValueText(field)}`)
  );
}

function hasAgentContextComposerDeveloperRoleSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(developer|developer[_\s-]?prompt|role[_\s-]?developer)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerRoleBoundarySignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /(?:^|\.)(roles?|messages?|system|developer|role_map|role_mapping)(?:\.|$)/iu.test(field.path));
}

function hasAgentContextComposerDelimiterDisabledSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/(?:^|\.)(delimiter|delimiters|isolation|separation|separators?|boundary|boundaries|quote|escape)(?:\.|$)/iu.test(field.path)) {
      return disabledConfigValue(field.value) || /(?:^|[_\W])(none|disabled|raw|passthrough|off|false)(?:[_\W]|$)/iu.test(text);
    }
    return /(?:^|[_\W])(no[_\s-]?delimiter|delimiter[_\s-]?none|raw[_\s-]?context|passthrough[_\s-]?context)(?:[_\W]|$)/iu.test(text);
  });
}

function hasAgentContextComposerSanitizationDisabledSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/(?:^|\.)(sanitize|sanitization|filter|prompt_injection_filter|prompt-injection-filter|validation|validate|strip_instructions|strip-instructions|escape|redact)(?:\.|$)/iu.test(
      field.path
    )) {
      return disabledConfigValue(field.value) || /(?:^|[_\W])(disabled|off|false|none|raw|passthrough|bypass)(?:[_\W]|$)/iu.test(text);
    }
    return /(?:^|[_\W])(unsanitized|raw[_\s-]?context|no[_\s-]?sanitization|bypass[_\s-]?filter)(?:[_\W]|$)/iu.test(text);
  });
}

function hasAgentContextComposerRawContextSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(raw[_\s-]?context|include[_\s-]?raw|full[_\s-]?context|verbatim|passthrough)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentContextComposerPrivilegedToolSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(tool|tools|mcp|browser|shell|database|secret|vault|slack|email|webhook|filesystem|memory|write|update|send|post|publish)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerWriteAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.some((category) =>
    ["database_access", "external_response", "memory_write", "repo_or_filesystem_write", "shell_execution"].includes(category)
  ) || fields.some((field) =>
    /(?:^|[_\W])(write|update|create|delete|reply|respond|send|post|publish|comment|commit|push|merge|deploy|remember|persist|assign)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerExternalAuthoritySignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(slack|email|webhook|send|post|publish|reply|respond|ticket|issue|external|api|customer[_\s-]?system)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerDestructiveAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("shell_execution") ||
    fields.some((field) =>
      /(?:^|[_\W])(delete|drop|destroy|destructive|irreversible|overwrite|merge|deploy|charge|refund|close[_\s-]?account|remove|revoke)(?:[_\W]|$)/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasAgentContextComposerSecretAccessSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(secret|secrets|token|credential|api[_-]?key|password|vault|key[_\s-]?vault|authorization|oauth)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|prod|production|admin|credential|token|api[_-]?key|secret)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentContextComposerApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|review|human[_-]?in[_-]?the[_-]?loop/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isAgentContextComposerSecurityField(fieldPath: string): boolean {
  return /context|source|input|prompt|message|role|system|developer|instruction|composer|builder|assembly|router|delimiter|boundary|sanitize|filter|validation|raw|passthrough|tool|mcp|browser|shell|database|db|secret|token|credential|auth|env|memory|external|write|delete|approval|customer|ticket|retrieved|rag|pii|sensitive/iu.test(
    fieldPath
  );
}

function classifySaasConnectorConfig(value: unknown, filePath: string): SaasConnectorPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferSaasProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const destinations = classifySaasConnectorDestinations(fields, provider);
  const scopeCategories = collectSaasScopeCategories(fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);
  const externalWrite = hasSaasExternalWriteSignal(fields, scopeCategories);
  const approvalRequired = hasSaasApprovalRequiredSignal(fields);

  return {
    saas_connector_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isSaasConnectorSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    saas_connector_provider: provider,
    saas_connector_external_reach: destinations.remote,
    saas_connector_destination_redacted: destinations.destinationCount > 0,
    saas_connector_destination_count: destinations.destinationCount,
    saas_connector_destination_kinds: destinations.destinationKinds,
    saas_connector_scope_redacted: scopeCategories.length > 0,
    saas_connector_scope_categories: scopeCategories,
    saas_connector_broad_scope: isSaasBroadScope(scopeCategories),
    saas_connector_admin_scope: scopeCategories.some((scope) => scope.includes("admin") || scope === "wildcard_scope"),
    saas_connector_read_enabled: hasSaasReadSignal(fields, scopeCategories),
    saas_connector_external_write_enabled: externalWrite,
    saas_connector_untrusted_input: hasSaasUntrustedInputSignal(fields),
    saas_connector_sensitive_data: hasSaasSensitiveDataSignal(fields),
    saas_connector_pii_data: hasSaasPiiDataSignal(fields),
    saas_connector_approval_required: approvalRequired,
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferSaasProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["slack", /\bslack\b|slack\.com/iu],
    ["github", /\bgithub\b|api\.github\.com/iu],
    ["gitlab", /\bgitlab\b/iu],
    ["gmail", /\bgmail\b|googleapis\.com\/auth\/gmail/iu],
    ["outlook", /\boutlook\b|graph\.microsoft\.com|microsoft graph/iu],
    ["jira", /\bjira\b|atlassian/iu],
    ["linear", /\blinear\b/iu],
    ["zendesk", /\bzendesk\b/iu],
    ["salesforce", /\bsalesforce\b/iu],
    ["hubspot", /\bhubspot\b/iu],
    ["notion", /\bnotion\b/iu],
    ["servicenow", /\bservice[-_\s]?now\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifySaasConnectorDestinations(
  fields: RuntimeField[],
  provider: string | undefined
): { remote: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  if (provider) {
    destinationKinds.add("managed_saas_provider");
    destinationCount += 1;
  }
  for (const field of fields) {
    for (const value of saasFieldStringValues(field)) {
      const destination = parseRemoteSaasDestination(value);
      if (destination) {
        destinationKinds.add(destination.kind);
        destinationCount += 1;
      }
    }
  }
  return {
    remote: destinationCount > 0,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b))
  };
}

function parseRemoteSaasDestination(value: string): { kind: string } | undefined {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
    if (isLocalHost(parsed.hostname.toLowerCase())) return undefined;
    return { kind: parsed.protocol === "http:" ? "plaintext_api_endpoint" : "api_endpoint" };
  } catch {
    return undefined;
  }
}

function saasFieldStringValues(field: RuntimeField): string[] {
  if (Array.isArray(field.value)) return field.value.map(String);
  if (typeof field.value === "string") return [field.value];
  return [];
}

function collectSaasScopeCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    if (!/(^|\.)(scopes?|oauth[_-]?scopes?|permissions?|roles?)$/iu.test(field.path)) continue;
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/(^|[\s,])\*(?=[$\s,])|\ball[_\s-]?scopes?\b|full[_\s-]?access/iu.test(text)) categories.add("wildcard_scope");
    if (/\b(admin|administrator|owner|admin:org|admin:repo|admin:repo_hook|manage_runners)\b/iu.test(text)) {
      categories.add("admin_scope");
    }
    if (/\brepo\b|contents:write|pull[_-]?requests?:write|issues?:write|workflow|checks:write|deployments?:write/iu.test(text)) {
      categories.add("repo_write");
    }
    if (/chat:write|channels?:write|groups?:write|im:write|mpim:write|files:write|reactions:write|pins:write|commands/iu.test(text)) {
      categories.add("messaging_write");
    }
    if (/channels?:history|groups?:history|im:history|mpim:history|users:read|users:read\.email|team:read/iu.test(text)) {
      categories.add("messaging_read");
    }
    if (/gmail\.modify|gmail\.send|mail\.send|mail\.readwrite|mailboxsettings|smtp|email:send|email:write/iu.test(text)) {
      categories.add("email_modify");
    }
    if (/jira.*write|write:jira|issue:write|tickets?:write|zendesk.*write|linear.*write|servicenow.*write/iu.test(text)) {
      categories.add("ticket_write");
    }
    if (/salesforce.*write|hubspot.*write|crm\.objects.*write|contacts?:write|companies?:write|deals?:write/iu.test(text)) {
      categories.add("crm_write");
    }
    if (/calendar.*write|calendar\.events|calendars?:write/iu.test(text)) categories.add("calendar_write");
    if (/read|history|list|metadata|profile|users:read|contacts?:read/iu.test(text)) categories.add("read_scope");
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function isSaasBroadScope(scopeCategories: string[]): boolean {
  return scopeCategories.some((scope) =>
    [
      "admin_scope",
      "calendar_write",
      "crm_write",
      "email_modify",
      "messaging_write",
      "repo_write",
      "ticket_write",
      "wildcard_scope"
    ].includes(scope)
  );
}

function hasSaasReadSignal(fields: RuntimeField[], scopeCategories: string[]): boolean {
  return scopeCategories.some((scope) => scope.includes("read")) ||
    fields.some((field) => /\b(read|list|fetch|history|search|lookup|get)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasSaasExternalWriteSignal(fields: RuntimeField[], scopeCategories: string[]): boolean {
  return scopeCategories.some((scope) => ["calendar_write", "crm_write", "email_modify", "messaging_write", "repo_write", "ticket_write"].includes(scope)) ||
    fields.some((field) =>
      /\b(write|send|post|publish|create|update|delete|comment|reply|email|message|ticket|issue|merge|approve|upload|invite|assign)\b/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasSaasUntrustedInputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|slack|browser|web[_-]?page|chat)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasSaasSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|order|record|case|profile|note|incident)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasSaasPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasSaasApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation/iu.test(field.path) && truthyConfigValue(field.value)
  );
}

function isSaasConnectorSecurityField(fieldPath: string): boolean {
  return /provider|service|connector|integration|api|endpoint|url|host|oauth|scope|permission|role|token|secret|credential|auth|webhook|channel|repo|email|ticket|issue|crm|customer|user|source|input|action|write|send|post|publish|approval|destination/iu.test(
    fieldPath
  );
}

function classifySecretManagerConfig(value: unknown, filePath: string): SecretManagerPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferSecretManagerProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const destination = classifySecretManagerDestination(fields, provider);
  const scopeCategories = collectSecretManagerScopeCategories(fields);
  const envKeys = extractEnvironmentReferenceKeys(stringValues);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);
  const readEnabled = hasSecretManagerReadSignal(fields, scopeCategories);
  const listEnabled = hasSecretManagerListSignal(fields, scopeCategories);
  const writeEnabled = hasSecretManagerWriteSignal(fields, scopeCategories);

  return {
    secret_manager_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isSecretManagerSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    secret_manager_provider: provider,
    secret_manager_remote: destination.remote,
    secret_manager_destination_redacted: destination.destinationCount > 0,
    secret_manager_destination_count: destination.destinationCount,
    secret_manager_destination_kinds: destination.destinationKinds,
    secret_manager_scope_redacted: scopeCategories.length > 0,
    secret_manager_scope_categories: scopeCategories,
    secret_manager_path_references_redacted: hasSecretManagerPathReferenceSignal(fields),
    secret_manager_read_enabled: readEnabled,
    secret_manager_list_enabled: listEnabled,
    secret_manager_write_enabled: writeEnabled,
    secret_manager_broad_scope: isSecretManagerBroadScope(scopeCategories, listEnabled),
    secret_manager_injects_into_tools: hasSecretManagerToolInjectionSignal(fields),
    secret_manager_untrusted_input: hasSecretManagerUntrustedInputSignal(fields),
    secret_manager_sensitive_scope: hasSecretManagerSensitiveScopeSignal(fields),
    secret_manager_pii_scope: hasSecretManagerPiiScopeSignal(fields),
    secret_manager_approval_required: hasSecretManagerApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferSecretManagerProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["hashicorp_vault", /\b(hashicorp[_\s-]?vault|vault)\b|vault\./iu],
    ["aws_secrets_manager", /\b(aws[_\s-]?secrets?[_\s-]?manager|secretsmanager)\b|secretsmanager\.[a-z0-9-]+\.amazonaws\.com/iu],
    ["gcp_secret_manager", /\b(gcp[_\s-]?secret|google[_\s-]?secret|secretmanager\.googleapis\.com)\b/iu],
    ["azure_key_vault", /\b(azure[_\s-]?key[_\s-]?vault|keyvault)\b|vault\.azure\.net/iu],
    ["kubernetes_secrets", /\b(kubernetes|k8s)\b[\s\S]{0,80}\bsecrets?\b|\/api\/v1\/namespaces\/[^/]+\/secrets/iu],
    ["doppler", /\bdoppler\b/iu],
    ["1password", /\b1password|op[_\s-]?vault\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifySecretManagerDestination(
  fields: RuntimeField[],
  provider: string | undefined
): { remote: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  if (provider && provider !== "kubernetes_secrets") {
    destinationKinds.add("managed_secret_store");
    destinationCount += 1;
  }
  for (const field of fields) {
    for (const value of secretManagerFieldStringValues(field)) {
      const destination = parseRemoteSecretManagerDestination(value);
      if (destination) {
        destinationKinds.add(destination.kind);
        destinationCount += 1;
      }
    }
  }
  return {
    remote: destinationCount > 0,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b))
  };
}

function parseRemoteSecretManagerDestination(value: string): { kind: string } | undefined {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
    if (isLocalHost(parsed.hostname.toLowerCase())) return undefined;
    return { kind: parsed.protocol === "http:" ? "plaintext_secret_store_endpoint" : "secret_store_endpoint" };
  } catch {
    return undefined;
  }
}

function secretManagerFieldStringValues(field: RuntimeField): string[] {
  if (Array.isArray(field.value)) return field.value.map(String);
  if (typeof field.value === "string") return [field.value];
  return [];
}

function collectSecretManagerScopeCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    if (!/(^|\.)(capabilities|permissions?|policies|roles?|scopes?|secret[_-]?paths?|paths?|mounts?|resources?)$/iu.test(field.path)) continue;
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/(^|[\s,])\*(?=[$\s,])|\ball[_\s-]?(secrets?|paths?|mounts?|namespaces?)\b|root|superuser/iu.test(text)) {
      categories.add("wildcard_secret_scope");
    }
    if (/\b(read|get|decrypt|access|retrieve)\b/iu.test(text)) categories.add("secret_read");
    if (/\b(list|enumerate|metadata)\b/iu.test(text)) categories.add("secret_list");
    if (/\b(write|put|create|update|delete|destroy|rotate|revoke|encrypt)\b/iu.test(text)) categories.add("secret_write");
    if (/\b(prod|production|customer|client|billing|payment|support|internal|admin|service[_-]?tokens?|api[_-]?tokens?|credentials?)\b/iu.test(text)) {
      categories.add("sensitive_secret_scope");
    }
    if (/\b(email|phone|address|ssn|passport|pii|customer[_-]?id|user[_-]?id)\b/iu.test(text)) {
      categories.add("pii_secret_scope");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasSecretManagerReadSignal(fields: RuntimeField[], scopeCategories: string[]): boolean {
  return scopeCategories.includes("secret_read") ||
    fields.some((field) => /\b(read|get|retrieve|fetch|access|decrypt|lookup)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasSecretManagerListSignal(fields: RuntimeField[], scopeCategories: string[]): boolean {
  return scopeCategories.includes("secret_list") ||
    fields.some((field) => /\b(list|enumerate|metadata|discover)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasSecretManagerWriteSignal(fields: RuntimeField[], scopeCategories: string[]): boolean {
  return scopeCategories.includes("secret_write") ||
    fields.some((field) => /\b(write|put|create|update|delete|destroy|rotate|revoke|set)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function isSecretManagerBroadScope(scopeCategories: string[], listEnabled: boolean): boolean {
  return listEnabled || scopeCategories.some((scope) => ["sensitive_secret_scope", "wildcard_secret_scope"].includes(scope));
}

function hasSecretManagerPathReferenceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /secret[_-]?paths?|paths?|mounts?|namespaces?|vault[_-]?path|key[_-]?vault|resource|arn|projects?\/[^/\s]+\/secrets/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasSecretManagerToolInjectionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(inject|export|materialize|hydrate|pass|forward|write[_-]?env|env[_-]?inject|tool|mcp|runtime|command|shell|browser|saas|connector)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasSecretManagerUntrustedInputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|slack|browser|web[_-]?page|chat)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasSecretManagerSensitiveScopeSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|prod|production|admin|credential|token|api[_-]?key|secret)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasSecretManagerPiiScopeSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasSecretManagerApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation/iu.test(field.path) && truthyConfigValue(field.value)
  );
}

function isSecretManagerSecurityField(fieldPath: string): boolean {
  return /provider|vault|secret|credential|token|password|api[_-]?key|auth|endpoint|url|host|path|mount|namespace|policy|role|permission|capabilit|scope|read|list|write|access|decrypt|inject|export|tool|source|input|approval|resource|project|arn|kms|keyvault/iu.test(
    fieldPath
  );
}

function classifyAiModelEndpointConfig(value: unknown, filePath: string): AiModelEndpointPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferAiModelProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const remote = classifyAiModelRemoteEndpoint(fields, provider);
  const envKeys = collectEnvKeyNamesFromConfig(value);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);
  const promptSignal = hasAiModelContextSignal(fields, /\b(prompt|prompts|system|developer|input|inputs|message|messages|conversation|chat)\b/iu);
  const toolOutputSignal = hasAiModelContextSignal(
    fields,
    /(?:^|[_\W])(tool[_\s-]?outputs?|function[_\s-]?outputs?|mcp|observation|command[_\s-]?outputs?)(?:[_\W]|$)/iu
  );
  const retrievalSignal = hasAiModelContextSignal(
    fields,
    /(?:^|[_\W])(retrieval[_\s-]?context|retrieval|retrieved|rag|documents?|vector|embedding)(?:[_\W]|$)/iu
  );
  const memorySignal = hasAiModelContextSignal(fields, /(?:^|[_\W])(memory|memories|session|state|history|transcript)(?:[_\W]|$)/iu);
  const piiSignal = fields.some((field) => /\b(pii|email|phone|address|ssn|passport|customer|client|ticket|support)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
  const sendsPrompts = remote.remote || promptSignal;

  return {
    ai_model_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAiModelSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    ai_model_provider: provider,
    ai_model_remote_endpoint: remote.remote,
    ai_model_custom_endpoint: remote.customEndpoint,
    ai_model_destination_redacted: remote.destinationCount > 0,
    ai_model_remote_destination_count: remote.destinationCount,
    ai_model_remote_destination_kinds: remote.destinationKinds,
    ai_model_plaintext_endpoint: remote.plaintext,
    ai_model_encrypted_endpoint: remote.encrypted,
    ai_model_sends_prompts: sendsPrompts,
    ai_model_sends_tool_outputs: toolOutputSignal,
    ai_model_sends_retrieval_context: retrievalSignal,
    ai_model_sends_memory: memorySignal,
    ai_model_sensitive_context: sendsPrompts || toolOutputSignal || retrievalSignal || memorySignal || piiSignal,
    ai_model_pii_context: piiSignal,
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferAiModelProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["openai_compatible", /\b(openai[-_\s]?compatible|litellm|vllm|localai|llama\.?cpp|text[-_\s]?generation[-_\s]?inference|tgi)\b/iu],
    ["azure_openai", /\b(azure[-_\s]?openai|azure ai)\b/iu],
    ["openai", /\bopenai\b|\bapi\.openai\.com\b/iu],
    ["anthropic", /\banthropic\b|\bapi\.anthropic\.com\b/iu],
    ["bedrock", /\b(aws[-_\s]?bedrock|bedrock)\b/iu],
    ["vertex_ai", /\b(vertex[-_\s]?ai|google[-_\s]?ai|gemini)\b/iu],
    ["ollama", /\bollama\b/iu],
    ["groq", /\bgroq\b/iu],
    ["mistral", /\bmistral\b/iu],
    ["cohere", /\bcohere\b/iu],
    ["together", /\btogether\b/iu],
    ["fireworks", /\bfireworks\b/iu],
    ["openrouter", /\bopenrouter\b/iu],
    ["huggingface", /\b(huggingface|hugging face)\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifyAiModelRemoteEndpoint(
  fields: RuntimeField[],
  provider: string | undefined
): {
  remote: boolean;
  customEndpoint: boolean;
  destinationCount: number;
  destinationKinds: string[];
  plaintext: boolean;
  encrypted: boolean;
} {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  let plaintext = false;
  let encrypted = false;
  let customEndpoint = false;
  const managedProviders = new Set([
    "openai",
    "anthropic",
    "azure_openai",
    "bedrock",
    "vertex_ai",
    "groq",
    "mistral",
    "cohere",
    "together",
    "fireworks",
    "openrouter",
    "huggingface"
  ]);
  if (provider && managedProviders.has(provider)) {
    destinationKinds.add("managed_model_api");
    destinationCount += 1;
  }
  if (provider && ["openai_compatible", "ollama"].includes(provider)) {
    customEndpoint = true;
  }

  for (const field of fields) {
    const values = Array.isArray(field.value) ? field.value.map(String) : [String(field.value ?? "")];
    for (const value of values) {
      const remoteUrl = parseRemoteHttpUrl(value);
      if (!remoteUrl) continue;
      destinationKinds.add("http_endpoint");
      destinationCount += 1;
      if (remoteUrl.protocol === "http:") plaintext = true;
      if (remoteUrl.protocol === "https:") encrypted = true;
    }
    if (/(^|\.)(base_url|baseurl|api_base|api_url|endpoint|url|uri|host|gateway|proxy|router|server)$/iu.test(field.path)) {
      customEndpoint = true;
      const text = values.join(" ");
      if (/\b(api|gateway|proxy|router|llm|model|inference|openai|anthropic|litellm|vllm|ollama|localai)\b/iu.test(text)) {
        destinationKinds.add("configured_model_endpoint");
        destinationCount += 1;
      }
    }
  }

  return {
    remote: destinationCount > 0,
    customEndpoint,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b)),
    plaintext,
    encrypted
  };
}

function hasAiModelContextSignal(fields: RuntimeField[], pattern: RegExp): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (!pattern.test(text)) return false;
    if (/redact|mask|scrub|sanitize|exclude|drop|deny/iu.test(field.path)) return false;
    return truthyConfigValue(field.value) || /include|send|forward|attach|full|raw|context|history|memory|tool|prompt/iu.test(text);
  });
}

function isAiModelSecurityField(fieldPath: string): boolean {
  return /provider|model|base[_-]?url|api[_-]?base|endpoint|url|uri|host|gateway|proxy|router|server|api[_-]?key|token|secret|credential|auth|env|prompt|input|message|completion|output|tool|retrieval|rag|context|memory|history|pii/iu.test(
    fieldPath
  );
}

function classifyAiEvalHarnessConfig(value: unknown, filePath: string): AiEvalHarnessPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const framework = inferAiEvalFramework([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const toolAuthorityCategories = collectAiEvalToolAuthorityCategories(fields);
  const datasetCount = countAiEvalDatasetEntries(value, fields);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);

  return {
    ai_eval_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAiEvalSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    ai_eval_framework: framework,
    ai_eval_live_execution: hasAiEvalLiveExecutionSignal(fields),
    ai_eval_adversarial_cases: hasAiEvalAdversarialSignal(fields),
    ai_eval_untrusted_prompts: hasAiEvalUntrustedPromptSignal(fields),
    ai_eval_dataset_redacted: datasetCount > 0 || hasAiEvalDatasetSignal(fields),
    ai_eval_dataset_count: datasetCount,
    ai_eval_invokes_agent: hasAiEvalAgentInvocationSignal(fields),
    ai_eval_invokes_tools: toolAuthorityCategories.length > 0 || hasAiEvalToolInvocationSignal(fields),
    ai_eval_tool_authority_categories: toolAuthorityCategories,
    ai_eval_write_authority: hasAiEvalWriteAuthoritySignal(fields, toolAuthorityCategories),
    ai_eval_external_write_authority: hasAiEvalExternalWriteAuthoritySignal(fields, toolAuthorityCategories),
    ai_eval_remote_target: hasAiEvalRemoteTargetSignal(fields),
    ai_eval_production_target: hasAiEvalProductionTargetSignal(fields),
    ai_eval_records_outputs: hasAiEvalOutputRetentionSignal(fields),
    ai_eval_sensitive_data: hasAiEvalSensitiveDataSignal(fields),
    ai_eval_pii_data: hasAiEvalPiiDataSignal(fields),
    ai_eval_secret_exposure:
      toolAuthorityCategories.includes("secret_manager_access") ||
      hasAiEvalSecretSignal(fields) ||
      envKeys.some(isCredentialLikeKeyName) ||
      secretRefKeys.length > 0,
    ai_eval_approval_required: hasAiEvalApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferAiEvalFramework(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const frameworks: Array<[string, RegExp]> = [
    ["promptfoo", /\bpromptfoo\b/iu],
    ["garak", /\bgarak\b/iu],
    ["deepeval", /\bdeepeval\b/iu],
    ["openai_evals", /\b(openai[-_\s]?evals?|evals\.elsuite)\b/iu],
    ["langsmith", /\blangsmith\b/iu],
    ["braintrust", /\bbraintrust\b/iu],
    ["custom_red_team", /\b(red[-_\s]?team|adversarial|jailbreak|prompt[-_\s]?injection)\b/iu]
  ];
  return frameworks.find(([, pattern]) => pattern.test(text))?.[0];
}

function countAiEvalDatasetEntries(value: unknown, fields: RuntimeField[]): number {
  const counts: number[] = [];
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (!/(tests?|scenarios?|cases?|prompts?|probes?|attacks?|datasets?)$/iu.test(key)) continue;
      if (Array.isArray(item)) counts.push(item.length);
      if (item && typeof item === "object" && !Array.isArray(item)) counts.push(Object.keys(item as Record<string, unknown>).length);
    }
  }

  const prefixes = new Set<string>();
  for (const field of fields) {
    const match = field.path.match(/(?:^|\.)(tests?|scenarios?|cases?|prompts?|probes?|attacks?|datasets?)\.(\d+|[A-Za-z][\w-]*)/u);
    if (match?.[1] && match[2]) prefixes.add(`${match[1]}.${match[2]}`);
  }
  if (prefixes.size > 0) counts.push(prefixes.size);
  return Math.max(0, ...counts);
}

function hasAiEvalDatasetSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /(?:^|\.)(tests?|scenarios?|cases?|prompts?|probes?|attacks?|datasets?)(?:\.|$)/iu.test(field.path));
}

function hasAiEvalLiveExecutionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (/(^|\.)(dry_run|dryrun|mock|simulate|simulation|offline)$/iu.test(field.path)) return disabledConfigValue(field.value);
    return /\b(live|execute|run[_\s-]?agent|invoke[_\s-]?agent|call[_\s-]?agent|call[_\s-]?tools?|execute[_\s-]?tools?|real[_\s-]?tools?|production[_\s-]?run)\b/iu.test(
      text
    ) && truthyConfigValue(field.value);
  });
}

function hasAiEvalAdversarialSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(red[-_\s]?team|adversarial|jailbreak|prompt[_\s-]?injection|instruction[_\s-]?override|attack|malicious|unsafe|bypass|exfiltrat|data[_\s-]?leak|tool[_\s-]?misuse)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAiEvalUntrustedPromptSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|chat|inbound|external|public|web[_-]?page|browser[_-]?output)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAiEvalAgentInvocationSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(agent|assistant|bot|autogen|crew|langgraph|codex|claude|run[_\s-]?agent|invoke[_\s-]?agent|target[_\s-]?agent|live[_\s-]?agent)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function collectAiEvalToolAuthorityCategories(fields: RuntimeField[]): string[] {
  const categories = new Set<string>();
  for (const field of fields) {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/\b(tool|tools|function|function_call|mcp|connector|capability)\b/iu.test(text)) categories.add("tool_call");
    if (/\b(browser|playwright|puppeteer|web[_\s-]?agent|click|form|navigate)\b/iu.test(text)) categories.add("browser_action");
    if (/\b(database|db|sql|query|support_db|warehouse)\b/iu.test(text)) categories.add("database_access");
    if (/(?:^|[_\W])(vault|secret|secrets|secret[_\s-]?manager|key[_\s-]?vault|credential)(?:[_\W]|$)/iu.test(text)) {
      categories.add("secret_manager_access");
    }
    if (/\b(slack|email|webhook|message|ticket|issue|comment|reply|send|post|publish)\b/iu.test(text)) categories.add("external_response");
    if (/(?:^|[_\W])(memory|remember|store|persist|session[_\s-]?state)(?:[_\W]|$)/iu.test(text)) categories.add("memory_write");
    if (/\b(shell|bash|command|exec|terminal|python|node|subprocess)\b/iu.test(text)) categories.add("shell_execution");
    if (/\b(filesystem|file[_\s-]?write|workspace|repo|repository|github|gitlab|pull[_\s-]?request)\b/iu.test(text)) {
      categories.add("repo_or_filesystem_write");
    }
  }
  return [...categories].sort((a, b) => a.localeCompare(b));
}

function hasAiEvalToolInvocationSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(call[_\s-]?tools?|invoke[_\s-]?tools?|tool[_\s-]?access|function[_\s-]?call|mcp|browser|database|vault|shell|filesystem|write[_\s-]?tool)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAiEvalWriteAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.some((category) => ["database_access", "external_response", "repo_or_filesystem_write", "shell_execution"].includes(category)) ||
    fields.some((field) =>
      /\b(write|update|create|delete|reply|respond|send|post|publish|comment|commit|push|merge|deploy|remember|persist|approve|close|assign)\b/iu.test(
        `${field.path} ${fieldValueText(field)}`
      )
    );
}

function hasAiEvalExternalWriteAuthoritySignal(fields: RuntimeField[], categories: string[]): boolean {
  return categories.includes("external_response") ||
    fields.some((field) => /\b(slack|email|webhook|send|post|publish|reply|respond|ticket|issue|external)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasAiEvalRemoteTargetSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const values = Array.isArray(field.value) ? field.value.map(String) : [String(field.value ?? "")];
    return values.some((value) => Boolean(parseRemoteHttpUrl(value)));
  });
}

function hasAiEvalProductionTargetSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(prod|production|live|customer[_\s-]?support|customer[_\s-]?success|billing|payment|admin|internal[_\s-]?ops|real[_\s-]?users?)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAiEvalOutputRetentionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(results?|outputs?|traces?|logs?|history|store|persist|artifact|report|dataset|record|recording|retention)\b/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function hasAiEvalSecretSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(secret|token|credential|api[_-]?key|password|vault|key[_\s-]?vault|authorization)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function hasAiEvalSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|order|record|case|profile|note|incident)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAiEvalPiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAiEvalApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|review|human[_-]?in[_-]?the[_-]?loop/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isAiEvalSecurityField(fieldPath: string): boolean {
  if (/(^|\.)(vars?|assert|assertions?|expected|value)\./iu.test(fieldPath)) return false;
  return /framework|provider|eval|evaluation|redteam|red[_-]?team|scenario|case|dataset|prompt|probe|attack|jailbreak|injection|target|agent|assistant|tool|mcp|function|browser|database|secret|memory|input|source|customer|ticket|email|chat|write|send|reply|approval|auth|token|credential|env|scope|permission|result|output|trace|log|retention|endpoint|url|host|production|live/iu.test(
    fieldPath
  );
}

function classifyAiTelemetryConfig(value: unknown, filePath: string): AiTelemetryPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferAiTelemetryProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const remote = classifyAiTelemetryRemote(fields, provider);
  const envKeys = collectEnvKeyNamesFromConfig(value);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);
  const capturesPrompts = hasTelemetryCaptureSignal(fields, /\b(prompt|prompts|input|inputs|message|messages|conversation|chat)\b/iu);
  const capturesCompletions = hasTelemetryCaptureSignal(fields, /\b(completion|completions|response|responses|output|outputs|generation|generations)\b/iu);
  const capturesToolOutputs = hasTelemetryCaptureSignal(
    fields,
    /(?:^|[_\W])(tool[_\s-]?outputs?|tools?|function[_\s-]?outputs?|functions?|mcp|command[_\s-]?outputs?|span|observation)(?:[_\W]|$)/iu
  );
  const capturesRetrieval = hasTelemetryCaptureSignal(
    fields,
    /(?:^|[_\W])(retrieval[_\s-]?context|retrieval|retrieved|rag|documents?|context|vector|embedding)(?:[_\W]|$)/iu
  );
  const capturesMemory = hasTelemetryCaptureSignal(fields, /\b(memory|memories|session|state|history|transcript|trace)\b/iu);
  const secretCapture = hasTelemetrySecretCaptureSignal(fields);
  const piiCapture = fields.some((field) => /\b(pii|email|phone|address|ssn|passport|customer|client|ticket|support)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
  const sensitiveCapture =
    capturesPrompts ||
    capturesCompletions ||
    capturesToolOutputs ||
    capturesRetrieval ||
    capturesMemory ||
    secretCapture ||
    piiCapture;

  return {
    ai_telemetry_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAiTelemetrySecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    ai_telemetry_provider: provider,
    ai_telemetry_export_enabled: remote.remote || hasTelemetryEnabledSignal(fields),
    ai_telemetry_remote_export: remote.remote,
    ai_telemetry_destination_redacted: remote.destinationCount > 0,
    ai_telemetry_remote_destination_count: remote.destinationCount,
    ai_telemetry_remote_destination_kinds: remote.destinationKinds,
    ai_telemetry_captures_prompts: capturesPrompts,
    ai_telemetry_captures_completions: capturesCompletions,
    ai_telemetry_captures_tool_outputs: capturesToolOutputs,
    ai_telemetry_captures_retrieval: capturesRetrieval,
    ai_telemetry_captures_memory: capturesMemory,
    ai_telemetry_sensitive_capture: sensitiveCapture,
    ai_telemetry_pii_capture: piiCapture,
    ai_telemetry_secret_capture_signal: secretCapture,
    ai_telemetry_redaction_disabled: hasTelemetryRedactionDisabledSignal(fields),
    ai_telemetry_retention_enabled: hasTelemetryRetentionSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferAiTelemetryProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["langsmith", /\blangsmith\b|\bsmith\.langchain\b/iu],
    ["langfuse", /\blangfuse\b/iu],
    ["helicone", /\bhelicone\b/iu],
    ["braintrust", /\bbraintrust\b/iu],
    ["traceloop", /\btraceloop\b/iu],
    ["phoenix", /\bphoenix\b/iu],
    ["arize", /\barize\b/iu],
    ["opentelemetry", /\b(open[_\s-]?telemetry|otel|otlp)\b/iu],
    ["honeycomb", /\bhoneycomb\b/iu],
    ["datadog", /\bdatadog\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifyAiTelemetryRemote(
  fields: RuntimeField[],
  provider: string | undefined
): { remote: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  const managedProviders = new Set(["langsmith", "langfuse", "helicone", "braintrust", "traceloop", "arize", "honeycomb", "datadog"]);
  if (provider && managedProviders.has(provider)) {
    destinationKinds.add("managed_ai_observability");
    destinationCount += 1;
  }
  for (const field of fields) {
    const values = Array.isArray(field.value) ? field.value.map(String) : [String(field.value ?? "")];
    for (const value of values) {
      if (parseRemoteHttpUrl(value)) {
        destinationKinds.add("http_endpoint");
        destinationCount += 1;
      }
    }
    if (/(^|\.)(endpoint|url|uri|host|dsn|base_url|exporter|otlp_endpoint)$/iu.test(field.path)) {
      const text = values.join(" ");
      if (/\b(api|cloud|trace|otel|otlp|langsmith|langfuse|helicone|braintrust|phoenix|arize|honeycomb|datadog)\b/iu.test(text)) {
        destinationKinds.add("configured_endpoint");
        destinationCount += 1;
      }
    }
  }
  return {
    remote: destinationCount > 0,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b))
  };
}

function hasTelemetryCaptureSignal(fields: RuntimeField[], pattern: RegExp): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    if (!pattern.test(text)) return false;
    if (/redact|mask|scrub|sanitize|exclude|drop|deny/iu.test(field.path)) return false;
    return truthyConfigValue(field.value) || /capture|include|record|log|trace|store|full|payload/iu.test(text);
  });
}

function hasTelemetryEnabledSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /(^|\.)(enabled|tracing|telemetry|observability|export|remote)$/iu.test(field.path) && truthyConfigValue(field.value));
}

function hasTelemetrySecretCaptureSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    return /\b(secret|token|api[_-]?key|credential|authorization|password|cookie)\b/iu.test(text) && truthyConfigValue(field.value);
  });
}

function hasTelemetryRedactionDisabledSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`.toLowerCase();
    if (/(redact|redaction|mask|masking|scrub|sanitize|pii_filter|secret_filter)/iu.test(field.path)) {
      return /false|off|disabled|disable|none|raw|full/iu.test(fieldValueText(field));
    }
    return /\b(disable_redaction|redaction_disabled|raw_traces|raw_payloads|capture_full_payloads)\b/iu.test(text) && truthyConfigValue(field.value);
  });
}

function hasTelemetryRetentionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /retention|store|persist|dataset|history|trace_archive|ttl|days/iu.test(field.path) && truthyConfigValue(field.value));
}

function isAiTelemetrySecurityField(fieldPath: string): boolean {
  return /provider|endpoint|url|uri|host|dsn|api[_-]?key|token|secret|credential|auth|env|export|remote|trace|span|prompt|input|output|completion|message|tool|retrieval|rag|context|memory|redact|mask|pii|retention|store|persist|sample|project/iu.test(
    fieldPath
  );
}

function classifyAgentMemoryStoreConfig(value: unknown, filePath: string): AgentMemoryStorePosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferAgentMemoryStoreProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const remote = classifyAgentMemoryStoreRemote(fields, provider);
  const envKeys = uniqueStrings([
    ...collectEnvKeyNamesFromConfig(value).filter(isLikelyEnvKeyName),
    ...extractEnvironmentReferenceKeys(stringValues)
  ]);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);

  return {
    agent_memory_store_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isAgentMemoryStoreSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    agent_memory_store_provider: provider,
    agent_memory_store_remote: remote.remote,
    agent_memory_store_destination_redacted: remote.destinationCount > 0,
    agent_memory_store_destination_count: remote.destinationCount,
    agent_memory_store_destination_kinds: remote.destinationKinds,
    agent_memory_store_persistent: hasAgentMemoryStorePersistentSignal(fields),
    agent_memory_store_shared: hasAgentMemoryStoreSharedSignal(fields),
    agent_memory_store_write_enabled: hasAgentMemoryStoreWriteSignal(fields),
    agent_memory_store_sync_enabled: hasAgentMemoryStoreSyncSignal(fields),
    agent_memory_store_untrusted_write: hasAgentMemoryStoreUntrustedWriteSignal(fields),
    agent_memory_store_tool_output_capture: hasAgentMemoryStoreToolOutputSignal(fields),
    agent_memory_store_prompt_capture: hasAgentMemoryStorePromptCaptureSignal(fields),
    agent_memory_store_retrieval_capture: hasAgentMemoryStoreRetrievalCaptureSignal(fields),
    agent_memory_store_secret_capture: hasAgentMemoryStoreSecretCaptureSignal(fields),
    agent_memory_store_output_replay_enabled: hasAgentMemoryStoreReplaySignal(fields),
    agent_memory_store_sensitive_data: hasAgentMemoryStoreSensitiveDataSignal(fields),
    agent_memory_store_pii_data: hasAgentMemoryStorePiiDataSignal(fields),
    agent_memory_store_namespace_redacted: hasAgentMemoryStoreNamespaceSignal(fields),
    agent_memory_store_approval_required: hasAgentMemoryStoreApprovalRequiredSignal(fields),
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function inferAgentMemoryStoreProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["langgraph_checkpointer", /\b(langgraph|checkpointer|checkpoint)\b/iu],
    ["redis", /\b(redis|rediss|upstash)\b/iu],
    ["postgres", /\b(postgres|postgresql|pgvector)\b/iu],
    ["sqlite", /\bsqlite\b/iu],
    ["zep", /\bzep\b/iu],
    ["mem0", /\bmem0\b/iu],
    ["dynamodb", /\bdynamodb\b/iu],
    ["mongodb", /\b(mongodb|mongo)\b/iu],
    ["chroma", /\b(chroma|chromadb)\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifyAgentMemoryStoreRemote(
  fields: RuntimeField[],
  provider: string | undefined
): { remote: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  const managedProviders = new Set(["zep", "mem0"]);
  if (provider && managedProviders.has(provider)) {
    destinationKinds.add("managed_memory_service");
    destinationCount += 1;
  }

  for (const field of fields) {
    const values = Array.isArray(field.value) ? field.value.map(String) : [String(field.value ?? "")];
    for (const value of values) {
      const destination = parseRemoteMemoryStoreDestination(value);
      if (destination) {
        destinationKinds.add(destination.kind);
        destinationCount += 1;
      }
    }
    if (/(^|\.)(host|hostname|server|endpoint|dsn|connection|connection_string|url|uri|redis_url|database_url)$/iu.test(field.path)) {
      const text = values.join(" ");
      if (looksLikeRemoteMemoryStoreHost(text)) {
        destinationKinds.add("memory_store_host");
        destinationCount += 1;
      }
    }
  }

  return {
    remote: destinationCount > 0,
    destinationCount,
    destinationKinds: [...destinationKinds].sort((a, b) => a.localeCompare(b))
  };
}

function parseRemoteMemoryStoreDestination(value: string): { kind: string } | undefined {
  try {
    const parsed = new URL(value);
    const protocol = parsed.protocol.replace(":", "").toLowerCase();
    if (!/^(https?|redis|rediss|postgres|postgresql|mongodb|mongodb\+srv)$/iu.test(protocol)) return undefined;
    if (isLocalHost(parsed.hostname.toLowerCase())) return undefined;
    return { kind: protocol === "http" ? "plaintext_memory_endpoint" : "memory_store_endpoint" };
  } catch {
    return undefined;
  }
}

function looksLikeRemoteMemoryStoreHost(value: string): boolean {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || trimmed.startsWith("${")) return false;
  if (isLocalHost(trimmed)) return false;
  return /\b(upstash|redis|redislabs|memory|checkpoint|checkpointer|zep|mem0|mongodb|rds\.amazonaws\.com|supabase|neon\.tech|db\.|database)\b/iu.test(
    trimmed
  ) || /^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?$/iu.test(trimmed);
}

function hasAgentMemoryStorePersistentSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(persistent|persist|persistence|long[_\s-]?term|durable|retention|ttl|checkpoint|checkpointer|cross[_\s-]?session|save|store)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentMemoryStoreSharedSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /shared|global|team|workspace|cross[_\s-]?agents?|multi[_\s-]?agents?|user[_\s-]?profile|tenant|organization|org[_\s-]?wide/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentMemoryStoreWriteSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const text = `${field.path} ${fieldValueText(field)}`;
    return /\b(write|read[_\s-]?write|append|upsert|insert|update|save|store|remember|persist|checkpoint|mutable|writable)\b/iu.test(text) &&
      truthyConfigValue(field.value);
  });
}

function hasAgentMemoryStoreSyncSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(sync|auto[_\s-]?sync|background[_\s-]?sync|flush|replicate|mirror|export|import)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentMemoryStoreUntrustedWriteSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(untrusted|user|customer|client|ticket|support|issue|comment|message|prompt|retrieved|rag|document|email|chat|inbound|external|public|browser[_-]?output|tool[_-]?output)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentMemoryStoreToolOutputSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(tool[_\s-]?outputs?|function[_\s-]?outputs?|mcp|observation|command[_\s-]?outputs?|browser[_\s-]?outputs?)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentMemoryStorePromptCaptureSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(prompt|prompts|system|developer|input|inputs|message|messages|conversation|chat|transcript)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentMemoryStoreRetrievalCaptureSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(retrieval[_\s-]?context|retrieval|retrieved|rag|documents?|vector|embedding|knowledge)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentMemoryStoreSecretCaptureSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(secrets?|token|api[_-]?key|credential|authorization|password|cookie|vault)\b/iu.test(`${field.path} ${fieldValueText(field)}`)
  );
}

function hasAgentMemoryStoreReplaySignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(replay|recall|hydrate|inject|load[_\s-]?into[_\s-]?prompt|prepend|context[_\s-]?window|system[_\s-]?prompt|future[_\s-]?runs?|next[_\s-]?run)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    ) && truthyConfigValue(field.value)
  );
}

function hasAgentMemoryStoreSensitiveDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|billing|payment|order|record|case|profile|note|incident)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentMemoryStorePiiDataSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(?:^|[_\W])(pii|email|phone|address|ssn|passport|dob|date[_\s-]?of[_\s-]?birth|customer[_-]?id|user[_-]?id|account[_-]?id)(?:[_\W]|$)/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasAgentMemoryStoreNamespaceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /(^|\.)(namespace|namespaces|collection|collections|key_prefix|prefix|table|tables|database|index|indexes|thread_id|user_id|tenant_id)$/iu.test(
      field.path
    )
  );
}

function hasAgentMemoryStoreApprovalRequiredSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /approval|required[_-]?approval|human[_-]?approval|confirm|confirmation|review|human[_-]?in[_-]?the[_-]?loop/iu.test(field.path) &&
    truthyConfigValue(field.value)
  );
}

function isAgentMemoryStoreSecurityField(fieldPath: string): boolean {
  return /provider|memory|memories|store|persistence|persistent|retention|ttl|checkpoint|checkpointer|thread|session|state|namespace|collection|prefix|table|database|index|shared|global|agent|tool|output|prompt|retrieval|rag|source|input|customer|ticket|email|chat|secret|token|credential|auth|env|endpoint|url|uri|host|dsn|connection|write|sync|replay|recall|inject|approval|pii|sensitive/iu.test(
    fieldPath
  );
}

function classifyRagConnectorConfig(value: unknown, filePath: string): RagConnectorPosture {
  const fields = flattenRuntimeFields(value);
  const stringValues = collectFieldStringValues(fields);
  const provider = inferVectorStoreProvider([filePath, ...fields.map((field) => field.path), ...stringValues]);
  const remote = classifyVectorStoreRemote(fields, provider);
  const envKeys = collectEnvKeyNamesFromConfig(value);
  const secretRefKeys = extractSecretReferenceKeys(stringValues);
  const writeEnabled = hasVectorWriteSignal(fields);
  const syncEnabled = hasVectorSyncSignal(fields);
  const untrustedSources = hasVectorUntrustedSourceSignal(fields);
  const sensitiveCollection = hasVectorSensitiveCollectionSignal(fields);
  const piiCollection = hasVectorPiiCollectionSignal(fields);
  const namespaceRedacted = fields.some((field) => /(^|\.)(collection|collections|namespace|index|indexes|table|bucket|corpus|dataset)$/iu.test(field.path));

  return {
    rag_connector_fields: fields
      .map((field) => field.path)
      .filter((fieldPath) => isRagConnectorSecurityField(fieldPath))
      .sort((a, b) => a.localeCompare(b)),
    vector_store: true,
    vector_store_provider: provider,
    vector_store_remote: remote.remote,
    vector_store_destination_redacted: remote.destinationCount > 0,
    vector_store_remote_destination_count: remote.destinationCount,
    vector_store_remote_destination_kinds: remote.destinationKinds,
    vector_store_write_enabled: writeEnabled,
    vector_store_sync_enabled: syncEnabled,
    vector_store_ingests_untrusted_sources: untrustedSources,
    vector_store_sensitive_collection: sensitiveCollection,
    vector_store_pii_collection: piiCollection,
    vector_store_namespace_redacted: namespaceRedacted,
    env_key_names: envKeys,
    secret_ref_key_names: secretRefKeys
  };
}

function collectFieldStringValues(fields: RuntimeField[]): string[] {
  const values = new Set<string>();
  for (const field of fields) {
    if (typeof field.value === "string") values.add(field.value);
    if (Array.isArray(field.value)) {
      for (const item of field.value) values.add(String(item));
    }
  }
  return [...values].sort((a, b) => a.localeCompare(b));
}

function inferVectorStoreProvider(candidates: string[]): string | undefined {
  const text = candidates.join(" ").toLowerCase();
  const providers: Array<[string, RegExp]> = [
    ["pinecone", /\bpinecone\b/iu],
    ["qdrant", /\bqdrant\b/iu],
    ["weaviate", /\bweaviate\b/iu],
    ["chroma", /\b(chroma|chromadb)\b/iu],
    ["supabase", /\bsupabase\b/iu],
    ["pgvector", /\bpgvector\b/iu],
    ["milvus", /\bmilvus\b/iu],
    ["redis", /\bredis\b/iu],
    ["elasticsearch", /\belasticsearch\b/iu],
    ["opensearch", /\bopensearch\b/iu],
    ["azure_ai_search", /\b(azure[_\s-]?ai[_\s-]?search|azure[_\s-]?search)\b/iu],
    ["vespa", /\bvespa\b/iu]
  ];
  return providers.find(([, pattern]) => pattern.test(text))?.[0];
}

function classifyVectorStoreRemote(
  fields: RuntimeField[],
  provider: string | undefined
): { remote: boolean; destinationCount: number; destinationKinds: string[] } {
  const destinationKinds = new Set<string>();
  let destinationCount = 0;
  const managedProviders = new Set(["pinecone", "supabase", "azure_ai_search"]);
  if (provider && managedProviders.has(provider)) {
    destinationKinds.add("managed_vector_db");
    destinationCount += 1;
  }

  for (const field of fields) {
    const values = Array.isArray(field.value) ? field.value.map(String) : [String(field.value ?? "")];
    for (const value of values) {
      const remoteUrl = parseRemoteHttpUrl(value);
      if (remoteUrl) {
        destinationKinds.add("http_endpoint");
        destinationCount += 1;
      }
    }
    if (/(^|\.)(endpoint|url|uri|host|dsn|connection|string)$/iu.test(field.path)) {
      const text = values.join(" ");
      if (/\b(cloud|api|svc|service|cluster|pinecone|qdrant|weaviate|supabase|azure|elastic|opensearch)\b/iu.test(text)) {
        destinationKinds.add("configured_endpoint");
        destinationCount += 1;
      }
    }
  }

  const kinds = [...destinationKinds].sort((a, b) => a.localeCompare(b));
  return {
    remote: destinationCount > 0,
    destinationCount,
    destinationKinds: kinds
  };
}

function parseRemoteHttpUrl(value: string): URL | undefined {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
    if (isLocalHost(parsed.hostname.toLowerCase())) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

function hasVectorWriteSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => {
    const pathMatch = /(^|\.)(write|writable|read_write|upsert|upserts|insert|ingest|indexing|mutate|mutable|update|delete|sync|allow_updates|allow_deletes)$/iu.test(
      field.path
    );
    const valueText = fieldValueText(field).toLowerCase();
    return (pathMatch && truthyConfigValue(field.value)) || /\b(read_write|write|writable|upsert|insert|ingest|sync|mutable)\b/iu.test(valueText);
  });
}

function hasVectorSyncSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /(^|\.)sync(\.|$)|ingest_on_startup|auto_ingest|auto_sync/iu.test(field.path) && truthyConfigValue(field.value));
}

function hasVectorUntrustedSourceSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(user|customer|client|ticket|support|issue|comment|message|email|slack|web|browser|public|external|retrieved|document|note)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasVectorSensitiveCollectionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) =>
    /\b(customer|client|ticket|support|internal|confidential|private|proprietary|sensitive|account|record|case)\b/iu.test(
      `${field.path} ${fieldValueText(field)}`
    )
  );
}

function hasVectorPiiCollectionSignal(fields: RuntimeField[]): boolean {
  return fields.some((field) => /\b(pii|email|phone|address|ssn|passport)\b/iu.test(`${field.path} ${fieldValueText(field)}`));
}

function fieldValueText(field: RuntimeField): string {
  if (Array.isArray(field.value)) return field.value.map(String).join(" ");
  if (typeof field.value === "string" || typeof field.value === "number" || typeof field.value === "boolean") {
    return String(field.value);
  }
  return "";
}

function truthyConfigValue(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") return !/^(false|no|off|disabled|disable|none|readonly|read_only|read-only|0)$/iu.test(value.trim());
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value);
}

function isRagConnectorSecurityField(fieldPath: string): boolean {
  return /provider|endpoint|url|uri|host|dsn|connection|secret|token|api[_-]?key|credential|auth|env|collection|namespace|index|table|bucket|corpus|dataset|write|upsert|insert|ingest|sync|source|document|embedding|vector/iu.test(
    fieldPath
  );
}

function isCursorRulePath(lowerPath: string): boolean {
  return lowerPath.includes(".cursor/rules/");
}

function classifyCursorRule(
  file: WalkedFile,
  content: string,
  surfaces: DetectedSurfaces
): CursorRuleClassification {
  const frontmatter = parseCursorRuleFrontmatter(content);
  const parsed = frontmatter?.parsed;
  const globs = parsed ? cursorRuleGlobs(parsed) : [];
  const alwaysApply = parsed ? cursorRuleBoolean(parsed, "alwaysApply") : undefined;
  const descriptionPresent = parsed ? typeof parsed.description === "string" && parsed.description.trim().length > 0 : false;
  const applicationMode = cursorRuleApplicationMode(alwaysApply, globs, descriptionPresent);
  const scopeKinds = cursorRuleScopeKinds(globs);
  const appliesBroadly = alwaysApply === true || scopeKinds.includes("all_files") || scopeKinds.includes("workspace");

  if (frontmatter?.parseFailed) {
    addDiagnostic(surfaces, file, {
      code: "CURSOR_RULE_FRONTMATTER_PARSE_FAILED",
      parser: "cursor-rule",
      reason: "Cursor rule frontmatter could not be parsed and was skipped. Raw rule content was redacted."
    });
  }

  return {
    analyzedContent: frontmatter?.body ?? content,
    metadata: {
      cursor_rule: true,
      cursor_rule_frontmatter_present: frontmatter !== undefined,
      cursor_rule_frontmatter_parsed: Boolean(parsed),
      cursor_rule_body_redacted: true,
      cursor_rule_description_present: descriptionPresent,
      cursor_rule_always_apply: alwaysApply === true,
      cursor_rule_application_mode: applicationMode,
      cursor_rule_glob_count: globs.length,
      cursor_rule_glob_scope_kinds: scopeKinds,
      cursor_rule_applies_broadly: appliesBroadly
    }
  };
}

function parseCursorRuleFrontmatter(
  content: string
): { parsed?: Record<string, unknown>; body: string; parseFailed: boolean } | undefined {
  const normalized = content.replaceAll("\r\n", "\n");
  if (!normalized.startsWith("---\n")) return undefined;
  const endIndex = normalized.indexOf("\n---", 4);
  if (endIndex === -1) return { body: normalized, parseFailed: true };
  const frontmatterText = normalized.slice(4, endIndex).trim();
  const bodyStart = normalized.indexOf("\n", endIndex + 4);
  const body = bodyStart === -1 ? "" : normalized.slice(bodyStart + 1);
  try {
    const parsed = YAML.parse(frontmatterText);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { body, parseFailed: true };
    }
    return { parsed: parsed as Record<string, unknown>, body, parseFailed: false };
  } catch {
    return { body, parseFailed: true };
  }
}

function cursorRuleBoolean(frontmatter: Record<string, unknown>, key: string): boolean | undefined {
  const value = frontmatter[key];
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  return undefined;
}

function cursorRuleGlobs(frontmatter: Record<string, unknown>): string[] {
  const raw = frontmatter.globs;
  const values: string[] = [];
  if (typeof raw === "string") {
    values.push(...raw.split(",").map((value) => value.trim()));
  } else if (Array.isArray(raw)) {
    for (const value of raw) {
      if (typeof value === "string") values.push(value.trim());
    }
  }
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function cursorRuleApplicationMode(
  alwaysApply: boolean | undefined,
  globs: string[],
  descriptionPresent: boolean
): string {
  if (alwaysApply === true) return "always";
  if (globs.length > 0) return "auto_attached";
  if (descriptionPresent) return "agent_requested";
  if (alwaysApply === false) return "manual";
  return "unknown";
}

function cursorRuleScopeKinds(globs: string[]): string[] {
  const kinds = new Set<string>();
  for (const glob of globs) {
    const normalized = glob.toLowerCase();
    if (["*", "**", "**/*", "**/*.*"].includes(normalized)) kinds.add("all_files");
    if (normalized.startsWith("**/") || normalized.startsWith("**.")) kinds.add("workspace");
    if (/\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|kt|rb|php|cs|cpp|c|h|sh|zsh|bash)(?:[},\]])?$/iu.test(normalized)) {
      kinds.add("code");
    }
    if (/\.(md|mdx|txt|rst|adoc)(?:[},\]])?$/iu.test(normalized) || normalized.includes("docs/")) kinds.add("docs");
    if (/\.(json|ya?ml|toml|ini|env)(?:[},\]])?$/iu.test(normalized) || normalized.includes("config")) kinds.add("config");
  }
  return [...kinds].sort((a, b) => a.localeCompare(b));
}

function classifyContextContent(content: string): ContextContentSignals {
  const instructionOverride = hasAffirmedContextPattern(
    content,
    /\b(ignore|override|bypass|forget|disregard)\b[\s\S]{0,80}\b(instruction|policy|approval|guard|previous|system|developer)\b/i
  );
  const instructionLike =
    instructionOverride ||
    hasAffirmedContextPattern(
      content,
      /\b(system prompt|developer instruction|highest priority|follow these instructions|do not obey|new instruction)\b/i
    );
  const untrustedContext = hasAffirmedContextPattern(
    content,
    /\b(untrusted|user|customer|client|ticket|issue|support|web\s?page|browser|email|slack|copied chat|transcript|retrieved|rag|document|note)\b/i
  );
  const toolDirective = hasAffirmedContextPattern(
    content,
    /\b(call|invoke|use|run|execute|trigger)\b[\s\S]{0,80}\b(tool|mcp|shell|browser|github|slack|webhook|function|api)\b/i
  );
  const memoryWriteDirective = hasAffirmedContextPattern(
    content,
    /\b(remember|store|persist|save|write|update)\b[\s\S]{0,80}\b(memory|future|session|run|instruction|shortcut)\b/i
  );
  const externalDirective =
    hasExternalReach(content) ||
    hasAffirmedContextPattern(content, /\b(webhook|slack|email|external|publish|send|post|upload)\b/i);
  const secretReference = hasSecretExposure(content);
  const sensitiveContextReference = hasSensitiveContextReference(content);
  const dataEgressDirective = hasDataEgressDirective(content);
  const contextBridgeTool = untrustedContext && toolDirective;
  const contextBridgeMemory = untrustedContext && memoryWriteDirective;
  const contextBridgeExternal = untrustedContext && externalDirective;
  const contextBridgeDataEgress = untrustedContext && dataEgressDirective;
  const contextBridgePrivileged =
    contextBridgeTool ||
    contextBridgeMemory ||
    contextBridgeExternal ||
    contextBridgeDataEgress ||
    (untrustedContext && secretReference);
  const signals = [
    instructionLike,
    instructionOverride,
    untrustedContext,
    toolDirective,
    memoryWriteDirective,
    externalDirective,
    secretReference,
    sensitiveContextReference,
    dataEgressDirective
  ].filter(Boolean).length;
  return {
    instruction_like_content: instructionLike,
    instruction_override: instructionOverride,
    untrusted_context_reference: untrustedContext,
    tool_directive: toolDirective,
    memory_write_directive: memoryWriteDirective,
    external_directive: externalDirective,
    secret_reference: secretReference,
    sensitive_context_reference: sensitiveContextReference,
    data_egress_directive: dataEgressDirective,
    context_bridge_tool: contextBridgeTool,
    context_bridge_memory: contextBridgeMemory,
    context_bridge_external: contextBridgeExternal,
    context_bridge_data_egress: contextBridgeDataEgress,
    context_bridge_privileged: contextBridgePrivileged,
    content_signal_count: signals
  };
}

function classifyModelVisibleToolDescription(description: string): Record<string, unknown> {
  const analyzed = description.trim().length > 0;
  const signals = classifyContextContent(description);
  return {
    model_visible_description_analyzed: analyzed,
    model_visible_description_redacted: analyzed,
    model_visible_description_instruction_like_content: signals.instruction_like_content,
    model_visible_description_instruction_override: signals.instruction_override,
    model_visible_description_untrusted_context_reference: signals.untrusted_context_reference,
    model_visible_description_tool_directive: signals.tool_directive,
    model_visible_description_memory_write_directive: signals.memory_write_directive,
    model_visible_description_external_directive: signals.external_directive,
    model_visible_description_secret_reference: signals.secret_reference,
    model_visible_description_sensitive_context_reference: signals.sensitive_context_reference,
    model_visible_description_data_egress_directive: signals.data_egress_directive,
    model_visible_description_context_bridge_tool: signals.context_bridge_tool,
    model_visible_description_context_bridge_memory: signals.context_bridge_memory,
    model_visible_description_context_bridge_external: signals.context_bridge_external,
    model_visible_description_context_bridge_data_egress: signals.context_bridge_data_egress,
    model_visible_description_context_bridge_privileged: signals.context_bridge_privileged,
    model_visible_description_signal_count: signals.content_signal_count
  };
}

function hasSensitiveContextReference(content: string): boolean {
  return hasAffirmedContextPattern(
    content,
    /\b(internal|confidential|proprietary|private|sensitive|customer|client|ticket|support|account|record|summary|report|document|note|pii|credential|secret|token|api[\s_-]?key)\b/i
  );
}

function hasDataEgressDirective(content: string): boolean {
  const verbThenData = hasAffirmedContextPattern(
    content,
    /\b(send|post|upload|publish|forward|share|copy|exfiltrate)\b[\s\S]{0,140}\b(internal|confidential|proprietary|private|sensitive|customer|client|ticket|support|account|record|summary|report|document|note|data|credential|secret|token|api[\s_-]?key)\b/i
  );
  const dataThenVerb = hasAffirmedContextPattern(
    content,
    /\b(internal|confidential|proprietary|private|sensitive|customer|client|ticket|support|account|record|summary|report|document|note|data|credential|secret|token|api[\s_-]?key)\b[\s\S]{0,140}\b(send|post|upload|publish|forward|share|copy|exfiltrate)\b/i
  );
  const externalTarget = hasAffirmedContextPattern(content, /\b(webhook|slack|email|external|remote|url|api|outside|third[-\s]?party)\b/i);
  return externalTarget && (verbThenData || dataThenVerb);
}

function hasAffirmedContextPattern(content: string, pattern: RegExp): boolean {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const matcher = new RegExp(pattern.source, flags);
  let match: RegExpExecArray | null;
  while ((match = matcher.exec(content)) !== null) {
    if (!isNegatedContextMatch(content, match.index)) return true;
    if (match[0].length === 0) matcher.lastIndex += 1;
  }
  return false;
}

function isNegatedContextMatch(content: string, index: number): boolean {
  const before = content.slice(Math.max(0, index - 120), index);
  const clauseStart = Math.max(before.lastIndexOf("."), before.lastIndexOf("\n"), before.lastIndexOf(";"));
  const clause = before.slice(clauseStart + 1);
  return /\b(do not|don't|dont|must not|should not|cannot|can't|never|not allowed to|not permitted to|forbid(?:s|den)?|prohibit(?:s|ed)?)\b/i.test(
    clause
  );
}

function classifySkillDataFlow(content: string): SkillDataFlowSignals {
  const sources = new Set<string>();
  const retrievedContextInput = /\b(retrieved|retrieval|rag|document|documents|knowledge|context|customer note|web page|webpage)\b/iu.test(
    content
  );
  const toolOutputInput = /\b(tool output|tool result|tool response|command output|browser output|mcp result)\b/iu.test(content);
  const memoryInput = /\b(memory|memories|remembered|session state|stored context)\b/iu.test(content);
  const promptInput = /\b(prompt|instruction|system message|developer message)\b/iu.test(content);
  const externalOutput =
    hasExternalReach(content) || /\b(publish|post|send|upload|webhook|slack|email|external)\b/iu.test(content);
  const localWriteOutput = /\b(write|update|save|modify|append|release notes|file)\b/iu.test(content);

  if (retrievedContextInput) sources.add("retrieved_context");
  if (toolOutputInput) sources.add("tool_output");
  if (memoryInput) sources.add("memory");
  if (promptInput) sources.add("prompt");

  return {
    retrieved_context_input: retrievedContextInput,
    tool_output_input: toolOutputInput,
    memory_input: memoryInput,
    prompt_input: promptInput,
    context_input_sources: [...sources].sort((a, b) => a.localeCompare(b)),
    context_input_count: sources.size,
    external_output: externalOutput,
    local_write_output: localWriteOutput,
    context_bridge_external_output: sources.size > 0 && externalOutput
  };
}

function classifyPromptTemplate(content: string): PromptTemplateSignals {
  const variableNames = extractTemplateVariableNames(content);
  const untrustedVariables = variableNames.filter(isUntrustedTemplateVariable);
  const roleSignals = classifyPromptTemplateRoleSignals(content, untrustedVariables);
  return {
    prompt_template: variableNames.length > 0,
    template_variable_names: variableNames,
    template_variable_count: variableNames.length,
    untrusted_template_variables: untrustedVariables,
    untrusted_template_input: untrustedVariables.length > 0,
    ...roleSignals
  };
}

function extractTemplateVariableNames(content: string): string[] {
  const variables = new Set<string>();
  for (const match of content.matchAll(/\{\{\s*([a-zA-Z_][a-zA-Z0-9_.-]*)\s*\}\}/g)) {
    if (match[1]) variables.add(normalizeTemplateVariableName(match[1]));
  }
  for (const match of content.matchAll(/\$\{\s*([a-zA-Z_][a-zA-Z0-9_.-]*)\s*\}/g)) {
    if (match[1]) variables.add(normalizeTemplateVariableName(match[1]));
  }
  for (const match of content.matchAll(/(?<!\{)\{([a-zA-Z_][a-zA-Z0-9_.-]*)\}(?!\})/g)) {
    if (match[1]) variables.add(normalizeTemplateVariableName(match[1]));
  }

  return [...variables].sort((a, b) => a.localeCompare(b));
}

function classifyPromptTemplateRoleSignals(
  content: string,
  untrustedVariables: string[]
): Pick<
  PromptTemplateSignals,
  | "privileged_prompt_role"
  | "privileged_template_roles"
  | "privileged_role_untrusted_variables"
  | "privileged_role_untrusted_variable_count"
  | "privileged_role_untrusted_template_input"
> {
  const roleSegments = promptRoleSegments(content);
  const privilegedRoles = new Set<string>();
  const privilegedRoleVariables = new Set<string>();
  const untrustedVariableSet = new Set(untrustedVariables);

  for (const segment of roleSegments) {
    privilegedRoles.add(segment.role);
    for (const variableName of extractTemplateVariableNames(segment.text)) {
      if (untrustedVariableSet.has(variableName)) privilegedRoleVariables.add(variableName);
    }
  }

  const variables = [...privilegedRoleVariables].sort((a, b) => a.localeCompare(b));
  return {
    privileged_prompt_role: privilegedRoles.size > 0,
    privileged_template_roles: [...privilegedRoles].sort((a, b) => a.localeCompare(b)),
    privileged_role_untrusted_variables: variables,
    privileged_role_untrusted_variable_count: variables.length,
    privileged_role_untrusted_template_input: variables.length > 0
  };
}

function promptRoleSegments(content: string): Array<{ role: "developer" | "system"; text: string }> {
  const segments: Array<{ role: "developer" | "system"; text: string }> = [];
  let activeRole: "developer" | "system" | undefined;
  let activeLines: string[] = [];

  const flush = (): void => {
    if (activeRole) segments.push({ role: activeRole, text: activeLines.join("\n") });
    activeRole = undefined;
    activeLines = [];
  };

  for (const line of content.split(/\r?\n/u)) {
    const markdownHeading = line.match(/^\s*#{1,6}\s*(system|developer)\b/iu);
    if (markdownHeading?.[1]) {
      flush();
      activeRole = markdownHeading[1].toLowerCase() as "developer" | "system";
      continue;
    }

    const roleLabel = line.match(/^\s*(?:[-*]\s*)?(system|developer|user|assistant|tool|function)\s*:\s*(.*)$/iu);
    if (roleLabel?.[1]) {
      flush();
      const role = roleLabel[1].toLowerCase();
      activeRole = role === "system" || role === "developer" ? role : undefined;
      if (activeRole && roleLabel[2]) activeLines.push(roleLabel[2]);
      continue;
    }

    const yamlRole = line.match(/^\s*(?:-\s*)?role\s*:\s*["']?(system|developer|user|assistant|tool|function)["']?/iu);
    if (yamlRole?.[1]) {
      flush();
      const role = yamlRole[1].toLowerCase();
      activeRole = role === "system" || role === "developer" ? role : undefined;
      continue;
    }

    if (activeRole) activeLines.push(line);
  }
  flush();

  return segments;
}

function classifyPromptTemplateBridge(
  template: PromptTemplateSignals,
  signals: ContextContentSignals
): PromptTemplateBridgeSignals {
  const untrustedTemplateInput = template.untrusted_template_input;
  const bridgeTool = untrustedTemplateInput && signals.tool_directive;
  const bridgeMemory = untrustedTemplateInput && signals.memory_write_directive;
  const bridgeExternal = untrustedTemplateInput && signals.external_directive;
  const bridgeSecret = untrustedTemplateInput && signals.secret_reference;
  return {
    template_bridge_tool: bridgeTool,
    template_bridge_memory: bridgeMemory,
    template_bridge_external: bridgeExternal,
    template_bridge_secret: bridgeSecret,
    template_bridge_privileged: bridgeTool || bridgeMemory || bridgeExternal || bridgeSecret
  };
}

function normalizeTemplateVariableName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "").toLowerCase();
}

function isUntrustedTemplateVariable(name: string): boolean {
  return /\b(user|customer|client|ticket|issue|comment|message|input|query|request|web|page|browser|email|slack|review|pr|pull_request|retrieved|rag|document|context|note)\b/iu.test(
    name.replace(/[._-]/g, " ")
  );
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

function promptActions(signals: ContextContentSignals): ActionType[] {
  const actions = new Set<ActionType>(["read"]);
  if (signals.memory_write_directive) actions.add("remember");
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

async function detectMcpConfig(
  file: WalkedFile,
  text: string | undefined,
  surfaces: DetectedSurfaces,
  projectFilePaths: Set<string>
): Promise<void> {
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
    const plaintextRemoteTransport = externalRemote && server.remoteScheme === "http";
    const encryptedRemoteTransport = externalRemote && server.remoteScheme === "https";
    const secretKeys = [...(server.envKeys ?? []), ...(server.secretRefKeys ?? []), ...(server.authHeaderNames ?? [])];
    const baseActions: ActionType[] = actions.length > 0 ? actions : ["call"];
    const packageRunner = server.packageRunner;
    const localImplementationPaths = server.localCommandPaths ?? [];
    const localImplementationPathsFound = localImplementationPaths.filter((pathRef) => projectFilePaths.has(pathRef));
    const localImplementationPathsMissing = localImplementationPaths.filter((pathRef) => !projectFilePaths.has(pathRef));
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
      secret_exposure: secretKeys.some(isCredentialLikeKeyName),
      reversible: isReversible(signalText),
      reason: "MCP server configuration exposes agent-callable tools and authority.",
      metadata: {
        command_name: server.command ? path.basename(server.command) : undefined,
        args_count: server.args?.length ?? 0,
        transport: server.transport,
        remote: server.remote,
        remote_host: server.remoteHost,
        remote_scheme: server.remoteScheme,
        plaintext_remote_transport: plaintextRemoteTransport,
        encrypted_remote_transport: encryptedRemoteTransport,
        url_redacted: Boolean(server.remote),
        header_names: server.headerNames ?? [],
        auth_header_names: server.authHeaderNames ?? [],
        env_key_names: server.envKeys ?? [],
        secret_ref_key_names: server.secretRefKeys ?? [],
        local_command_paths: localImplementationPaths,
        local_command_path_count: localImplementationPaths.length,
        local_command_paths_found: localImplementationPathsFound,
        local_command_paths_missing: localImplementationPathsMissing,
        local_command_paths_missing_count: localImplementationPathsMissing.length,
        local_command_paths_all_found: localImplementationPaths.length > 0 && localImplementationPathsMissing.length === 0,
        opaque_local_mcp_implementation: localImplementationPaths.length > 0 && localImplementationPathsMissing.length > 0,
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
  const commandSignals = classifyWorkflowRunCommands(collectWorkflowRunCommands(parsed));
  const eventSignals = classifyWorkflowEventInput(triggerNames, parsed, content, commandSignals);
  const untrustedEventPrivilegedBridge =
    eventSignals.untrusted_event_agent_input && (writePermissions || mentionsSecretsContext || commandSignals.agent_package_script_names.length > 0);
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
      mentions_secrets_context: mentionsSecretsContext,
      ...commandSignals,
      ...eventSignals
    }
  });
  surfaces.ci_cd.push({
    ...object,
    untrusted_to_privileged: untrustedEventPrivilegedBridge || isUntrustedToPrivileged(object)
  });
  detectWorkflowAutomation(file, content, triggerNames, {
    actions,
    writePermissions,
    mentionsSecretsContext,
    commandSignals,
    eventSignals,
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
    commandSignals: WorkflowCommandSignals;
    eventSignals: WorkflowEventInputSignals;
    permissions: unknown;
  },
  surfaces: DetectedSurfaces
): void {
  const automationTriggers = triggerNames.filter((trigger) =>
    [
      "discussion_comment",
      "issue_comment",
      "repository_dispatch",
      "schedule",
      "workflow_call",
      "workflow_dispatch",
      "workflow_run"
    ].includes(trigger)
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
      ...workflow.commandSignals,
      ...workflow.eventSignals,
      has_permissions_block: Boolean(workflow.permissions)
    }
  });
  const untrustedEventPrivilegedBridge =
    workflow.eventSignals.untrusted_event_agent_input &&
    (workflow.writePermissions ||
      workflow.mentionsSecretsContext ||
      workflow.commandSignals.agent_package_script_names.length > 0 ||
      actions.some((action) => ["write", "execute", "publish", "send", "delete", "call"].includes(action)));
  surfaces.automations.push({
    ...object,
    untrusted_to_privileged: untrustedEventPrivilegedBridge || isUntrustedToPrivileged(object)
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
    const modelVisibleDescription = classifyModelVisibleToolDescription(definition.description);
    const dataClasses: SurfaceObject["data_classes"] = authority.accepted_data_classes.length > 0
      ? uniqueDataClasses([
          ...(authority.secret_exposure ? ["credential"] : []),
          ...authority.accepted_data_classes
        ] as SurfaceObject["data_classes"])
      : authority.secret_exposure
        ? (["credential"] as SurfaceObject["data_classes"])
        : (["unknown"] as SurfaceObject["data_classes"]);
    const object = createSurfaceObject({
      type: "tool",
      name: definition.name,
      path: file.relativePath,
      data_classes: dataClasses,
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
        accepts_content_like_input: authority.accepts_content_like_input,
        accepts_path_input: authority.accepts_path_input,
        accepts_url_input: authority.accepts_url_input,
        accepts_pii_like_input: authority.accepts_pii_like_input,
        accepts_customer_data_input: authority.accepts_customer_data_input,
        accepted_data_classes: authority.accepted_data_classes,
        external_write: authority.external_write,
        destructive_action: authority.destructive_action,
        read_only_hint: definition.annotations?.readOnlyHint,
        idempotent_hint: definition.annotations?.idempotentHint,
        read_only_hint_conflict: authority.read_only_hint_conflict,
        open_world_authority: authority.open_world_authority,
        open_world_schema: definition.openWorldSchema,
        ...modelVisibleDescription
      }
    });
    surfaces.tools.push({
      ...object,
      untrusted_to_privileged: isUntrustedToPrivileged(object)
    });
  }
}

function annotateToolNameCollisions(surfaces: DetectedSurfaces): void {
  const groups = new Map<string, SurfaceObject[]>();
  for (const tool of surfaces.tools) {
    const name = normalizeCallableName(tool.name);
    if (!name) continue;
    const existing = groups.get(name) ?? [];
    existing.push(tool);
    groups.set(name, existing);
  }

  surfaces.tools = surfaces.tools.map((tool) => {
    const collisionName = normalizeCallableName(tool.name);
    const peers = groups.get(collisionName) ?? [];
    if (peers.length < 2) return tool;

    const authoritySignatures = new Set(peers.map(authoritySignature));
    const hasPrivilegedPeer = peers.some(isPrivilegedToolSurface);
    return {
      ...tool,
      metadata: {
        ...tool.metadata,
        name_collision: true,
        collision_name: collisionName,
        collision_count: peers.length,
        collision_paths: peers.map((peer) => peer.path).sort((a, b) => a.localeCompare(b)),
        collision_trust_levels: [...new Set(peers.map((peer) => peer.trust_level))].sort((a, b) => a.localeCompare(b)),
        collision_authority_mismatch: authoritySignatures.size > 1,
        collision_has_privileged_peer: hasPrivilegedPeer
      }
    };
  });
}

function annotateRuntimeCapabilityReferences(surfaces: DetectedSurfaces): void {
  if (surfaces.runtime_config.length === 0 || surfaces.mcp_servers.length === 0) return;

  surfaces.runtime_config = surfaces.runtime_config.map((runtime) => {
    const allowedTools = stringMetadataArray(runtime.metadata.allowed_tools);
    const referencedMcpServers = referencedMcpServersForRuntime(allowedTools, surfaces.mcp_servers);
    if (referencedMcpServers.length === 0) return runtime;

    const privilegedMcpServers = referencedMcpServers.filter(isPrivilegedMcpServer);
    const secretBackedMcpServers = referencedMcpServers.filter(isSecretBackedMcpServer);
    const hasSecretBackedMcp = secretBackedMcpServers.length > 0;
    const hasPrivilegedMcp = privilegedMcpServers.length > 0;
    const approvalBypass = runtime.metadata.approval_bypass === true;
    const dataClasses = hasSecretBackedMcp ? uniqueDataClasses([...runtime.data_classes, "credential"]) : runtime.data_classes;

    return {
      ...runtime,
      data_classes: dataClasses,
      secret_exposure: runtime.secret_exposure || hasSecretBackedMcp,
      metadata: {
        ...runtime.metadata,
        referenced_mcp_servers: surfaceNames(referencedMcpServers),
        referenced_mcp_count: referencedMcpServers.length,
        referenced_privileged_mcp_servers: surfaceNames(privilegedMcpServers),
        referenced_privileged_mcp_count: privilegedMcpServers.length,
        referenced_secret_backed_mcp_servers: surfaceNames(secretBackedMcpServers),
        referenced_secret_backed_mcp_count: secretBackedMcpServers.length,
        mcp_runtime_bridge: referencedMcpServers.length > 0,
        privileged_mcp_runtime_bridge: hasPrivilegedMcp,
        secret_backed_mcp_runtime_bridge: hasSecretBackedMcp,
        approvalless_privileged_mcp_bridge: approvalBypass && hasPrivilegedMcp,
        approvalless_secret_mcp_bridge: approvalBypass && hasSecretBackedMcp
      }
    };
  });
}

function annotateWorkflowPackageScriptReferences(surfaces: DetectedSurfaces): void {
  const packageScriptTools = surfaces.tools
    .filter((tool) => typeof tool.metadata.script_name === "string")
    .sort((a, b) => a.name.localeCompare(b.name) || a.path.localeCompare(b.path));
  if (packageScriptTools.length === 0) return;

  const annotate = (surface: SurfaceObject): SurfaceObject => {
    const agentScriptNames = stringMetadataArray(surface.metadata.agent_package_script_names);
    if (agentScriptNames.length === 0) return surface;

    const agentScriptNameSet = new Set(agentScriptNames);
    const referencedPackageScripts = packageScriptTools.filter((tool) => agentScriptNameSet.has(String(tool.metadata.script_name)));
    if (referencedPackageScripts.length === 0) return surface;

    const agentPackageScripts = referencedPackageScripts.filter((tool) => isAgentPackageScriptName(String(tool.metadata.script_name)));
    return {
      ...surface,
      metadata: {
        ...surface.metadata,
        referenced_package_scripts: surfaceNames(referencedPackageScripts),
        referenced_package_script_count: referencedPackageScripts.length,
        referenced_agent_package_scripts: surfaceNames(agentPackageScripts),
        referenced_agent_package_script_count: agentPackageScripts.length,
        package_script_bridge: referencedPackageScripts.length > 0,
        agent_package_script_bridge: agentPackageScripts.length > 0
      }
    };
  };

  surfaces.ci_cd = surfaces.ci_cd.map(annotate);
  surfaces.automations = surfaces.automations.map(annotate);
}

function annotateRuntimePackageScriptReferences(surfaces: DetectedSurfaces): void {
  const packageScriptTools = surfaces.tools
    .filter((tool) => typeof tool.metadata.script_name === "string")
    .sort((a, b) => a.name.localeCompare(b.name) || a.path.localeCompare(b.path));
  if (packageScriptTools.length === 0 || surfaces.runtime_config.length === 0) return;

  surfaces.runtime_config = surfaces.runtime_config.map((runtime) => {
    const autoApprovedScriptNames = stringMetadataArray(runtime.metadata.auto_approved_package_script_names);
    if (autoApprovedScriptNames.length === 0) return runtime;

    const autoApprovedScriptNameSet = new Set(autoApprovedScriptNames);
    const referencedPackageScripts = packageScriptTools.filter((tool) =>
      autoApprovedScriptNameSet.has(String(tool.metadata.script_name))
    );
    if (referencedPackageScripts.length === 0) return runtime;

    const releasePackageScripts = referencedPackageScripts.filter((tool) => tool.metadata.release_or_publish === true);
    return {
      ...runtime,
      metadata: {
        ...runtime.metadata,
        referenced_package_scripts: surfaceNames(referencedPackageScripts),
        referenced_package_script_count: referencedPackageScripts.length,
        referenced_auto_approved_package_scripts: surfaceNames(referencedPackageScripts),
        referenced_auto_approved_package_script_count: referencedPackageScripts.length,
        referenced_release_package_scripts: surfaceNames(releasePackageScripts),
        referenced_release_package_script_count: releasePackageScripts.length,
        auto_approved_package_script_bridge: referencedPackageScripts.length > 0,
        auto_approved_release_package_script_bridge: releasePackageScripts.length > 0
      }
    };
  });
}

function annotateContextCallableReferences(
  surfaces: DetectedSurfaces,
  contextContentByPath: Map<string, string>
): void {
  if (contextContentByPath.size === 0) return;

  const toolCandidates = callableCandidates(surfaces.tools, toolAliases);
  const mcpCandidates = callableCandidates(surfaces.mcp_servers, (server) => [server.name]);
  if (toolCandidates.length === 0 && mcpCandidates.length === 0) return;

  const annotate = (surface: SurfaceObject): SurfaceObject => {
    if (isHeuristicSurface(surface)) return surface;
    const content = contextContentByPath.get(surface.path);
    if (!content) return surface;

    const referencedTools = referencedCallableSurfaces(content, toolCandidates);
    const referencedMcpServers = referencedCallableSurfaces(content, mcpCandidates);
    if (referencedTools.length === 0 && referencedMcpServers.length === 0) return surface;

    const privilegedTools = referencedTools.filter(isPrivilegedToolSurface);
    const privilegedMcpServers = referencedMcpServers.filter(isPrivilegedMcpServer);
    const hasPrivilegedReference = privilegedTools.length > 0 || privilegedMcpServers.length > 0;
    return {
      ...surface,
      untrusted_to_privileged: surface.untrusted_to_privileged || hasPrivilegedReference,
      metadata: {
        ...surface.metadata,
        referenced_tools: surfaceNames(referencedTools),
        referenced_tool_count: referencedTools.length,
        referenced_privileged_tools: surfaceNames(privilegedTools),
        referenced_privileged_tool_count: privilegedTools.length,
        referenced_mcp_servers: surfaceNames(referencedMcpServers),
        referenced_mcp_count: referencedMcpServers.length,
        referenced_privileged_mcp_servers: surfaceNames(privilegedMcpServers),
        referenced_privileged_mcp_count: privilegedMcpServers.length,
        explicit_tool_reference: referencedTools.length > 0,
        explicit_mcp_reference: referencedMcpServers.length > 0,
        explicit_callable_reference: referencedTools.length > 0 || referencedMcpServers.length > 0,
        privileged_callable_reference: hasPrivilegedReference
      }
    };
  };

  surfaces.instructions = surfaces.instructions.map(annotate);
  surfaces.skills = surfaces.skills.map(annotate);
  surfaces.prompts = surfaces.prompts.map(annotate);
  surfaces.rag_sources = surfaces.rag_sources.map(annotate);
  surfaces.memory = surfaces.memory.map(annotate);
}

interface CallableCandidate {
  surface: SurfaceObject;
  aliases: string[];
}

function callableCandidates(
  surfaces: SurfaceObject[],
  aliasesForSurface: (surface: SurfaceObject) => Array<string | undefined>
): CallableCandidate[] {
  return surfaces
    .map((surface) => ({
      surface,
      aliases: uniqueStrings(
        aliasesForSurface(surface)
          .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
          .map(normalizeCallableName)
          .filter((value) => value.length >= 4)
      )
    }))
    .filter((candidate) => candidate.aliases.length > 0)
    .sort((a, b) => a.surface.name.localeCompare(b.surface.name) || a.surface.path.localeCompare(b.surface.path));
}

function toolAliases(tool: SurfaceObject): Array<string | undefined> {
  return [
    tool.name,
    typeof tool.metadata.tool_name === "string" ? tool.metadata.tool_name : undefined,
    typeof tool.metadata.script_name === "string" ? tool.metadata.script_name : undefined
  ];
}

function referencedCallableSurfaces(content: string, candidates: CallableCandidate[]): SurfaceObject[] {
  const normalizedContent = `_${normalizeCallableName(content)}_`;
  return candidates
    .filter((candidate) => candidate.aliases.some((alias) => normalizedContent.includes(`_${alias}_`)))
    .map((candidate) => candidate.surface)
    .sort((a, b) => a.name.localeCompare(b.name) || a.path.localeCompare(b.path));
}

function referencedMcpServersForRuntime(allowedTools: string[], mcpServers: SurfaceObject[]): SurfaceObject[] {
  const allowAllTools = allowedTools.some((tool) => /(^|\s|\*)\*(\s|$)|all_tools|all-tools|all tools/iu.test(tool));
  const mcpReferences = new Set<string>();

  for (const tool of allowedTools) {
    const normalized = tool.trim().toLowerCase();
    const match = normalized.match(/^mcp[:/](.+)$/iu);
    if (match?.[1]) mcpReferences.add(normalizeCallableName(match[1]));
  }

  return mcpServers
    .filter((server) => allowAllTools || mcpReferences.has(normalizeCallableName(server.name)))
    .sort((a, b) => a.name.localeCompare(b.name) || a.path.localeCompare(b.path));
}

function isPrivilegedMcpServer(server: SurfaceObject): boolean {
  return (
    server.side_effect ||
    server.external_reach ||
    server.secret_exposure ||
    !server.reversible ||
    server.actions.some((action) => ["write", "execute", "publish", "send", "delete", "remember", "call"].includes(action))
  );
}

function isSecretBackedMcpServer(server: SurfaceObject): boolean {
  return (
    server.secret_exposure ||
    server.data_classes.some((dataClass) => dataClass === "credential" || dataClass === "secret") ||
    stringMetadataArray(server.metadata.env_key_names).length > 0 ||
    stringMetadataArray(server.metadata.secret_ref_key_names).length > 0 ||
    stringMetadataArray(server.metadata.auth_header_names).length > 0
  );
}

function stringMetadataArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string").sort((a, b) => a.localeCompare(b));
}

function isHeuristicSurface(surface: SurfaceObject): boolean {
  return surface.metadata.heuristic === true;
}

function surfaceNames(surfaces: SurfaceObject[]): string[] {
  return [...new Set(surfaces.map((surface) => surface.name))].sort((a, b) => a.localeCompare(b));
}

function uniqueDataClasses(values: SurfaceObject["data_classes"]): SurfaceObject["data_classes"] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function contextualDataClasses(
  baseClasses: SurfaceObject["data_classes"],
  signals: ContextContentSignals
): SurfaceObject["data_classes"] {
  const classes = new Set(baseClasses);
  if (signals.secret_reference) classes.add("credential");
  if (signals.sensitive_context_reference || signals.data_egress_directive) classes.add("confidential");
  if (classes.size > 1) classes.delete("unknown");
  return uniqueDataClasses([...classes] as SurfaceObject["data_classes"]);
}

interface WorkflowCommandSignals {
  run_commands_redacted: boolean;
  run_command_count: number;
  package_manager_run: boolean;
  agent_run_command: boolean;
  agent_package_script_names: string[];
  command_redacted: boolean;
  command_signals?: unknown;
  network_to_shell?: unknown;
  release_or_publish?: unknown;
  destructive_command?: unknown;
}

interface WorkflowEventInputSignals {
  untrusted_event_trigger: boolean;
  untrusted_event_triggers: string[];
  untrusted_event_payload_used: boolean;
  untrusted_event_payload_sources: string[];
  untrusted_event_payload_source_count: number;
  untrusted_event_payload_redacted: boolean;
  untrusted_event_context_env_keys: string[];
  untrusted_event_context_env_key_count: number;
  untrusted_event_agent_input: boolean;
}

function collectWorkflowRunCommands(value: unknown): string[] {
  const commands: string[] = [];
  collectWorkflowRunCommandsInto(value, commands);
  return commands;
}

function collectWorkflowRunCommandsInto(value: unknown, commands: string[]): void {
  if (Array.isArray(value)) {
    for (const item of value) collectWorkflowRunCommandsInto(item, commands);
    return;
  }
  if (!value || typeof value !== "object") return;

  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (key === "run" && typeof item === "string") {
      commands.push(item);
      continue;
    }
    collectWorkflowRunCommandsInto(item, commands);
  }
}

function classifyWorkflowRunCommands(commands: string[]): WorkflowCommandSignals {
  const joined = commands.join("\n");
  const commandSignals = redactedCommandSignals(joined);
  const agentScriptNames = extractAgentPackageScriptNames(joined);
  return {
    run_commands_redacted: true,
    run_command_count: commands.length,
    package_manager_run: /\b(npm|pnpm|yarn|bun)\b/iu.test(joined),
    agent_run_command: agentScriptNames.length > 0 || /\b(agent|codex|claude|mcp|assistant|bot)\b/iu.test(joined),
    agent_package_script_names: agentScriptNames,
    command_redacted: true,
    ...commandSignals
  };
}

function classifyWorkflowEventInput(
  triggerNames: string[],
  parsedWorkflow: unknown,
  content: string,
  commandSignals: WorkflowCommandSignals
): WorkflowEventInputSignals {
  const eventTriggers = triggerNames.filter(isUntrustedWorkflowEventTrigger);
  const payloadSources = classifyWorkflowEventPayloadSources(content);
  const untrustedPayloadSources = payloadSources.filter((source) => source !== "workflow_dispatch_input");
  const eventEnvKeys = collectWorkflowEventInputEnvKeys(parsedWorkflow);
  const payloadUsed = untrustedPayloadSources.length > 0;
  return {
    untrusted_event_trigger: eventTriggers.length > 0,
    untrusted_event_triggers: eventTriggers,
    untrusted_event_payload_used: payloadUsed,
    untrusted_event_payload_sources: untrustedPayloadSources,
    untrusted_event_payload_source_count: untrustedPayloadSources.length,
    untrusted_event_payload_redacted: payloadUsed,
    untrusted_event_context_env_keys: eventEnvKeys,
    untrusted_event_context_env_key_count: eventEnvKeys.length,
    untrusted_event_agent_input: payloadUsed && commandSignals.agent_run_command
  };
}

function isUntrustedWorkflowEventTrigger(triggerName: string): boolean {
  return [
    "discussion",
    "discussion_comment",
    "issue_comment",
    "issues",
    "pull_request",
    "pull_request_review",
    "pull_request_target",
    "repository_dispatch"
  ].includes(triggerName);
}

function classifyWorkflowEventPayloadSources(content: string): string[] {
  const sources = new Set<string>();
  if (/github\.event\.comment\.body/iu.test(content)) sources.add("issue_comment_body");
  if (/github\.event\.issue\.(body|title)/iu.test(content)) sources.add("issue_text");
  if (/github\.event\.pull_request\.(body|title)/iu.test(content)) sources.add("pull_request_text");
  if (/github\.event\.review\.body/iu.test(content)) sources.add("pull_request_review_body");
  if (/github\.event\.discussion\.(body|title)/iu.test(content)) sources.add("discussion_text");
  if (/github\.event\.client_payload(?:\.|[\s}])|github\.event\.client_payload$/iu.test(content)) {
    sources.add("repository_dispatch_payload");
  }
  if (/github\.event\.inputs(?:\.|[\s}])|\binputs\.[A-Za-z_][\w-]*/u.test(content)) sources.add("workflow_dispatch_input");
  return [...sources].sort((a, b) => a.localeCompare(b));
}

function collectWorkflowEventInputEnvKeys(value: unknown): string[] {
  const keys = new Set<string>();
  collectWorkflowEventInputEnvKeysInto(value, keys);
  return [...keys].sort((a, b) => a.localeCompare(b));
}

function collectWorkflowEventInputEnvKeysInto(value: unknown, keys: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) collectWorkflowEventInputEnvKeysInto(item, keys);
    return;
  }
  if (!value || typeof value !== "object") return;

  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (key === "env" && item && typeof item === "object" && !Array.isArray(item)) {
      for (const [envKey, envValue] of Object.entries(item as Record<string, unknown>)) {
        if (typeof envValue === "string" && classifyWorkflowEventPayloadSources(envValue).length > 0) {
          keys.add(envKey);
        }
      }
    }
    collectWorkflowEventInputEnvKeysInto(item, keys);
  }
}

function extractAgentPackageScriptNames(commandText: string): string[] {
  return extractPackageScriptNames(commandText).filter(isAgentPackageScriptName);
}

function extractPackageScriptNames(commandText: string): string[] {
  const names = new Set<string>();
  const patterns = [
    /\bnpm\s+run\s+([a-zA-Z0-9][\w:.-]*)/giu,
    /\b(?:pnpm|yarn|bun)\s+(?:run\s+)?([a-zA-Z0-9][\w:.-]*)/giu
  ];

  for (const pattern of patterns) {
    for (const match of commandText.matchAll(pattern)) {
      if (match[1]) names.add(match[1]);
    }
  }

  return [...names].sort((a, b) => a.localeCompare(b));
}

function isAgentPackageScriptName(name: string): boolean {
  return /\b(agent|codex|claude|mcp|assistant|bot|autogen|crew|langgraph)\b/iu.test(name.replace(/[:._-]/g, " "));
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
      permission_allowlist: posture.permission_allowlist,
      permission_denylist: posture.permission_denylist,
      auto_approved_package_script_names: posture.auto_approved_package_script_names,
      auto_approved_mcp_servers: posture.auto_approved_mcp_servers,
      auto_approved_mcp_tool_refs: posture.auto_approved_mcp_tool_refs,
      auto_approved_mcp_tool_count: posture.auto_approved_mcp_tool_count,
      auto_approved_destructive_mcp_servers: posture.auto_approved_destructive_mcp_servers,
      auto_approved_destructive_mcp_tool_refs: posture.auto_approved_destructive_mcp_tool_refs,
      auto_approved_destructive_mcp_tool_count: posture.auto_approved_destructive_mcp_tool_count,
      auto_approved_destructive_mcp_tools: posture.auto_approved_destructive_mcp_tools,
      auto_approved_network_tools: posture.auto_approved_network_tools,
      auto_approved_network_scope_kinds: posture.auto_approved_network_scope_kinds,
      auto_approved_network_scope_count: posture.auto_approved_network_scope_count,
      auto_approved_wildcard_network_scope: posture.auto_approved_wildcard_network_scope,
      auto_approved_unscoped_network_tool: posture.auto_approved_unscoped_network_tool,
      auto_approved_broad_network_scope: posture.auto_approved_broad_network_scope,
      auto_approved_tools_redacted: posture.auto_approved_tools_redacted,
      auto_approved_tool_count: posture.auto_approved_tool_count,
      auto_approved_privileged_tool_count: posture.auto_approved_privileged_tool_count,
      auto_approved_privileged_tool_signal_count: posture.auto_approved_privileged_tool_signal_count,
      auto_approved_privileged_tools: posture.auto_approved_privileged_tools,
      auto_approved_privileged_tool_signals: posture.auto_approved_privileged_tool_signals,
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
  localCommandPaths?: string[];
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
    const localCommandPaths = extractLocalMcpCommandPathRefs(command, args);
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
      packageRunner,
      localCommandPaths
    };
  });
}

function extractLocalMcpCommandPathRefs(command: string | undefined, args: string[]): string[] {
  return uniqueStrings([command, ...args].flatMap((value) => normalizeLocalImplementationPath(value)));
}

function isCredentialLikeKeyName(keyName: string): boolean {
  return /authorization|token|secret|key|password|credential|auth|webhook|cookie|bearer/i.test(keyName);
}

function normalizeLocalImplementationPath(value: string | undefined): string[] {
  if (!value) return [];
  const normalizedValue = value.trim().replaceAll("\\", "/");
  if (!normalizedValue) return [];
  if (normalizedValue.startsWith("-")) return [];
  if (normalizedValue.startsWith("${") || normalizedValue.includes("${")) return [];
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(normalizedValue)) return [];
  if (path.posix.isAbsolute(normalizedValue) || path.win32.isAbsolute(value)) return [];
  if (!looksLikeImplementationPath(normalizedValue)) return [];

  const normalizedPath = normalizeProjectPath(normalizedValue);
  if (normalizedPath === "." || normalizedPath === ".." || normalizedPath.startsWith("../")) return [];
  return [normalizedPath];
}

function looksLikeImplementationPath(value: string): boolean {
  if (!value.includes("/") && !value.startsWith("./")) return false;
  return /\.(?:cjs|mjs|js|cts|mts|ts|jsx|tsx|py|sh|rb|go|rs|jar|php|pl|ps1)$/i.test(value);
}

function normalizeProjectPath(value: string): string {
  const normalized = path.posix.normalize(value.replaceAll("\\", "/"));
  return normalized.startsWith("./") ? normalized.slice(2) : normalized;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
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
  return extractEnvironmentReferenceKeys(values).filter((key) => isCredentialLikeKeyName(key));
}

function extractEnvironmentReferenceKeys(values: unknown[]): string[] {
  const keys = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") continue;
    for (const match of value.matchAll(/\$\{?([A-Z_][A-Z0-9_]*)\}?/g)) {
      if (match[1]) keys.add(match[1]);
    }
  }
  return [...keys].sort((a, b) => a.localeCompare(b));
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
  permission_allowlist: string[];
  permission_denylist: string[];
  auto_approved_package_script_names: string[];
  auto_approved_mcp_servers: string[];
  auto_approved_mcp_tool_refs: string[];
  auto_approved_mcp_tool_count: number;
  auto_approved_destructive_mcp_servers: string[];
  auto_approved_destructive_mcp_tool_refs: string[];
  auto_approved_destructive_mcp_tool_count: number;
  auto_approved_destructive_mcp_tools: boolean;
  auto_approved_network_tools: string[];
  auto_approved_network_scope_kinds: string[];
  auto_approved_network_scope_count: number;
  auto_approved_wildcard_network_scope: boolean;
  auto_approved_unscoped_network_tool: boolean;
  auto_approved_broad_network_scope: boolean;
  auto_approved_tools_redacted: boolean;
  auto_approved_tool_count: number;
  auto_approved_privileged_tool_count: number;
  auto_approved_privileged_tool_signal_count: number;
  auto_approved_privileged_tools: boolean;
  auto_approved_privileged_tool_signals: string[];
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
  if (normalized.startsWith(".claude/") && RUNTIME_CONFIG_BASENAMES.has(lowerBase)) return true;
  if (normalized.startsWith(".cursor/") && RUNTIME_CONFIG_BASENAMES.has(lowerBase)) return true;
  return false;
}

function parseStructuredConfig(content: string, filePath: string): { value?: unknown; parseFailed: boolean; parser?: string } {
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

function parseRuntimeConfig(content: string, filePath: string): { value?: unknown; parseFailed: boolean; parser?: string } {
  return parseStructuredConfig(content, filePath);
}

function classifyRuntimeConfig(value: unknown): RuntimePosture {
  const fields = flattenRuntimeFields(value);
  const sandboxMode = normalizeRuntimeScalar(findFirstField(fields, /(^|\.)sandbox(_mode|mode)?$|isolation|container/iu)?.value);
  const approvalPolicy = normalizeRuntimeScalar(
    findFirstField(fields, /approval|require_approval|tool_approval|human_approval|confirmation|confirm/iu)?.value
  );
  const networkAccess = normalizeRuntimeScalar(findFirstField(fields, /network|internet|web_access|allow_network|net_access/iu)?.value);
  const rawPermissionAllowlist = collectStringArrayFields(fields, /(^|\.)permissions\.(allow|allowed|allowlist)$/iu);
  const rawPermissionDenylist = collectStringArrayFields(fields, /(^|\.)permissions\.(deny|denied|denylist|block|blocked)$/iu);
  const permissionAllowlist = normalizeRuntimePermissionEntries(rawPermissionAllowlist);
  const permissionDenylist = normalizeRuntimePermissionEntries(rawPermissionDenylist);
  const configuredAllowedTools = collectStringArrayFields(fields, /(^|\.)(allowed_tools|allow_tools|enabled_tools|tools_allowlist|tools)$/iu);
  const configuredDisabledTools = collectStringArrayFields(fields, /(^|\.)(disabled_tools|deny_tools|blocked_tools|tools_denylist)$/iu);
  const allowedTools = uniqueStrings([
    ...configuredAllowedTools,
    ...permissionAllowlist
  ]);
  const disabledTools = uniqueStrings([
    ...configuredDisabledTools,
    ...permissionDenylist
  ]);
  const envKeys = collectEnvKeyNamesFromConfig(value);
  const privilegedSignals = classifyPrivilegedToolSignals([...configuredAllowedTools, ...rawPermissionAllowlist]);
  const autoApprovedPrivilegedSignals = classifyPrivilegedToolSignals(rawPermissionAllowlist);
  const autoApprovedPrivilegedToolCount = rawPermissionAllowlist.filter(
    (entry) => classifyPrivilegedToolSignals([entry]).length > 0
  ).length;
  const autoApprovedPackageScriptNames = extractPackageScriptNames(rawPermissionAllowlist.join("\n"));
  const autoApprovedMcpToolRefs = extractRuntimeMcpToolRefs(rawPermissionAllowlist);
  const autoApprovedDestructiveMcpToolRefs = autoApprovedMcpToolRefs.filter((ref) => isDestructiveMcpToolRef(ref.toolName));
  const autoApprovedNetworkScopes = extractRuntimeNetworkScopes(rawPermissionAllowlist);
  const networkEnabled = Boolean(
    (networkAccess && /true|yes|enabled|enable|on|full|unrestricted|allow/iu.test(networkAccess)) ||
      privilegedSignals.some((signal) => ["browser", "external_messaging", "github"].includes(signal)) ||
      autoApprovedNetworkScopes.length > 0
  );
  const autoApprovedNetworkScopeKinds = uniqueStrings(autoApprovedNetworkScopes.map((scope) => scope.scopeKind));

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
      (approvalPolicy && /never|none|auto|always_allow|disabled|disable|off|false|unrestricted|no_approval|without/iu.test(approvalPolicy)) ||
        autoApprovedPrivilegedSignals.length > 0
    ),
    network_access: networkAccess,
    network_enabled: networkEnabled,
    allowed_tools: allowedTools,
    disabled_tools: disabledTools,
    permission_allowlist: permissionAllowlist,
    permission_denylist: permissionDenylist,
    auto_approved_package_script_names: autoApprovedPackageScriptNames,
    auto_approved_mcp_servers: uniqueStrings(autoApprovedMcpToolRefs.map((ref) => ref.serverName)),
    auto_approved_mcp_tool_refs: uniqueStrings(autoApprovedMcpToolRefs.map((ref) => ref.ref)),
    auto_approved_mcp_tool_count: autoApprovedMcpToolRefs.length,
    auto_approved_destructive_mcp_servers: uniqueStrings(autoApprovedDestructiveMcpToolRefs.map((ref) => ref.serverName)),
    auto_approved_destructive_mcp_tool_refs: uniqueStrings(autoApprovedDestructiveMcpToolRefs.map((ref) => ref.ref)),
    auto_approved_destructive_mcp_tool_count: autoApprovedDestructiveMcpToolRefs.length,
    auto_approved_destructive_mcp_tools: autoApprovedDestructiveMcpToolRefs.length > 0,
    auto_approved_network_tools: uniqueStrings(autoApprovedNetworkScopes.map((scope) => scope.toolName)),
    auto_approved_network_scope_kinds: autoApprovedNetworkScopeKinds,
    auto_approved_network_scope_count: autoApprovedNetworkScopes.length,
    auto_approved_wildcard_network_scope: autoApprovedNetworkScopeKinds.some(
      (scopeKind) => scopeKind.startsWith("wildcard_") || scopeKind === "all_tools"
    ),
    auto_approved_unscoped_network_tool: autoApprovedNetworkScopeKinds.includes("unscoped_network_tool"),
    auto_approved_broad_network_scope: autoApprovedNetworkScopeKinds.some(
      (scopeKind) => scopeKind.startsWith("wildcard_") || scopeKind === "all_tools" || scopeKind === "unscoped_network_tool"
    ),
    auto_approved_tools_redacted: permissionAllowlist.length > 0,
    auto_approved_tool_count: rawPermissionAllowlist.length,
    auto_approved_privileged_tool_count: autoApprovedPrivilegedToolCount,
    auto_approved_privileged_tool_signal_count: autoApprovedPrivilegedSignals.length,
    auto_approved_privileged_tools: autoApprovedPrivilegedSignals.length > 0,
    auto_approved_privileged_tool_signals: autoApprovedPrivilegedSignals,
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

function normalizeRuntimePermissionEntries(entries: string[]): string[] {
  return uniqueStrings(entries.map(normalizeRuntimePermissionEntry));
}

function normalizeRuntimePermissionEntry(entry: string): string {
  const trimmed = entry.trim();
  if (!trimmed) return "redacted_permission";
  if (trimmed === "*") return "*";

  const mcpMatch = trimmed.match(/^mcp__([^_\s()]+)__[^()\s]+/iu);
  if (mcpMatch?.[1]) return `mcp:${mcpMatch[1]}`;

  const toolCallMatch = trimmed.match(/^([a-zA-Z][\w-]*)\s*\(/u);
  if (toolCallMatch?.[1]) return toolCallMatch[1];

  const mcpRuntimeMatch = trimmed.match(/^mcp[:/]([^()\s]+)/iu);
  if (mcpRuntimeMatch?.[1]) return `mcp:${normalizeCallableName(mcpRuntimeMatch[1])}`;

  if (/^[a-zA-Z][\w:.-]{0,79}$/u.test(trimmed)) return trimmed;
  return "redacted_permission";
}

interface RuntimeMcpToolRef {
  serverName: string;
  toolName: string;
  ref: string;
}

function extractRuntimeMcpToolRefs(entries: string[]): RuntimeMcpToolRef[] {
  const refs = new Map<string, RuntimeMcpToolRef>();
  for (const entry of entries) {
    const trimmed = entry.trim();
    const claudeMatch = trimmed.match(/^mcp__([^_\s()]+)__([^()\s]+)$/iu);
    if (claudeMatch?.[1] && claudeMatch[2]) {
      const serverName = normalizeCallableName(claudeMatch[1]);
      const toolName = normalizeCallableName(claudeMatch[2]);
      const ref = `mcp:${serverName}/${toolName}`;
      refs.set(ref, { serverName, toolName, ref });
      continue;
    }

    const runtimeMatch = trimmed.match(/^mcp[:/]([^/\s()]+)[/:]([^()\s]+)$/iu);
    if (runtimeMatch?.[1] && runtimeMatch[2]) {
      const serverName = normalizeCallableName(runtimeMatch[1]);
      const toolName = normalizeCallableName(runtimeMatch[2]);
      const ref = `mcp:${serverName}/${toolName}`;
      refs.set(ref, { serverName, toolName, ref });
    }
  }
  return [...refs.values()].sort((a, b) => a.ref.localeCompare(b.ref));
}

function isDestructiveMcpToolRef(toolName: string): boolean {
  return /\b(delete|remove|drop|truncate|destroy|purge|wipe|write|update|modify|publish|release|deploy|send|post)\b/iu.test(
    toolName.replace(/[_-]/g, " ")
  );
}

interface RuntimeNetworkScope {
  toolName: string;
  scopeKind: string;
}

function extractRuntimeNetworkScopes(entries: string[]): RuntimeNetworkScope[] {
  const scopes = new Map<string, RuntimeNetworkScope>();
  for (const entry of entries) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    if (trimmed === "*" || /^all[-_\s]?tools$/iu.test(trimmed)) {
      addRuntimeNetworkScope(scopes, "all_tools", "all_tools");
      continue;
    }

    const toolCallMatch = trimmed.match(/^([a-zA-Z][\w-]*)\s*(?:\((.*)\))?$/u);
    if (!toolCallMatch?.[1]) continue;

    const toolName = canonicalRuntimeNetworkToolName(toolCallMatch[1]);
    if (!toolName) continue;

    addRuntimeNetworkScope(scopes, toolName, runtimeNetworkScopeKind(toolName, toolCallMatch[2]));
  }
  return [...scopes.values()].sort((a, b) => `${a.toolName}:${a.scopeKind}`.localeCompare(`${b.toolName}:${b.scopeKind}`));
}

function addRuntimeNetworkScope(scopes: Map<string, RuntimeNetworkScope>, toolName: string, scopeKind: string): void {
  const key = `${toolName}:${scopeKind}`;
  scopes.set(key, { toolName, scopeKind });
}

function canonicalRuntimeNetworkToolName(toolName: string): string | undefined {
  const normalized = normalizeCallableName(toolName);
  if (/^web_?fetch$/iu.test(normalized)) return "WebFetch";
  if (/^web_?search$/iu.test(normalized)) return "WebSearch";
  if (/^browser$/iu.test(normalized)) return "Browser";
  if (/^fetch$/iu.test(normalized)) return "fetch";
  if (/^request$/iu.test(normalized)) return "request";
  if (/^http$/iu.test(normalized)) return "http";
  if (/^curl$/iu.test(normalized)) return "curl";
  if (/^playwright$/iu.test(normalized)) return "playwright";
  if (/^puppeteer$/iu.test(normalized)) return "puppeteer";
  return undefined;
}

function runtimeNetworkScopeKind(toolName: string, scopeText: string | undefined): string {
  if (!scopeText || !scopeText.trim()) return "unscoped_network_tool";

  const normalized = scopeText.toLowerCase();
  if (/domain\s*[:=]\s*\*/iu.test(normalized)) return "wildcard_domain";
  if (/url\s*[:=]\s*\*|https?:\/\/\*/iu.test(normalized)) return "wildcard_url";
  if (/^\s*\*\s*$/u.test(scopeText)) return toolName === "WebSearch" ? "wildcard_search" : "wildcard_network";
  if (/(^|[,:=\s])\*(?:[,)\s]|$)/u.test(scopeText)) return "wildcard_network";
  if (/domain|host/iu.test(normalized)) return "scoped_domain";
  if (/url|https?:\/\//iu.test(normalized)) return "scoped_url";
  if (toolName === "WebSearch") return "scoped_search";
  return "scoped_network";
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
  if (/browser|web|webfetch|websearch|playwright|puppeteer/iu.test(joined)) signals.add("browser");
  if (/mcp:|mcp__/iu.test(joined)) signals.add("mcp");
  if (/filesystem|file|workspace|fs|edit|multiedit|write|delete|notebookedit/iu.test(joined)) signals.add("filesystem");
  if (/github|gitlab|repo|pull|issue/iu.test(joined)) signals.add("github");
  if (/slack|email|smtp|webhook/iu.test(joined)) signals.add("external_messaging");
  return [...signals].sort((a, b) => a.localeCompare(b));
}

function isRuntimeSecurityField(fieldPath: string): boolean {
  return /sandbox|approval|confirm|network|internet|web_access|tool|permission|allow|deny|env|environment|secret|token|credential/iu.test(fieldPath);
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
  accepts_content_like_input: boolean;
  accepts_path_input: boolean;
  accepts_url_input: boolean;
  accepts_pii_like_input: boolean;
  accepts_customer_data_input: boolean;
  accepted_data_classes: SurfaceObject["data_classes"];
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
  const propertyText = normalizeAuthorityText(`${definition.schemaProperties.join(" ")} ${definition.requiredProperties.join(" ")}`);
  const acceptsContent = /\b(message|summary|content|text|prompt|comment|note|ticket|issue|email|chat|conversation|response|output|body)\b/i.test(
    propertyText
  );
  const acceptsPath = /(^|[_\W])(path|file|directory|dir|folder|repo|repository|workspace|glob)([_\W]|$)/i.test(text);
  const acceptsUrl = /\b(url|uri|webhook|endpoint|host|domain|http)\b/i.test(text);
  const schemaDataProfile = classifyToolSchemaDataProfile(definition);
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
  if (acceptsContent) {
    classes.add("content_input");
  }
  if (schemaDataProfile.acceptsPii) {
    classes.add("pii_input");
  }
  if (schemaDataProfile.acceptsCustomerData) {
    classes.add("customer_data_input");
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
    accepts_content_like_input: acceptsContent,
    accepts_path_input: acceptsPath,
    accepts_url_input: acceptsUrl,
    accepts_pii_like_input: schemaDataProfile.acceptsPii,
    accepts_customer_data_input: schemaDataProfile.acceptsCustomerData,
    accepted_data_classes: schemaDataProfile.dataClasses,
    external_write: externalWrite,
    destructive_action: destructive,
    open_world_authority: openWorldAuthority,
    read_only_hint_conflict: readOnlyHintConflict
  };
}

function classifyToolSchemaDataProfile(definition: ExtractedToolDefinition): {
  acceptsPii: boolean;
  acceptsCustomerData: boolean;
  dataClasses: SurfaceObject["data_classes"];
} {
  const schemaText = normalizeAuthorityText(
    `${definition.name} ${definition.schemaProperties.join(" ")} ${definition.requiredProperties.join(" ")}`
  );
  const acceptsPii =
    /\b(email|e mail|phone|mobile|address|ssn|social security|passport|date of birth|dob|birth date|customer id|user id|account id)\b/i.test(
      schemaText
    );
  const acceptsCustomerData = /\b(customer|client|account|ticket|case|support|record)\b/i.test(schemaText);
  const dataClasses = uniqueDataClasses([
    ...(acceptsPii ? ["pii"] : []),
    ...(acceptsCustomerData ? ["confidential"] : [])
  ] as SurfaceObject["data_classes"]);
  return {
    acceptsPii,
    acceptsCustomerData,
    dataClasses
  };
}

function normalizeAuthorityText(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeCallableName(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();
}

function authoritySignature(tool: SurfaceObject): string {
  const metadata = tool.metadata;
  const flags = [
    metadata.parsed_tool_schema === true ? "parsed" : "unparsed",
    metadata.external_write === true ? "external_write" : "",
    metadata.destructive_action === true ? "destructive" : "",
    metadata.accepts_secret_like_input === true ? "secret_input" : "",
    metadata.accepts_content_like_input === true ? "content_input" : "",
    metadata.accepts_path_input === true ? "path_input" : "",
    metadata.open_world_authority === true ? "open_world" : "",
    metadata.read_only_hint === true ? "read_only" : "",
    metadata.read_only_hint_conflict === true ? "read_only_conflict" : "",
    tool.side_effect ? "side_effect" : "",
    tool.external_reach ? "external_reach" : "",
    tool.secret_exposure ? "secret_exposure" : "",
    tool.reversible ? "reversible" : "irreversible",
    ...tool.actions.map((action) => `action:${action}`)
  ].filter(Boolean);
  return [...new Set(flags)].sort((a, b) => a.localeCompare(b)).join("|");
}

function isPrivilegedToolSurface(tool: SurfaceObject): boolean {
  return (
    tool.side_effect ||
    tool.external_reach ||
    tool.secret_exposure ||
    !tool.reversible ||
    tool.actions.some((action) => ["write", "execute", "publish", "send", "delete", "remember"].includes(action)) ||
    tool.metadata.external_write === true ||
    tool.metadata.destructive_action === true ||
    tool.metadata.open_world_authority === true ||
    tool.metadata.read_only_hint_conflict === true
  );
}
