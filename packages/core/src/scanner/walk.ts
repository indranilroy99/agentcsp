import fs from "node:fs/promises";
import type { Dirent } from "node:fs";
import path from "node:path";
import {
  DEFAULT_INCLUDED_HIDDEN_DIRS,
  DEFAULT_MAX_DIRECTORIES,
  DEFAULT_MAX_ENTRIES_PER_DIRECTORY,
  DEFAULT_MAX_FILE_SIZE_BYTES,
  DEFAULT_MAX_FILES,
  LOG_DIR_NAMES
} from "./defaults.js";
import type { ScanConfig, ScanCoverageSummary, ScanDiagnostic } from "../schemas/index.js";
import { stableId } from "../utils/ids.js";
import { isPathInsideRoot, relativePath, resolvePathFromRoot } from "../utils/paths.js";
import { IgnoreMatcher } from "./ignore.js";

export interface WalkedFile {
  absolutePath: string;
  relativePath: string;
  size: number;
  skippedForSize: boolean;
}

export interface WalkResult {
  files: WalkedFile[];
  coverage: ScanCoverageSummary;
  diagnostics: ScanDiagnostic[];
}

export const skippedPathPreviewLimit = 50;

export async function walkProject(config: ScanConfig): Promise<WalkedFile[]> {
  return (await walkProjectWithCoverage(config)).files;
}

export async function walkProjectWithCoverage(config: ScanConfig): Promise<WalkResult> {
  const rootPath = path.resolve(config.root_path);
  const outputIgnorePattern = outputPathIgnorePattern(rootPath, config.output_path);
  const ignore = IgnoreMatcher.load(rootPath, outputIgnorePattern ? [outputIgnorePattern] : [], {
    includeProjectIgnore: config.profile !== "ci_strict"
  });
  const files: WalkedFile[] = [];
  const diagnostics: ScanDiagnostic[] = [];
  if (config.profile === "ci_strict" && (await pathExists(path.join(rootPath, ".agentcspignore")))) {
    diagnostics.push({
      id: stableId("diagnostic", ["PROJECT_IGNORE_IGNORED", ".agentcspignore"]),
      severity: "info",
      code: "PROJECT_IGNORE_IGNORED",
      file_path: ".agentcspignore",
      parser: "scanner",
      reason: "Repository .agentcspignore was discovered but not applied by the ci_strict profile.",
      content_redacted: true
    });
  }
  const maxFiles = config.max_files ?? DEFAULT_MAX_FILES;
  const maxDirectories = config.max_directories ?? DEFAULT_MAX_DIRECTORIES;
  const maxEntriesPerDirectory = config.max_entries_per_directory ?? DEFAULT_MAX_ENTRIES_PER_DIRECTORY;
  const maxFileSize = config.max_file_size_bytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;
  const coverage: ScanCoverageSummary = {
    title: "AgentCSP Scan Coverage",
    scan_health: "complete",
    scan_health_reasons: [],
    directories_visited: 0,
    files_seen: 0,
    files_indexed: 0,
    files_skipped_for_size: 0,
    files_skipped_by_ignore: 0,
    directories_skipped_by_ignore: 0,
    directories_skipped_hidden: 0,
    directories_skipped_logs: 0,
    directories_skipped_for_entry_limit: 0,
    diagnostics_total: 0,
    diagnostics_errors: 0,
    diagnostics_warnings: 0,
    diagnostics_info: 0,
    max_files_reached: false,
    max_files: maxFiles,
    max_directories_reached: false,
    max_directories: maxDirectories,
    max_entries_per_directory: maxEntriesPerDirectory,
    max_file_size_bytes: maxFileSize,
    skipped_path_limit: skippedPathPreviewLimit,
    oversized_file_paths: [],
    oversized_file_paths_truncated: false,
    directory_entry_limit_paths: [],
    directory_entry_limit_paths_truncated: false
  };

  async function visit(directory: string): Promise<void> {
    if (files.length >= maxFiles) {
      coverage.max_files_reached = true;
      return;
    }

    if (coverage.directories_visited >= maxDirectories) {
      coverage.max_directories_reached = true;
      return;
    }

    const entries: Dirent[] = [];
    try {
      const handle = await fs.opendir(directory);
      coverage.directories_visited += 1;
      for await (const entry of handle) {
        if (entries.length >= maxEntriesPerDirectory) {
          coverage.directories_skipped_for_entry_limit += 1;
          const rel = relativePath(rootPath, directory);
          if (coverage.directory_entry_limit_paths.length < skippedPathPreviewLimit) {
            coverage.directory_entry_limit_paths.push(rel);
          } else {
            coverage.directory_entry_limit_paths_truncated = true;
          }
          return;
        }
        entries.push(entry);
      }
    } catch (error) {
      if (path.resolve(directory) === rootPath) throw error;
      diagnostics.push(walkDiagnostic(rootPath, directory, "SCAN_DIRECTORY_READ_FAILED"));
      return;
    }
    const sortedEntries = entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of sortedEntries) {
      const absolutePath = path.join(directory, entry.name);
      const rel = relativePath(rootPath, absolutePath);
      if (ignore.matches(rel)) {
        if (entry.isDirectory()) {
          coverage.directories_skipped_by_ignore += 1;
        } else if (entry.isFile()) {
          coverage.files_skipped_by_ignore += 1;
        }
        continue;
      }

      if (entry.isDirectory()) {
        if (entry.name.startsWith(".") && !DEFAULT_INCLUDED_HIDDEN_DIRS.has(entry.name) && config.include_hidden) {
          coverage.directories_skipped_hidden += 1;
          continue;
        }
        if (entry.name.startsWith(".") && !config.include_hidden) {
          coverage.directories_skipped_hidden += 1;
          continue;
        }
        if (LOG_DIR_NAMES.has(entry.name.toLowerCase()) && !config.include_logs) {
          coverage.directories_skipped_logs += 1;
          continue;
        }
        if (coverage.directories_visited >= maxDirectories) {
          coverage.max_directories_reached = true;
          continue;
        }
        await visit(absolutePath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (files.length >= maxFiles) {
        coverage.max_files_reached = true;
        return;
      }

      let stats: Awaited<ReturnType<typeof fs.stat>>;
      try {
        stats = await fs.stat(absolutePath);
      } catch {
        diagnostics.push(walkDiagnostic(rootPath, absolutePath, "SCAN_FILE_STAT_FAILED"));
        continue;
      }
      const skippedForSize = stats.size > maxFileSize;
      coverage.files_seen += 1;
      if (skippedForSize) {
        coverage.files_skipped_for_size += 1;
        if (coverage.oversized_file_paths.length < skippedPathPreviewLimit) {
          coverage.oversized_file_paths.push(rel);
        } else {
          coverage.oversized_file_paths_truncated = true;
        }
      }
      files.push({
        absolutePath,
        relativePath: rel,
        size: stats.size,
        skippedForSize
      });
    }
  }

  await visit(rootPath);
  const sortedFiles = files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  coverage.oversized_file_paths = [...coverage.oversized_file_paths].sort((a, b) => a.localeCompare(b));
  coverage.directory_entry_limit_paths = [...coverage.directory_entry_limit_paths].sort((a, b) => a.localeCompare(b));
  coverage.files_indexed = sortedFiles.length;
  return {
    files: sortedFiles,
    coverage: withWalkHealth(coverage),
    diagnostics: diagnostics.sort((a, b) => a.id.localeCompare(b.id))
  };
}

async function pathExists(candidate: string): Promise<boolean> {
  try {
    await fs.access(candidate);
    return true;
  } catch {
    return false;
  }
}

function withWalkHealth(coverage: ScanCoverageSummary): ScanCoverageSummary {
  const incomplete =
    coverage.max_files_reached ||
    coverage.max_directories_reached ||
    coverage.directories_skipped_for_entry_limit > 0;
  const scan_health = incomplete ? "incomplete" : coverage.files_skipped_for_size > 0 ? "degraded" : "complete";
  const scan_health_reasons = [
    ...(coverage.max_files_reached ? ["max_files_reached"] : []),
    ...(coverage.max_directories_reached ? ["max_directories_reached"] : []),
    ...(coverage.directories_skipped_for_entry_limit > 0 ? ["directory_entry_limit_reached"] : []),
    ...(coverage.files_skipped_for_size > 0 ? ["files_skipped_for_size"] : [])
  ];
  return { ...coverage, scan_health, scan_health_reasons };
}

function walkDiagnostic(rootPath: string, absolutePath: string, code: string): ScanDiagnostic {
  const filePath = relativePath(rootPath, absolutePath);
  return {
    id: stableId("diagnostic", [code, filePath]),
    severity: "warning",
    code,
    file_path: filePath,
    parser: "scanner",
    reason:
      code === "SCAN_DIRECTORY_READ_FAILED"
        ? "Directory could not be read during traversal. Scan continued with that subtree omitted and raw OS details redacted."
        : "File metadata could not be read during traversal. Scan continued with that file omitted and raw OS details redacted.",
    content_redacted: true
  };
}

function outputPathIgnorePattern(rootPath: string, outputPath: string): string | undefined {
  const resolvedOutputPath = resolvePathFromRoot(rootPath, outputPath);
  if (!isPathInsideRoot(rootPath, resolvedOutputPath)) return undefined;
  return relativePath(rootPath, resolvedOutputPath);
}
