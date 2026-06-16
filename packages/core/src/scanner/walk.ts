import fs from "node:fs/promises";
import path from "node:path";
import {
  DEFAULT_INCLUDED_HIDDEN_DIRS,
  DEFAULT_MAX_FILE_SIZE_BYTES,
  DEFAULT_MAX_FILES,
  LOG_DIR_NAMES
} from "./defaults.js";
import type { ScanConfig, ScanCoverageSummary } from "../schemas/index.js";
import { relativePath } from "../utils/paths.js";
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
}

export async function walkProject(config: ScanConfig): Promise<WalkedFile[]> {
  return (await walkProjectWithCoverage(config)).files;
}

export async function walkProjectWithCoverage(config: ScanConfig): Promise<WalkResult> {
  const rootPath = path.resolve(config.root_path);
  const outputIgnorePattern = outputPathIgnorePattern(rootPath, config.output_path);
  const ignore = IgnoreMatcher.load(rootPath, outputIgnorePattern ? [outputIgnorePattern] : []);
  const files: WalkedFile[] = [];
  const maxFiles = config.max_files ?? DEFAULT_MAX_FILES;
  const maxFileSize = config.max_file_size_bytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;
  const coverage: ScanCoverageSummary = {
    title: "AgentCSP Scan Coverage",
    directories_visited: 0,
    files_seen: 0,
    files_indexed: 0,
    files_skipped_for_size: 0,
    files_skipped_by_ignore: 0,
    directories_skipped_by_ignore: 0,
    directories_skipped_hidden: 0,
    directories_skipped_logs: 0,
    diagnostics_total: 0,
    diagnostics_errors: 0,
    diagnostics_warnings: 0,
    diagnostics_info: 0,
    max_files_reached: false,
    max_files: maxFiles,
    max_file_size_bytes: maxFileSize
  };

  async function visit(directory: string): Promise<void> {
    if (files.length >= maxFiles) {
      coverage.max_files_reached = true;
      return;
    }

    coverage.directories_visited += 1;
    const entries = await fs.readdir(directory, { withFileTypes: true });
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
        await visit(absolutePath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (files.length >= maxFiles) {
        coverage.max_files_reached = true;
        return;
      }

      const stats = await fs.stat(absolutePath);
      const skippedForSize = stats.size > maxFileSize;
      coverage.files_seen += 1;
      if (skippedForSize) coverage.files_skipped_for_size += 1;
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
  coverage.files_indexed = sortedFiles.length;
  return { files: sortedFiles, coverage };
}

function outputPathIgnorePattern(rootPath: string, outputPath: string): string | undefined {
  const resolvedOutputPath = path.resolve(outputPath);
  const relativeOutputPath = path.relative(rootPath, resolvedOutputPath);
  if (!relativeOutputPath || relativeOutputPath === ".") return undefined;
  if (relativeOutputPath.startsWith("..") || path.isAbsolute(relativeOutputPath)) return undefined;
  return relativePath(rootPath, resolvedOutputPath);
}
