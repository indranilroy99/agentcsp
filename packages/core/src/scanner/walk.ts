import fs from "node:fs/promises";
import path from "node:path";
import {
  DEFAULT_INCLUDED_HIDDEN_DIRS,
  DEFAULT_MAX_FILE_SIZE_BYTES,
  DEFAULT_MAX_FILES,
  LOG_DIR_NAMES
} from "./defaults.js";
import type { ScanConfig } from "../schemas/index.js";
import { relativePath } from "../utils/paths.js";
import { IgnoreMatcher } from "./ignore.js";

export interface WalkedFile {
  absolutePath: string;
  relativePath: string;
  size: number;
  skippedForSize: boolean;
}

export async function walkProject(config: ScanConfig): Promise<WalkedFile[]> {
  const rootPath = path.resolve(config.root_path);
  const ignore = IgnoreMatcher.load(rootPath);
  const files: WalkedFile[] = [];

  async function visit(directory: string): Promise<void> {
    if (files.length >= (config.max_files ?? DEFAULT_MAX_FILES)) return;

    const entries = await fs.readdir(directory, { withFileTypes: true });
    const sortedEntries = entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of sortedEntries) {
      const absolutePath = path.join(directory, entry.name);
      const rel = relativePath(rootPath, absolutePath);
      if (ignore.matches(rel)) continue;

      if (entry.isDirectory()) {
        if (entry.name.startsWith(".") && !DEFAULT_INCLUDED_HIDDEN_DIRS.has(entry.name) && config.include_hidden) {
          continue;
        }
        if (entry.name.startsWith(".") && !config.include_hidden) continue;
        if (LOG_DIR_NAMES.has(entry.name.toLowerCase()) && !config.include_logs) {
          continue;
        }
        await visit(absolutePath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (files.length >= (config.max_files ?? DEFAULT_MAX_FILES)) return;

      const stats = await fs.stat(absolutePath);
      const maxFileSize = config.max_file_size_bytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;
      files.push({
        absolutePath,
        relativePath: rel,
        size: stats.size,
        skippedForSize: stats.size > maxFileSize
      });
    }
  }

  await visit(rootPath);
  return files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
}
