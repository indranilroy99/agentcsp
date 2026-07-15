import fs from "node:fs";
import path from "node:path";
import { minimatch } from "minimatch";
import { DEFAULT_EXCLUDED_DIRS } from "./defaults.js";
import { toPosixPath } from "../utils/paths.js";

export class IgnoreMatcher {
  private readonly patterns: string[];

  constructor(patterns: string[]) {
    this.patterns = patterns.map((pattern) => pattern.trim()).filter(Boolean);
  }

  static load(
    rootPath: string,
    extraPatterns: string[] = [],
    options: { includeProjectIgnore?: boolean } = {}
  ): IgnoreMatcher {
    const ignorePath = path.join(rootPath, ".agentcspignore");
    const patterns = [...DEFAULT_EXCLUDED_DIRS, ...extraPatterns];
    if (options.includeProjectIgnore !== false && fs.existsSync(ignorePath)) {
      const lines = fs
        .readFileSync(ignorePath, "utf8")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith("#"));
      patterns.push(...lines);
    }
    return new IgnoreMatcher(patterns);
  }

  matches(relativePath: string): boolean {
    const normalized = toPosixPath(relativePath);
    const segments = normalized.split("/");
    for (const segment of segments) {
      if (DEFAULT_EXCLUDED_DIRS.has(segment)) return true;
    }
    return this.patterns.some((pattern) => {
      const normalizedPattern = toPosixPath(pattern);
      return (
        minimatch(normalized, normalizedPattern, { dot: true }) ||
        minimatch(normalized, `${normalizedPattern}/**`, { dot: true })
      );
    });
  }
}
