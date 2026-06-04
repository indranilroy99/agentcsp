import path from "node:path";

export function toPosixPath(value: string): string {
  return value.replaceAll(path.sep, "/");
}

export function relativePath(rootPath: string, absolutePath: string): string {
  const rel = path.relative(rootPath, absolutePath) || ".";
  return toPosixPath(rel);
}

export function normalizePath(value: string): string {
  return toPosixPath(path.normalize(value));
}
