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

export function resolvePathFromRoot(rootPath: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? path.resolve(targetPath) : path.resolve(rootPath, targetPath);
}

export function isPathInsideRoot(rootPath: string, targetPath: string): boolean {
  const relativeTargetPath = path.relative(path.resolve(rootPath), path.resolve(targetPath));
  return Boolean(relativeTargetPath) && !relativeTargetPath.startsWith("..") && !path.isAbsolute(relativeTargetPath);
}
