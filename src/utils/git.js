import { execFile } from 'node:child_process';
import { access, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const SUPPORTED_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx']);
const IGNORED_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
]);

export function isSupportedSourceFile(filepath) {
  return SUPPORTED_EXTENSIONS.has(path.extname(filepath).toLowerCase());
}

export async function hasGitRepository(projectRoot = process.cwd()) {
  try {
    await access(path.join(projectRoot, '.git'));
    return true;
  } catch {
    return false;
  }
}

export async function getStagedSourceFiles(projectRoot = process.cwd()) {
  if (!(await hasGitRepository(projectRoot))) {
    return [];
  }

  const { stdout } = await execFileAsync('git', ['diff', '--staged', '--name-only', '--diff-filter=ACMR'], {
    cwd: projectRoot,
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  });

  const candidates = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter(isSupportedSourceFile)
    .map((relativePath) => path.resolve(projectRoot, relativePath));

  const existingFiles = [];
  for (const candidate of candidates) {
    try {
      const details = await stat(candidate);
      if (details.isFile()) {
        existingFiles.push(candidate);
      }
    } catch {
      continue;
    }
  }

  return existingFiles;
}

export async function collectSourceFiles(rootPath = process.cwd()) {
  const absoluteRoot = path.resolve(rootPath);
  const details = await stat(absoluteRoot);

  if (details.isFile()) {
    return isSupportedSourceFile(absoluteRoot) ? [absoluteRoot] : [];
  }

  const files = [];

  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });

    for (const entry of entries) {
      const absoluteEntry = path.join(directory, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) {
          await walk(absoluteEntry);
        }
        continue;
      }

      if (entry.isFile() && isSupportedSourceFile(absoluteEntry)) {
        files.push(absoluteEntry);
      }
    }
  }

  await walk(absoluteRoot);
  return files;
}

export async function getScanTargets(projectRoot = process.cwd(), options = {}) {
  const root = path.resolve(options.path ?? projectRoot);
  const stagedFiles = await getStagedSourceFiles(projectRoot);

  if (stagedFiles.length > 0) {
    return {
      mode: 'staged',
      files: stagedFiles.filter((file) => file.startsWith(path.resolve(root)) || root === projectRoot),
    };
  }

  return {
    mode: 'full',
    files: await collectSourceFiles(root),
  };
}
