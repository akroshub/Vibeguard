import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_IGNORED_PATTERNS = [
  '.git/**',
  'node_modules/**',
  'dist/**',
  'build/**',
  'coverage/**',
  '.next/**',
  '.nuxt/**',
  '.turbo/**',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  '*.lock',
];

function normalizePath(filepath) {
  return filepath.split(path.sep).join('/');
}

function escapeRegExp(value) {
  return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

function globToRegExp(pattern) {
  let source = '';

  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    const nextChar = pattern[index + 1];

    if (char === '*' && nextChar === '*') {
      source += '.*';
      index += 1;
    } else if (char === '*') {
      source += '[^/]*';
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += escapeRegExp(char);
    }
  }

  return new RegExp(`^${source}$`);
}

async function resolveIgnoreRoot(targetPath, projectRoot) {
  const absoluteTarget = path.resolve(targetPath ?? projectRoot);

  try {
    const details = await stat(absoluteTarget);
    return details.isDirectory() ? absoluteTarget : path.dirname(absoluteTarget);
  } catch {
    return path.resolve(projectRoot);
  }
}

export function parseIgnoreFile(content) {
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

export async function loadIgnorePolicy(options = {}) {
  const projectRoot = path.resolve(options.projectRoot ?? process.cwd());
  const ignoreRoot = await resolveIgnoreRoot(options.path ?? projectRoot, projectRoot);
  const ignoreFile = path.join(ignoreRoot, '.vibeguardignore');
  const extraPatterns = Array.isArray(options.extraPatterns) ? options.extraPatterns : [];

  try {
    const content = await readFile(ignoreFile, 'utf8');
    return {
      ignoreFile,
      ignoreRoot,
      patterns: [...DEFAULT_IGNORED_PATTERNS, ...parseIgnoreFile(content), ...extraPatterns],
    };
  } catch (error) {
    if (error.code === 'ENOENT') {
      return {
        ignoreFile,
        ignoreRoot,
        patterns: [...DEFAULT_IGNORED_PATTERNS, ...extraPatterns],
      };
    }
    throw error;
  }
}

export function isIgnored(filepath, policy) {
  if (!policy?.patterns?.length) {
    return false;
  }

  const relativePath = normalizePath(path.relative(policy.ignoreRoot, filepath));
  const basename = path.basename(filepath);

  return policy.patterns.some((pattern) => {
    const normalizedPattern = normalizePath(pattern.replace(/^\/+/, ''));

    if (normalizedPattern.endsWith('/')) {
      return relativePath.startsWith(normalizedPattern);
    }

    if (!normalizedPattern.includes('/')) {
      return globToRegExp(normalizedPattern).test(basename);
    }

    return globToRegExp(normalizedPattern).test(relativePath);
  });
}

export function filterIgnoredFiles(files, policy) {
  return files.filter((file) => !isIgnored(file, policy));
}
