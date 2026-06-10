#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { access, chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import pc from 'picocolors';
import prompts from 'prompts';

const execFileAsync = promisify(execFile);
const START_MARKER = '# >>> VibeGuard Sentinel >>>';
const END_MARKER = '# <<< VibeGuard Sentinel <<<';

async function execGit(args, cwd = process.cwd()) {
  const { stdout } = await execFileAsync('git', args, {
    cwd,
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  });

  return stdout.trim();
}

async function fileExists(filepath) {
  try {
    await access(filepath);
    return true;
  } catch {
    return false;
  }
}

async function atomicWrite(filepath, content) {
  await mkdir(path.dirname(filepath), { recursive: true });
  const temporaryFile = path.join(path.dirname(filepath), `.${path.basename(filepath)}.${process.pid}.${Date.now()}.tmp`);
  await writeFile(temporaryFile, content, 'utf8');
  await rename(temporaryFile, filepath);
}

export async function resolveGitRepository(cwd = process.cwd()) {
  const insideWorkTree = await execGit(['rev-parse', '--is-inside-work-tree'], cwd);
  if (insideWorkTree !== 'true') {
    throw new Error('Current directory is not inside a Git work tree.');
  }

  const projectRoot = await execGit(['rev-parse', '--show-toplevel'], cwd);
  const hookPathOutput = await execGit(['rev-parse', '--git-path', 'hooks/pre-commit'], projectRoot);
  const hookPath = path.isAbsolute(hookPathOutput) ? hookPathOutput : path.resolve(projectRoot, hookPathOutput);

  return {
    projectRoot,
    hookPath,
  };
}

export function buildHookScript() {
  return [
    START_MARKER,
    '# VibeGuard blocks commits when staged JavaScript or TypeScript contains validated high-entropy secrets.',
    'echo "[VibeGuard] Sentinel scanning staged changes..."',
    'if command -v npx >/dev/null 2>&1; then',
    '  npx vibe-security-akoris scan --ci',
    '  status=$?',
    'elif command -v npx.cmd >/dev/null 2>&1; then',
    '  npx.cmd vibe-security-akoris scan --ci',
    '  status=$?',
    'elif command -v powershell.exe >/dev/null 2>&1; then',
    '  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "npx vibe-security-akoris scan --ci"',
    '  status=$?',
    'elif command -v pwsh >/dev/null 2>&1; then',
    '  pwsh -NoProfile -Command "npx vibe-security-akoris scan --ci"',
    '  status=$?',
    'else',
    '  echo "[VibeGuard] Unable to find npx. Install Node.js/npm before committing."',
    '  exit 1',
    'fi',
    'if [ "$status" -ne 0 ]; then',
    '  echo "[VibeGuard] Commit blocked. Remediate the reported secret candidate(s) and try again."',
    '  exit "$status"',
    'fi',
    END_MARKER,
    '',
  ].join('\n');
}

function ensureShellHook(existingContent, sentinelBlock) {
  const normalized = existingContent.replace(/\r\n/g, '\n');
  const contentWithoutSentinel = normalized.includes(START_MARKER)
    ? normalized.replace(new RegExp(`${START_MARKER}[\\s\\S]*?${END_MARKER}\\n?`, 'm'), '')
    : normalized;

  const hasShebang = contentWithoutSentinel.startsWith('#!');
  const baseContent = hasShebang ? contentWithoutSentinel : `#!/bin/sh\n${contentWithoutSentinel}`;
  const separator = baseContent.endsWith('\n') ? '' : '\n';

  return `${baseContent}${separator}${sentinelBlock}`;
}

export async function installPreCommitHook(options = {}) {
  const repository = await resolveGitRepository(options.cwd ?? process.cwd());
  const existingContent = (await fileExists(repository.hookPath)) ? await readFile(repository.hookPath, 'utf8') : '';
  const nextContent = ensureShellHook(existingContent, buildHookScript());

  await atomicWrite(repository.hookPath, nextContent);
  await chmod(repository.hookPath, 0o755);

  return repository;
}

function parseArgs(argv = []) {
  return {
    yes: argv.includes('--yes') || argv.includes('-y'),
  };
}

export async function main(argv = process.argv.slice(2)) {
  try {
    const options = parseArgs(argv);
    const repository = await resolveGitRepository(process.cwd());

    process.stdout.write(`${pc.bold('VibeGuard Sentinel')}\n`);
    process.stdout.write(`${pc.dim(`Repository: ${repository.projectRoot}`)}\n`);
    process.stdout.write(`${pc.dim(`Hook: ${repository.hookPath}`)}\n`);

    let shouldInstall = options.yes;
    if (!shouldInstall) {
      const answer = await prompts(
        {
          type: 'confirm',
          name: 'install',
          message: 'Install VibeGuard pre-commit protection for this repository?',
          initial: true,
        },
        {
          onCancel: () => {
            throw new Error('Protection setup cancelled by user.');
          },
        },
      );
      shouldInstall = Boolean(answer.install);
    }

    if (!shouldInstall) {
      process.stdout.write(`${pc.dim('No hook installed.')}\n`);
      return;
    }

    const installed = await installPreCommitHook({ cwd: repository.projectRoot });
    process.stdout.write(`${pc.green('Pre-commit protection installed.')}\n`);
    process.stdout.write(`${pc.dim('Commits now run: npx vibe-security-akoris scan --ci')}\n`);
    process.stdout.write(`${pc.dim(`Installed at: ${installed.hookPath}`)}\n`);
  } catch (error) {
    process.stderr.write(`${pc.red('VibeGuard protection failed:')} ${error.message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
