const fs = require('node:fs');
const path = require('node:path');
const { AppError } = require('../errors/AppError');

const HOOK_MARKER = '# Managed by VibeGuard';

function toHookPath(filepath) {
    return filepath.replace(/\\/g, '/');
}

function buildPreCommitHook(cliPath) {
    const safeCliPath = toHookPath(cliPath).replace(/"/g, '\\"');

    return [
        '#!/bin/sh',
        HOOK_MARKER,
        '',
        'echo "[VibeGuard] Running local secret scan..."',
        `VSG_FAIL_ON_FINDINGS=1 node "${safeCliPath}" --scan --dry-run --quiet --path "$PWD"`,
        'status=$?',
        '',
        'if [ "$status" -ne 0 ]; then',
        '  echo "[VibeGuard] Secrets detected. Commit blocked."',
        '  exit "$status"',
        'fi',
        '',
        'exit 0',
        '',
    ].join('\n');
}

function createPreCommitHook(projectRoot) {
    const gitDir = path.join(projectRoot, '.git');
    if (!fs.existsSync(gitDir)) {
        throw new AppError('GIT_DIR_NOT_FOUND', `No .git directory found at: ${gitDir}`, {
            details: { projectRoot },
        });
    }

    const hooksDir = path.join(gitDir, 'hooks');
    const hookPath = path.join(hooksDir, 'pre-commit');
    const backupPath = path.join(hooksDir, 'pre-commit.vibeguard-backup');
    const cliPath = path.resolve(__dirname, '..', '..', 'bin', 'vsg');
    const hookScript = buildPreCommitHook(cliPath);

    fs.mkdirSync(hooksDir, { recursive: true });

    if (fs.existsSync(hookPath)) {
        const existing = fs.readFileSync(hookPath, 'utf8');
        if (existing.trim() && !existing.includes(HOOK_MARKER) && !fs.existsSync(backupPath)) {
            fs.copyFileSync(hookPath, backupPath);
        }
    }

    fs.writeFileSync(hookPath, hookScript, 'utf8');
    fs.chmodSync(hookPath, 0o755);

    return {
        hookPath,
        backupPath: fs.existsSync(backupPath) ? backupPath : null,
    };
}

module.exports = { createPreCommitHook, buildPreCommitHook };
