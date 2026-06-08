import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { scanFile, scanProject } from '../src/core/engine.js';
import { abstractFindings } from '../src/core/remediator.js';
import { buildHookScript, installPreCommitHook } from '../src/protector.js';
import { shannonEntropy } from '../src/utils/entropy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..');
const execFileAsync = promisify(execFile);

async function runCli(args, options = {}) {
  try {
    const result = await execFileAsync(process.execPath, [path.join(projectRoot, 'bin/vsg'), ...args], {
      cwd: projectRoot,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
      ...options,
    });
    return {
      code: 0,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  } catch (error) {
    return {
      code: error.code,
      stdout: error.stdout,
      stderr: error.stderr,
    };
  }
}

async function run() {
  const genericFile = path.join(__dirname, 'generic-secrets.js');
  const safeFile = path.join(__dirname, 'safe-code.js');

  assert.equal(Number(shannonEntropy('aaaaaaaaaaaaaaaa').toFixed(2)), 0);
  assert.ok(shannonEntropy('f9uQpL7xZ2vN4mR8sT1bC6dE3hJ5kW0y') > 4.0);

  const genericFindings = await scanFile(genericFile);
  assert.equal(genericFindings.length, 3);
  assert.deepEqual(
    genericFindings.map((finding) => finding.identifier).sort(),
    ['apiKey', 'authSecret', 'serviceToken'].sort(),
  );

  const safeFindings = await scanFile(safeFile);
  assert.equal(safeFindings.length, 0);

  const cleanCi = await runCli(['scan', '--ci', '--path', safeFile]);
  assert.equal(cleanCi.code, 0);
  assert.equal(JSON.parse(cleanCi.stdout).summary.findings, 0);

  const blockedCi = await runCli(['scan', '--ci', '--path', genericFile]);
  assert.equal(blockedCi.code, 1);
  const blockedPayload = JSON.parse(blockedCi.stdout);
  assert.equal(blockedPayload.summary.findings, 3);
  assert.equal(blockedPayload.findings[0].value, undefined);

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), 'vibeguard-'));
  const tempSource = path.join(tempRoot, 'sample.js');
  await writeFile(
    tempSource,
    [
      "const accessToken = 'R7tY2uIoP9aSdFgH4jKlZxCvBnM6qWeR';",
      "const config = { authSecret: 'Hj8Kp2Lm5Nq9Rs3Tv6Wx1Yz4Ab7Cd0Ef' };",
      "client.apiKey = 'Qw4Er7Ty1Ui8Op2As9Df3Gh6Jk5Lz0Xc';",
      '',
    ].join('\n'),
    'utf8',
  );

  const projectScan = await scanProject({ projectRoot: tempRoot });
  assert.equal(projectScan.findings.length, 3);

  const remediation = await abstractFindings(projectScan.findings, { projectRoot: tempRoot });
  assert.equal(remediation.remediated.length, 3);

  const remediatedSource = await readFile(tempSource, 'utf8');
  const envContent = await readFile(path.join(tempRoot, '.env'), 'utf8');
  const gitignoreContent = await readFile(path.join(tempRoot, '.gitignore'), 'utf8');

  assert.ok(remediatedSource.includes('process.env.ACCESS_TOKEN'));
  assert.ok(remediatedSource.includes('process.env.AUTH_SECRET'));
  assert.ok(remediatedSource.includes('process.env.API_KEY'));
  assert.ok(envContent.includes('ACCESS_TOKEN="R7tY2uIoP9aSdFgH4jKlZxCvBnM6qWeR"'));
  assert.ok(envContent.includes('AUTH_SECRET="Hj8Kp2Lm5Nq9Rs3Tv6Wx1Yz4Ab7Cd0Ef"'));
  assert.ok(envContent.includes('API_KEY="Qw4Er7Ty1Ui8Op2As9Df3Gh6Jk5Lz0Xc"'));
  assert.ok(gitignoreContent.split(/\r?\n/).includes('.env*'));

  await rm(tempRoot, { recursive: true, force: true });

  const hookScript = buildHookScript();
  assert.ok(hookScript.includes('npx vibeguard scan --ci'));
  assert.ok(hookScript.includes('npx.cmd vibeguard scan --ci'));
  assert.ok(hookScript.includes('powershell.exe'));

  const gitRoot = await mkdtemp(path.join(os.tmpdir(), 'vibeguard-git-'));
  await execFileAsync('git', ['init'], { cwd: gitRoot, windowsHide: true });
  const emptyStagedScan = await runCli(['scan', '--ci'], { cwd: gitRoot });
  assert.equal(emptyStagedScan.code, 0);
  assert.equal(JSON.parse(emptyStagedScan.stdout).summary.scannedFiles, 0);

  const stagedSecret = path.join(gitRoot, 'staged-secret.js');
  await writeFile(stagedSecret, "const deployToken = 'R7tY2uIoP9aSdFgH4jKlZxCvBnM6qWeR';\n", 'utf8');
  await execFileAsync('git', ['add', 'staged-secret.js'], { cwd: gitRoot, windowsHide: true });
  const stagedScan = await runCli(['scan', '--ci'], { cwd: gitRoot });
  assert.equal(stagedScan.code, 1);
  assert.equal(JSON.parse(stagedScan.stdout).summary.findings, 1);

  const hookPath = path.join(gitRoot, '.git', 'hooks', 'pre-commit');
  await writeFile(hookPath, '#!/bin/sh\necho "existing hook"\n', 'utf8');
  await installPreCommitHook({ cwd: gitRoot });
  await installPreCommitHook({ cwd: gitRoot });
  const installedHook = await readFile(hookPath, 'utf8');
  assert.ok(installedHook.includes('echo "existing hook"'));
  assert.equal((installedHook.match(/# >>> VibeGuard Sentinel >>>/g) ?? []).length, 1);
  assert.ok((installedHook.match(/npx vibeguard scan --ci/g) ?? []).length >= 1);
  await rm(gitRoot, { recursive: true, force: true });
}

await run();
console.log('VibeGuard MVP tests passed.');
