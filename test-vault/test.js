import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { isObviousPlaceholder, scanFile, scanProject } from '../src/core/engine.js';
import { abstractFindings, maskSecret } from '../src/core/remediator.js';
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

async function exists(filepath) {
  try {
    await access(filepath);
    return true;
  } catch {
    return false;
  }
}

async function run() {
  const genericFile = path.join(__dirname, 'generic-secrets.js');
  const safeFile = path.join(__dirname, 'safe-code.js');

  assert.equal(Number(shannonEntropy('aaaaaaaaaaaaaaaa').toFixed(2)), 0);
  assert.ok(shannonEntropy('f9uQpL7xZ2vN4mR8sT1bC6dE3hJ5kW0y') > 4.0);
  assert.equal(maskSecret('sk-1234567890abcd'), 'sk-****abcd');
  assert.equal(isObviousPlaceholder('your-api-key'), true);

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
  assert.ok(blockedPayload.findings[0].maskedValue.includes('****'));
  assert.ok(blockedPayload.findings[0].reason.includes('entropy'));
  assert.ok(['low', 'medium', 'high'].includes(blockedPayload.findings[0].confidence));

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
  assert.ok(gitignoreContent.split(/\r?\n/).includes('.env'));

  await rm(tempRoot, { recursive: true, force: true });

  const cliRoot = await mkdtemp(path.join(os.tmpdir(), 'vibeguard-cli-'));
  const cliSource = path.join(cliRoot, 'app.js');
  const cliSecret = 'R7tY2uIoP9aSdFgH4jKlZxCvBnM6qWeR';
  await writeFile(cliSource, `const deployToken = '${cliSecret}';\n`, 'utf8');
  const originalCliSource = await readFile(cliSource, 'utf8');

  const scanOnly = await runCli(['scan', '--path', cliSource], { cwd: cliRoot });
  assert.equal(scanOnly.code, 1);
  assert.ok(scanOnly.stdout.includes('Scan-only mode'));
  assert.equal(await readFile(cliSource, 'utf8'), originalCliSource);
  assert.equal(await exists(path.join(cliRoot, '.env')), false);
  assert.equal(scanOnly.stdout.includes(cliSecret), false);

  const dryRun = await runCli(['scan', '--path', cliSource, '--dry-run'], { cwd: cliRoot });
  assert.equal(dryRun.code, 1);
  assert.ok(dryRun.stdout.includes('Remediation preview'));
  assert.ok(dryRun.stdout.includes('process.env.DEPLOY_TOKEN'));
  assert.equal(dryRun.stdout.includes(cliSecret), false);
  assert.equal(await readFile(cliSource, 'utf8'), originalCliSource);
  assert.equal(await exists(path.join(cliRoot, '.env')), false);

  const jsonScan = await runCli(['scan', '--path', cliSource, '--json'], { cwd: cliRoot });
  assert.equal(jsonScan.code, 1);
  assert.equal(jsonScan.stdout.includes(cliSecret), false);
  const jsonPayload = JSON.parse(jsonScan.stdout);
  assert.equal(jsonPayload.findings[0].value, undefined);
  assert.ok(jsonPayload.findings[0].maskedValue.endsWith('qWeR'));

  await writeFile(path.join(cliRoot, '.env'), 'DEPLOY_TOKEN="already-set"\n', 'utf8');
  await writeFile(path.join(cliRoot, '.gitignore'), '.env\n', 'utf8');
  const fixed = await runCli(['scan', '--path', cliSource, '--fix', '--yes'], { cwd: cliRoot });
  assert.equal(fixed.code, 1);
  assert.ok(fixed.stdout.includes('Remediation preview'));
  assert.ok(fixed.stdout.includes('DEPLOY_TOKEN already exists'));
  assert.equal(fixed.stdout.includes(cliSecret), false);

  const fixedSource = await readFile(cliSource, 'utf8');
  const fixedEnv = await readFile(path.join(cliRoot, '.env'), 'utf8');
  const fixedGitignore = await readFile(path.join(cliRoot, '.gitignore'), 'utf8');
  assert.ok(fixedSource.includes('process.env.DEPLOY_TOKEN_2'));
  assert.ok(fixedEnv.includes('DEPLOY_TOKEN="already-set"'));
  assert.ok(fixedEnv.includes(`DEPLOY_TOKEN_2="${cliSecret}"`));
  assert.equal(fixedGitignore.split(/\r?\n/).filter((line) => line === '.env').length, 1);
  await rm(cliRoot, { recursive: true, force: true });

  const resilientRoot = await mkdtemp(path.join(os.tmpdir(), 'vibeguard-resilient-'));
  await writeFile(path.join(resilientRoot, 'empty.ts'), '', 'utf8');
  await writeFile(path.join(resilientRoot, 'broken.js'), 'const = ;\n', 'utf8');
  await writeFile(path.join(resilientRoot, 'large.js'), `const apiKey = '${'A'.repeat(2048)}';\n`, 'utf8');
  const resilientScan = await scanProject({ projectRoot: resilientRoot, maxFileSizeBytes: 64 });
  assert.equal(resilientScan.findings.length, 0);
  assert.equal(resilientScan.scanWarnings.length, 1);
  assert.equal(resilientScan.parseErrors.length, 1);
  const resilientCli = await runCli(['scan', '--path', resilientRoot], { cwd: resilientRoot });
  assert.equal(resilientCli.code, 2);
  await rm(resilientRoot, { recursive: true, force: true });

  const ignoreRoot = await mkdtemp(path.join(os.tmpdir(), 'vibeguard-ignore-'));
  await mkdir(path.join(ignoreRoot, 'node_modules'), { recursive: true });
  await mkdir(path.join(ignoreRoot, 'dist'), { recursive: true });
  await mkdir(path.join(ignoreRoot, 'src'), { recursive: true });
  await writeFile(path.join(ignoreRoot, 'node_modules', 'secret.js'), "const apiKey = 'Qw4Er7Ty1Ui8Op2As9Df3Gh6Jk5Lz0Xc';\n", 'utf8');
  await writeFile(path.join(ignoreRoot, 'dist', 'secret.js'), "const apiKey = 'Qw4Er7Ty1Ui8Op2As9Df3Gh6Jk5Lz0Xc';\n", 'utf8');
  await writeFile(path.join(ignoreRoot, 'src', 'app.js'), "const apiKey = 'Qw4Er7Ty1Ui8Op2As9Df3Gh6Jk5Lz0Xc';\n", 'utf8');
  const ignoreScan = await scanProject({ projectRoot: ignoreRoot });
  assert.equal(ignoreScan.findings.length, 1);
  assert.ok(ignoreScan.scannedFiles.every((file) => !file.includes('node_modules') && !file.includes(`${path.sep}dist${path.sep}`)));
  await rm(ignoreRoot, { recursive: true, force: true });

  const configRoot = await mkdtemp(path.join(os.tmpdir(), 'vibeguard-config-'));
  await mkdir(path.join(configRoot, 'ignored'), { recursive: true });
  await writeFile(path.join(configRoot, '.vibeguardrc'), JSON.stringify({ entropyThreshold: 10, ignoredPaths: ['ignored/**'] }), 'utf8');
  await writeFile(path.join(configRoot, 'app.js'), "const apiKey = 'Qw4Er7Ty1Ui8Op2As9Df3Gh6Jk5Lz0Xc';\n", 'utf8');
  await writeFile(path.join(configRoot, 'ignored', 'app.js'), "const apiKey = 'Qw4Er7Ty1Ui8Op2As9Df3Gh6Jk5Lz0Xc';\n", 'utf8');
  const configScan = await scanProject({ projectRoot: configRoot });
  assert.equal(configScan.findings.length, 0);
  const configOverrideScan = await scanProject({ projectRoot: configRoot, entropyThreshold: 4 });
  assert.equal(configOverrideScan.findings.length, 1);
  await rm(configRoot, { recursive: true, force: true });

  const badConfigRoot = await mkdtemp(path.join(os.tmpdir(), 'vibeguard-bad-config-'));
  await writeFile(path.join(badConfigRoot, '.vibeguardrc'), '{bad json', 'utf8');
  const badConfig = await runCli(['scan'], { cwd: badConfigRoot });
  assert.equal(badConfig.code, 2);
  assert.ok(badConfig.stderr.includes('Invalid .vibeguardrc JSON'));
  await rm(badConfigRoot, { recursive: true, force: true });

  const hookScript = buildHookScript();
  assert.ok(hookScript.includes('npx vibe-security-akoris scan --ci'));
  assert.ok(hookScript.includes('npx.cmd vibe-security-akoris scan --ci'));
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
  assert.ok((installedHook.match(/npx vibe-security-akoris scan --ci/g) ?? []).length >= 1);
  await rm(gitRoot, { recursive: true, force: true });
}

await run();
console.log('VibeGuard beta safety tests passed.');
