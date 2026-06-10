import path from 'node:path';
import process from 'node:process';
import pc from 'picocolors';
import prompts from 'prompts';
import { scanProject } from './core/engine.js';
import { abstractFindings, maskSecret } from './core/remediator.js';

function parseArgs(argv = []) {
  const options = {
    scan: false,
    dryRun: false,
    fix: false,
    yes: false,
    json: false,
    ci: false,
    silent: false,
    pathProvided: false,
    path: process.cwd(),
    entropyThreshold: undefined,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === 'scan' || arg === '--scan') {
      options.scan = true;
    } else if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--fix') {
      options.fix = true;
    } else if (arg === '--yes' || arg === '-y') {
      options.yes = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--ci') {
      options.ci = true;
      options.json = true;
      options.dryRun = true;
    } else if (arg === '--silent') {
      options.silent = true;
      options.json = true;
      options.dryRun = true;
    } else if (arg === '--threshold') {
      const threshold = Number(argv[index + 1]);
      if (Number.isFinite(threshold)) {
        options.entropyThreshold = threshold;
        index += 1;
      }
    } else if (arg === '--path') {
      options.path = path.resolve(argv[index + 1] ?? process.cwd());
      options.pathProvided = true;
      index += 1;
    } else if (!arg.startsWith('-')) {
      options.path = path.resolve(arg);
      options.pathProvided = true;
    }
  }

  return options;
}

function safeFinding(finding, projectRoot) {
  return {
    file: path.relative(projectRoot, finding.file),
    identifier: finding.identifier,
    envName: finding.envName,
    maskedValue: maskSecret(finding.value),
    entropy: Number(finding.entropy.toFixed(4)),
    threshold: finding.threshold,
    confidence: finding.confidence,
    reason: finding.reason,
    nodeType: finding.nodeType,
    line: finding.line,
    column: finding.column,
  };
}

function safeScan(scan) {
  return {
    mode: scan.mode,
    scannedFiles: scan.scannedFiles.map((file) => path.relative(scan.projectRoot, file)),
    findings: scan.findings.map((finding) => safeFinding(finding, scan.projectRoot)),
    parseErrors: scan.parseErrors.map((parseError) => ({
      file: path.relative(scan.projectRoot, parseError.file),
      message: parseError.message,
    })),
    scanWarnings: (scan.scanWarnings ?? []).map((warning) => ({
      file: path.relative(scan.projectRoot, warning.file),
      message: warning.message,
    })),
    summary: {
      scannedFiles: scan.scannedFiles.length,
      findings: scan.findings.length,
      parseErrors: scan.parseErrors.length,
      scanWarnings: (scan.scanWarnings ?? []).length,
    },
  };
}

function exitCodeForScan(scan) {
  if (scan.parseErrors.length > 0) {
    return 2;
  }

  if (scan.findings.length > 0) {
    return 1;
  }

  return 0;
}

function applyExitCode(scan) {
  process.exitCode = exitCodeForScan(scan);
}

function formatFinding(finding, projectRoot) {
  const relativeFile = path.relative(projectRoot, finding.file);
  const location = `${relativeFile}:${finding.line}:${finding.column + 1}`;
  return `${pc.yellow(location)} ${pc.cyan(finding.identifier)} confidence=${finding.confidence} ${finding.reason}`;
}

function formatRemediationPreview(result, projectRoot) {
  const lines = [`${pc.bold('Remediation preview:')}`];

  for (const finding of result.remediated) {
    const relativeFile = path.relative(projectRoot, finding.file);
    const location = `${relativeFile}:${finding.line}:${finding.column + 1}`;
    lines.push(`  ${pc.yellow(location)} ${finding.identifier} -> ${finding.replacement}`);
  }

  for (const entry of result.envEntries) {
    const action = entry.action === 'add' ? 'add' : 'reuse';
    lines.push(`  ${pc.cyan(path.relative(projectRoot, result.envFile))} ${action} ${entry.envName}=${entry.maskedValue}`);
  }

  const gitignoreAction = result.gitignoreUpdated ? 'add .env' : '.env already ignored';
  lines.push(`  ${pc.cyan(path.relative(projectRoot, result.gitignoreFile))} ${gitignoreAction}`);

  for (const warning of result.warnings) {
    lines.push(`  ${pc.yellow('Warning:')} ${warning}`);
  }

  return `${lines.join('\n')}\n`;
}

async function confirmFix(options) {
  if (options.yes) {
    return true;
  }

  const answer = await prompts(
    {
      type: 'confirm',
      name: 'apply',
      message: 'Apply these remediations now?',
      initial: false,
    },
    {
      onCancel: () => {
        throw new Error('Fix cancelled by user.');
      },
    },
  );

  return Boolean(answer.apply);
}

export async function run(argv = []) {
  const options = parseArgs(argv);
  const scan = await scanProject({
    projectRoot: process.cwd(),
    path: options.path,
    stagedOnly: (options.ci || options.silent) && !options.pathProvided,
    entropyThreshold: options.entropyThreshold,
  });

  if (options.ci || options.silent) {
    process.stdout.write(`${JSON.stringify(safeScan(scan), null, 2)}\n`);
    applyExitCode(scan);
    return scan;
  }

  if (options.json) {
    process.stdout.write(`${JSON.stringify(safeScan(scan), null, 2)}\n`);
    applyExitCode(scan);
    return scan;
  }

  process.stdout.write(`${pc.bold('VibeGuard')} ${pc.dim(`AST+entropy scan (${scan.mode})`)}\n`);
  process.stdout.write(`${pc.dim(`Scanned ${scan.scannedFiles.length} source file(s).`)}\n`);

  for (const parseError of scan.parseErrors) {
    process.stderr.write(`${pc.red('Parse warning:')} ${parseError.file} ${parseError.message}\n`);
  }

  for (const warning of scan.scanWarnings ?? []) {
    process.stderr.write(`${pc.yellow('Scan warning:')} ${warning.file} ${warning.message}\n`);
  }

  if (scan.findings.length === 0) {
    process.stdout.write(`${pc.green('No validated high-entropy secrets found.')}\n`);
    applyExitCode(scan);
    return scan;
  }

  process.stdout.write(`${pc.red(`Found ${scan.findings.length} validated secret candidate(s):`)}\n`);
  for (const finding of scan.findings) {
    process.stdout.write(`  ${formatFinding(finding, scan.projectRoot)}\n`);
  }

  if (options.dryRun) {
    const preview = await abstractFindings(scan.findings, {
      projectRoot: scan.projectRoot,
      dryRun: true,
    });
    process.stdout.write(formatRemediationPreview(preview, scan.projectRoot));
    process.stdout.write(`${pc.yellow('Dry run enabled. No files were changed.')}\n`);
    applyExitCode(scan);
    return scan;
  }

  if (!options.fix) {
    if (options.yes) {
      process.stdout.write(`${pc.yellow('--yes was provided without --fix, so no files were changed.')}\n`);
    }
    process.stdout.write(`${pc.dim('Scan-only mode. No files changed. Run with --dry-run to preview or --fix to remediate.')}\n`);
    applyExitCode(scan);
    return scan;
  }

  const preview = await abstractFindings(scan.findings, {
    projectRoot: scan.projectRoot,
    dryRun: true,
  });
  process.stdout.write(formatRemediationPreview(preview, scan.projectRoot));

  if (!(await confirmFix(options))) {
    process.stdout.write(`${pc.dim('No remediations applied.')}\n`);
    applyExitCode(scan);
    return scan;
  }

  const result = await abstractFindings(scan.findings, {
    projectRoot: scan.projectRoot,
    dryRun: false,
  });

  process.stdout.write(`${pc.green(`Abstracted ${result.remediated.length} secret(s) into ${path.relative(scan.projectRoot, result.envFile)}.`)}\n`);
  process.stdout.write(`${pc.dim(`Ensured ${path.relative(scan.projectRoot, result.gitignoreFile)} ignores .env.`)}\n`);
  applyExitCode(scan);

  return {
    ...scan,
    remediation: result,
  };
}

export async function main(argv = process.argv.slice(2)) {
  try {
    await run(argv);
  } catch (error) {
    process.stderr.write(`${pc.red('VibeGuard failed:')} ${error.message}\n`);
    process.exitCode = 2;
  }
}
