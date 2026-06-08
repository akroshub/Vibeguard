import path from 'node:path';
import process from 'node:process';
import pc from 'picocolors';
import prompts from 'prompts';
import { DEFAULT_ENTROPY_THRESHOLD, scanProject } from './core/engine.js';
import { abstractFindings } from './core/remediator.js';

function parseArgs(argv = []) {
  const options = {
    scan: false,
    dryRun: false,
    yes: false,
    json: false,
    ci: false,
    silent: false,
    pathProvided: false,
    path: process.cwd(),
    entropyThreshold: DEFAULT_ENTROPY_THRESHOLD,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === 'scan' || arg === '--scan') {
      options.scan = true;
    } else if (arg === '--dry-run') {
      options.dryRun = true;
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
    entropy: Number(finding.entropy.toFixed(4)),
    threshold: finding.threshold,
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
    summary: {
      scannedFiles: scan.scannedFiles.length,
      findings: scan.findings.length,
      parseErrors: scan.parseErrors.length,
    },
  };
}

function formatFinding(finding, projectRoot) {
  const relativeFile = path.relative(projectRoot, finding.file);
  const location = `${relativeFile}:${finding.line}:${finding.column + 1}`;
  return `${pc.yellow(location)} ${pc.cyan(finding.identifier)} entropy=${finding.entropy.toFixed(2)}`;
}

async function chooseFindings(findings, options, projectRoot) {
  if (options.yes) {
    return findings;
  }

  const selected = [];

  for (const finding of findings) {
    const relativeFile = path.relative(projectRoot, finding.file);
    const answer = await prompts(
      {
        type: 'confirm',
        name: 'abstract',
        message: `Suspicious high-entropy token found in ${relativeFile}. Abstract to .env?`,
        initial: true,
      },
      {
        onCancel: () => {
          throw new Error('Scan cancelled by user.');
        },
      },
    );

    if (answer.abstract) {
      selected.push(finding);
    }
  }

  return selected;
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
    if (scan.findings.length > 0) {
      process.exitCode = 1;
    }
    return scan;
  }

  if (options.json) {
    process.stdout.write(`${JSON.stringify(scan, null, 2)}\n`);
    return scan;
  }

  process.stdout.write(`${pc.bold('VibeGuard')} ${pc.dim(`AST+entropy scan (${scan.mode})`)}\n`);
  process.stdout.write(`${pc.dim(`Scanned ${scan.scannedFiles.length} source file(s).`)}\n`);

  for (const parseError of scan.parseErrors) {
    process.stderr.write(`${pc.red('Parse warning:')} ${parseError.file} ${parseError.message}\n`);
  }

  if (scan.findings.length === 0) {
    process.stdout.write(`${pc.green('No validated high-entropy secrets found.')}\n`);
    return scan;
  }

  process.stdout.write(`${pc.red(`Found ${scan.findings.length} validated secret candidate(s):`)}\n`);
  for (const finding of scan.findings) {
    process.stdout.write(`  ${formatFinding(finding, scan.projectRoot)}\n`);
  }

  if (options.dryRun) {
    process.stdout.write(`${pc.yellow('Dry run enabled. No files were changed.')}\n`);
    return scan;
  }

  const selected = await chooseFindings(scan.findings, options, scan.projectRoot);
  if (selected.length === 0) {
    process.stdout.write(`${pc.dim('No remediations selected.')}\n`);
    return scan;
  }

  const result = await abstractFindings(selected, {
    projectRoot: scan.projectRoot,
    dryRun: options.dryRun,
  });

  process.stdout.write(`${pc.green(`Abstracted ${result.remediated.length} secret(s) into ${path.relative(scan.projectRoot, result.envFile)}.`)}\n`);
  process.stdout.write(`${pc.dim(`Ensured ${path.relative(scan.projectRoot, result.gitignoreFile)} ignores .env*.`)}\n`);

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
    process.exitCode = 1;
  }
}
