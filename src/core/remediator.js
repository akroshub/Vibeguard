import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

function sourceReplacement(envName) {
  return `process.env.${envName}`;
}

function maskSecret(value) {
  const text = String(value);
  if (text.length <= 4) {
    return '****';
  }

  const prefix = text.match(/^[A-Za-z]{2,6}[-_]/)?.[0] ?? '';
  return `${prefix}****${text.slice(-4)}`;
}

function escapeEnvValue(value) {
  return JSON.stringify(String(value));
}

function splitEnvLine(line) {
  const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/);
  return match?.[1] ?? null;
}

async function readTextFile(filepath) {
  try {
    return await readFile(filepath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      return '';
    }
    throw error;
  }
}

async function atomicWrite(filepath, content) {
  await mkdir(path.dirname(filepath), { recursive: true });
  const temporaryFile = path.join(path.dirname(filepath), `.${path.basename(filepath)}.${process.pid}.${Date.now()}.tmp`);
  await writeFile(temporaryFile, content, 'utf8');
  await rename(temporaryFile, filepath);
}

function parseExistingEnv(content) {
  const names = new Map();

  for (const line of content.split(/\r?\n/)) {
    const name = splitEnvLine(line);
    if (name) {
      names.set(name, line.slice(line.indexOf('=') + 1));
    }
  }

  return names;
}

function uniqueEnvName(baseName, value, existingEnv) {
  const base = baseName || 'VIBEGUARD_SECRET';
  const encodedValue = escapeEnvValue(value);

  if (!existingEnv.has(base) || existingEnv.get(base) === encodedValue) {
    return {
      envName: base,
      warning: null,
    };
  }

  let suffix = 2;
  while (existingEnv.has(`${base}_${suffix}`) && existingEnv.get(`${base}_${suffix}`) !== encodedValue) {
    suffix += 1;
  }

  return {
    envName: `${base}_${suffix}`,
    warning: `${base} already exists in .env with a different value; using ${base}_${suffix} instead.`,
  };
}

function appendEnvEntries(content, entries) {
  const existingEnv = parseExistingEnv(content);
  let nextContent = content;
  const resolved = [];
  const envEntries = [];
  const warnings = [];

  for (const finding of entries) {
    const { envName, warning } = uniqueEnvName(finding.envName, finding.value, existingEnv);
    const encodedValue = escapeEnvValue(finding.value);
    let action = 'reuse';

    if (warning) {
      warnings.push(warning);
    }

    if (!existingEnv.has(envName)) {
      if (nextContent.length > 0 && !nextContent.endsWith('\n')) {
        nextContent += '\n';
      }
      nextContent += `${envName}=${encodedValue}\n`;
      existingEnv.set(envName, encodedValue);
      action = 'add';
    }

    envEntries.push({
      envName,
      action,
      maskedValue: maskSecret(finding.value),
    });

    resolved.push({
      ...finding,
      envName,
      replacement: sourceReplacement(envName),
    });
  }

  return {
    content: nextContent,
    findings: resolved,
    envEntries,
    warnings,
  };
}

function appendGitignoreEntry(content) {
  const lines = content.split(/\r?\n/).map((line) => line.trim());
  if (lines.includes('.env')) {
    return content;
  }

  let nextContent = content;
  if (nextContent.length > 0 && !nextContent.endsWith('\n')) {
    nextContent += '\n';
  }

  return `${nextContent}.env\n`;
}

function replaceFindingsInSource(source, findings) {
  const ordered = [...findings].sort((a, b) => b.literalStart - a.literalStart);
  let nextSource = source;

  for (const finding of ordered) {
    nextSource = `${nextSource.slice(0, finding.literalStart)}${finding.replacement}${nextSource.slice(finding.literalEnd)}`;
  }

  return nextSource;
}

export async function abstractFindings(findings, options = {}) {
  const projectRoot = path.resolve(options.projectRoot ?? process.cwd());
  const envFile = path.resolve(projectRoot, options.envFile ?? '.env');
  const gitignoreFile = path.resolve(projectRoot, '.gitignore');

  if (findings.length === 0) {
    return {
      remediated: [],
      envFile,
      gitignoreFile,
    };
  }

  const envContent = await readTextFile(envFile);
  const envUpdate = appendEnvEntries(envContent, findings);
  const gitignoreContent = await readTextFile(gitignoreFile);
  const nextGitignoreContent = appendGitignoreEntry(gitignoreContent);
  const gitignoreUpdated = nextGitignoreContent !== gitignoreContent;

  if (!options.dryRun) {
    await atomicWrite(envFile, envUpdate.content);
    if (gitignoreUpdated) {
      await atomicWrite(gitignoreFile, nextGitignoreContent);
    }
  }

  const byFile = new Map();
  for (const finding of envUpdate.findings) {
    const fileFindings = byFile.get(finding.file) ?? [];
    fileFindings.push(finding);
    byFile.set(finding.file, fileFindings);
  }

  for (const [file, fileFindings] of byFile) {
    const source = await readFile(file, 'utf8');
    const nextSource = replaceFindingsInSource(source, fileFindings);

    if (!options.dryRun) {
      await atomicWrite(file, nextSource);
    }
  }

  return {
    remediated: envUpdate.findings.map(({ value, ...finding }) => finding),
    envFile,
    gitignoreFile,
    envEntries: envUpdate.envEntries,
    warnings: envUpdate.warnings,
    gitignoreUpdated,
  };
}

export { appendGitignoreEntry, escapeEnvValue, maskSecret, sourceReplacement };
