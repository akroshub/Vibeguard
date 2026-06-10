import { readFile } from 'node:fs/promises';
import path from 'node:path';

function stringList(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item) => typeof item === 'string' && item.trim().length > 0);
}

function numberOption(value) {
  return Number.isFinite(value) && value > 0 ? value : undefined;
}

export async function loadConfig(options = {}) {
  const projectRoot = path.resolve(options.projectRoot ?? process.cwd());
  const configFile = path.join(projectRoot, '.vibeguardrc');

  try {
    const content = await readFile(configFile, 'utf8');
    const parsed = JSON.parse(content);

    return {
      configFile,
      entropyThreshold: numberOption(parsed.entropyThreshold ?? parsed.threshold),
      ignoredPaths: stringList(parsed.ignoredPaths ?? parsed.ignore ?? parsed.ignores),
      maxFileSizeBytes: numberOption(parsed.maxFileSizeBytes),
    };
  } catch (error) {
    if (error.code === 'ENOENT') {
      return {
        configFile,
        entropyThreshold: undefined,
        ignoredPaths: [],
        maxFileSizeBytes: undefined,
      };
    }

    if (error instanceof SyntaxError) {
      throw new Error(`Invalid .vibeguardrc JSON: ${error.message}`);
    }

    throw error;
  }
}
