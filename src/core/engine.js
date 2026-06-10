import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
import { shannonEntropy } from '../utils/entropy.js';
import { loadConfig } from '../utils/config.js';
import { getScanTargets, isSupportedSourceFile } from '../utils/git.js';
import { filterIgnoredFiles, loadIgnorePolicy } from '../utils/ignore.js';

const traverse = traverseModule.default ?? traverseModule;
const SECRET_NAME_PATTERN = /secret|token|key|password|auth/i;
const DEFAULT_ENTROPY_THRESHOLD = 4.0;
const DEFAULT_MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;
const PLACEHOLDER_VALUES = new Set([
  'test',
  'testing',
  'password',
  'secret',
  'token',
  'apikey',
  'api-key',
  'api_key',
  'your-api-key',
  'your_api_key',
  'your api key',
  'your-token',
  'your_token',
  'your-secret',
  'your_secret',
  'change-me',
  'changeme',
  'replace-me',
  'placeholder',
  'example',
  'sample',
  'dummy',
  'fake',
]);

function parserPluginsForFile(filepath) {
  const extension = path.extname(filepath).toLowerCase();
  const plugins = [
    'jsx',
    'classProperties',
    'classPrivateProperties',
    'objectRestSpread',
    'optionalChaining',
    'nullishCoalescingOperator',
    'topLevelAwait',
    'dynamicImport',
    'importAttributes',
  ];

  if (extension === '.ts' || extension === '.tsx') {
    plugins.push('typescript');
  }

  return plugins;
}

function parseSource(source, filepath) {
  return parse(source, {
    sourceType: 'unambiguous',
    errorRecovery: true,
    ranges: false,
    tokens: false,
    plugins: parserPluginsForFile(filepath),
  });
}

function identifierToEnvName(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
}

function propertyName(node) {
  if (!node) {
    return null;
  }

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'StringLiteral' || node.type === 'NumericLiteral') {
    return String(node.value);
  }

  if (node.type === 'PrivateName') {
    return node.id?.name ?? null;
  }

  return null;
}

function bindingName(node) {
  if (!node) {
    return null;
  }

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'ObjectPattern' || node.type === 'ArrayPattern') {
    return null;
  }

  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    return propertyName(node.property);
  }

  return null;
}

function stringLiteralValue(node) {
  if (!node) {
    return null;
  }

  if (node.type === 'StringLiteral') {
    return {
      value: node.value,
      start: node.start,
      end: node.end,
    };
  }

  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return {
      value: node.quasis[0]?.value?.cooked ?? node.quasis[0]?.value?.raw ?? '',
      start: node.start,
      end: node.end,
    };
  }

  return null;
}

function isSecretName(name) {
  return typeof name === 'string' && SECRET_NAME_PATTERN.test(name);
}

function normalizeCandidateValue(value) {
  return String(value)
    .trim()
    .replace(/^['"`]+|['"`]+$/g, '')
    .toLowerCase();
}

function isObviousPlaceholder(value) {
  const normalized = normalizeCandidateValue(value);

  if (PLACEHOLDER_VALUES.has(normalized)) {
    return true;
  }

  if (/^\$\{[a-z0-9_]+\}$/i.test(normalized)) {
    return true;
  }

  if (/^(x+|a+|0+|1+)$/.test(normalized)) {
    return true;
  }

  if (/^your[-_\s]?(api[-_\s]?key|key|token|secret|password)$/.test(normalized)) {
    return true;
  }

  if (/^(example|sample|dummy|fake|test)[-_\s]?(api[-_\s]?key|key|token|secret|password)?$/.test(normalized)) {
    return true;
  }

  return /^(api[-_\s]?key|key|token|secret|password)[-_\s]?(here|value|example|sample|test)$/.test(normalized);
}

function confidenceForEntropy(entropy, threshold) {
  const margin = entropy - threshold;

  if (margin >= 1.25) {
    return 'high';
  }

  if (margin >= 0.5) {
    return 'medium';
  }

  return 'low';
}

function createFinding({ filepath, source, name, literal, nodeType, threshold }) {
  if (!literal || typeof literal.start !== 'number' || typeof literal.end !== 'number') {
    return null;
  }

  if (isObviousPlaceholder(literal.value)) {
    return null;
  }

  const entropy = shannonEntropy(literal.value);
  if (entropy <= threshold) {
    return null;
  }

  const prefix = source.slice(0, literal.start);
  const line = prefix.split(/\r?\n/).length;
  const column = prefix.length - Math.max(prefix.lastIndexOf('\n'), prefix.lastIndexOf('\r\n')) - 1;

  return {
    file: filepath,
    relativeFile: path.relative(process.cwd(), filepath),
    identifier: name,
    envName: identifierToEnvName(name),
    value: literal.value,
    entropy,
    threshold,
    confidence: confidenceForEntropy(entropy, threshold),
    reason: `sensitive identifier "${name}" has entropy ${entropy.toFixed(2)} above threshold ${threshold.toFixed(2)}`,
    nodeType,
    literalStart: literal.start,
    literalEnd: literal.end,
    line,
    column,
  };
}

export async function scanFile(filepath, options = {}) {
  const absoluteFile = path.resolve(filepath);
  const threshold = options.entropyThreshold ?? DEFAULT_ENTROPY_THRESHOLD;
  const maxFileSizeBytes = options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;

  if (!isSupportedSourceFile(absoluteFile)) {
    return [];
  }

  const details = await stat(absoluteFile);
  if (!details.isFile() || details.size === 0) {
    return [];
  }

  if (maxFileSizeBytes > 0 && details.size > maxFileSizeBytes) {
    const error = new Error(`Skipped file larger than ${maxFileSizeBytes} bytes`);
    error.code = 'VIBEGUARD_FILE_TOO_LARGE';
    error.scanWarning = true;
    throw error;
  }

  const source = await readFile(absoluteFile, 'utf8');
  const ast = parseSource(source, absoluteFile);
  const findings = [];

  function consider({ name, literal, nodeType }) {
    if (!isSecretName(name)) {
      return;
    }

    const finding = createFinding({
      filepath: absoluteFile,
      source,
      name,
      literal,
      nodeType,
      threshold,
    });

    if (finding) {
      findings.push(finding);
    }
  }

  traverse(ast, {
    VariableDeclarator(pathRef) {
      const name = bindingName(pathRef.node.id);
      consider({
        name,
        literal: stringLiteralValue(pathRef.node.init),
        nodeType: 'VariableDeclarator',
      });
    },

    AssignmentExpression(pathRef) {
      const name = bindingName(pathRef.node.left);
      consider({
        name,
        literal: stringLiteralValue(pathRef.node.right),
        nodeType: 'AssignmentExpression',
      });
    },

    ObjectProperty(pathRef) {
      const name = propertyName(pathRef.node.key);
      consider({
        name,
        literal: stringLiteralValue(pathRef.node.value),
        nodeType: 'ObjectProperty',
      });
    },

    ClassProperty(pathRef) {
      const name = propertyName(pathRef.node.key);
      consider({
        name,
        literal: stringLiteralValue(pathRef.node.value),
        nodeType: 'ClassProperty',
      });
    },
  });

  return findings;
}

export async function scanProject(options = {}) {
  const projectRoot = path.resolve(options.projectRoot ?? process.cwd());
  const config = await loadConfig({ projectRoot });
  const entropyThreshold = options.entropyThreshold ?? config.entropyThreshold ?? DEFAULT_ENTROPY_THRESHOLD;
  const maxFileSizeBytes = options.maxFileSizeBytes ?? config.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;
  const scanTargets = await getScanTargets(projectRoot, {
    path: options.path ?? projectRoot,
    stagedOnly: options.stagedOnly ?? false,
  });
  const ignorePolicy = await loadIgnorePolicy({
    projectRoot,
    path: options.path ?? projectRoot,
    extraPatterns: config.ignoredPaths,
  });
  const scannedFiles = filterIgnoredFiles(scanTargets.files, ignorePolicy);
  const findings = [];
  const parseErrors = [];
  const scanWarnings = [];

  for (const file of scannedFiles) {
    try {
      findings.push(...(await scanFile(file, {
        ...options,
        entropyThreshold,
        maxFileSizeBytes,
      })));
    } catch (error) {
      const target = error.scanWarning ? scanWarnings : parseErrors;
      target.push({
        file,
        message: error.message,
      });
    }
  }

  return {
    projectRoot,
    mode: scanTargets.mode,
    scannedFiles,
    ignoredFiles: scanTargets.files.filter((file) => !scannedFiles.includes(file)),
    ignoreFile: ignorePolicy.ignoreFile,
    configFile: config.configFile,
    findings,
    parseErrors,
    scanWarnings,
  };
}

export {
  DEFAULT_ENTROPY_THRESHOLD,
  DEFAULT_MAX_FILE_SIZE_BYTES,
  SECRET_NAME_PATTERN,
  identifierToEnvName,
  isObviousPlaceholder,
};
