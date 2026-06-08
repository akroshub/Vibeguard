import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
import { shannonEntropy } from '../utils/entropy.js';
import { getScanTargets, isSupportedSourceFile } from '../utils/git.js';
import { filterIgnoredFiles, loadIgnorePolicy } from '../utils/ignore.js';

const traverse = traverseModule.default ?? traverseModule;
const SECRET_NAME_PATTERN = /secret|token|key|password|auth/i;
const DEFAULT_ENTROPY_THRESHOLD = 4.0;

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

function createFinding({ filepath, source, name, literal, nodeType, threshold }) {
  if (!literal || typeof literal.start !== 'number' || typeof literal.end !== 'number') {
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

  if (!isSupportedSourceFile(absoluteFile)) {
    return [];
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
  const scanTargets = await getScanTargets(projectRoot, {
    path: options.path ?? projectRoot,
    stagedOnly: options.stagedOnly ?? false,
  });
  const ignorePolicy = await loadIgnorePolicy({
    projectRoot,
    path: options.path ?? projectRoot,
  });
  const scannedFiles = filterIgnoredFiles(scanTargets.files, ignorePolicy);
  const findings = [];
  const parseErrors = [];

  for (const file of scannedFiles) {
    try {
      findings.push(...(await scanFile(file, options)));
    } catch (error) {
      parseErrors.push({
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
    findings,
    parseErrors,
  };
}

export { DEFAULT_ENTROPY_THRESHOLD, SECRET_NAME_PATTERN, identifierToEnvName };
