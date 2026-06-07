const fs = require('node:fs');
const path = require('node:path');
const { AppError } = require('../errors/AppError');
const { getRules, isPlaceholder } = require('../rules');
const { isIgnoredDirectoryName, shouldScanFile } = require('./ignore-policy');

function shouldSkipLine(line) {
    const stripped = line.trim();
    return (
        stripped.startsWith('#') ||
        stripped.startsWith('//') ||
        line.includes('process.env.') ||
        line.includes('os.environ')
    );
}

function toFinding(rule, match, filepath, lineNumber) {
    return {
        ruleId: rule.id,
        patternName: rule.id,
        match,
        envVarName: rule.envVarName,
        env_var_name: rule.envVarName,
        description: rule.description,
        severity: rule.severity || 'medium',
        filepath,
        lineNumber,
    };
}

function runRegexRule(rule, line) {
    const findings = [];
    rule.regex.lastIndex = 0;

    let match;
    while ((match = rule.regex.exec(line)) !== null) {
        const value = match[0];
        if (value.length < (rule.minLength || 1)) continue;
        if (isPlaceholder(value)) continue;
        findings.push({ match: value });
    }

    return findings;
}

function runRule(rule, context) {
    if (typeof rule.detect === 'function') {
        return rule.detect(context);
    }

    if (rule.regex) {
        return runRegexRule(rule, context.line);
    }

    return [];
}

function scanLine(line, options = {}) {
    if (shouldSkipLine(line)) return [];

    const filepath = options.filepath || '';
    const lineNumber = options.lineNumber || 1;
    const rules = options.rules || getRules();
    const findings = [];

    for (const rule of rules) {
        const ruleMatches = runRule(rule, {
            line,
            filepath,
            lineNumber,
            existingFindings: findings,
            isPlaceholder,
        });

        for (const ruleMatch of ruleMatches) {
            findings.push(toFinding(rule, ruleMatch.match, filepath, lineNumber));
        }
    }

    return findings;
}

function walkFiles(directory, options = {}) {
    const files = [];
    let entries;

    try {
        entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch (cause) {
        if (options.onError) {
            options.onError(new AppError('DIRECTORY_READ_FAILED', `Unable to read directory: ${directory}`, {
                cause,
                recoverable: true,
                details: { directory },
            }));
        }
        return files;
    }

    for (const entry of entries) {
        if (entry.isDirectory() && isIgnoredDirectoryName(entry.name)) continue;

        const fullPath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
            files.push(...walkFiles(fullPath, options));
        } else {
            files.push(fullPath);
        }
    }

    return files;
}

async function scanFile(filepath, options = {}) {
    const stats = options.stats;
    if (!shouldScanFile(filepath)) return [];

    if (stats) {
        stats.filesScanned += 1;
    }

    let content;
    try {
        content = fs.readFileSync(filepath, 'utf8');
    } catch (cause) {
        if (stats) stats.errors += 1;
        if (options.reporter) {
            options.reporter.warning(new AppError('FILE_READ_FAILED', `Unable to read file: ${filepath}`, {
                cause,
                recoverable: true,
                details: { filepath },
            }));
        }
        return [];
    }

    const findings = [];
    const lines = content.split(/\r?\n/);

    let skipFile = false;

    for (let index = 0; index < lines.length; index += 1) {
        if (skipFile) break;

        const line = lines[index];
        const lineFindings = scanLine(line, {
            filepath,
            lineNumber: index + 1,
            rules: options.rules,
        });

        for (const finding of lineFindings) {
            findings.push(finding);
            if (stats) stats.findings += 1;
            if (options.onFinding) {
                const action = await options.onFinding(finding);
                if (action === 'skip-file') {
                    skipFile = true;
                    break;
                }
            }
        }
    }

    return findings;
}

async function scanProject(options) {
    const projectRoot = options.projectRoot;
    const scanPath = options.scanPath || projectRoot;
    const rules = options.rules || getRules();
    const stats = {
        filesVisited: 0,
        filesScanned: 0,
        findings: 0,
        errors: 0,
    };

    let target;
    try {
        target = fs.statSync(scanPath);
    } catch (cause) {
        stats.errors += 1;
        if (options.reporter) {
            options.reporter.warning(new AppError('PATH_STAT_FAILED', `Unable to inspect path: ${scanPath}`, {
                cause,
                recoverable: true,
                details: { path: scanPath },
            }));
        }
        return stats;
    }

    if (target.isFile()) {
        stats.filesVisited = 1;
        await scanFile(scanPath, {
            rules,
            reporter: options.reporter,
            onFinding: options.onFinding,
            stats,
        });
        return stats;
    }

    const files = walkFiles(scanPath, {
        onError(error) {
            stats.errors += 1;
            if (options.reporter) options.reporter.warning(error);
        },
    });

    stats.filesVisited = files.length;

    for (const file of files) {
        await scanFile(file, {
            rules,
            reporter: options.reporter,
            onFinding: options.onFinding,
            stats,
        });
    }

    return stats;
}

module.exports = {
    scanProject,
    scanFile,
    scanLine,
    walkFiles,
};
