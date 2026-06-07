const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { AppError } = require('../errors/AppError');
const { getEnvVarReplacement, applyLanguageImports } = require('./replacement');
const { ensureEnvEntry } = require('./env-file');
const { ensureGitignore } = require('./gitignore');

function canPrompt(options) {
    return Boolean(options.interactive && process.stdin.isTTY && process.stdout.isTTY);
}

function ask(question) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            rl.close();
            resolve(answer.trim().toLowerCase());
        });
    });
}

async function shouldRemediateInteractively(finding, options = {}) {
    if (!options.requireApproval) return true;
    if (!options.interactive) return false;
    if (!canPrompt(options)) return false;

    const filename = path.basename(finding.filepath);
    const answer = await ask(`[Vibeguard] Secret found in ${filename} (Line ${finding.lineNumber}). Safely move to .env and replace? (y/n): `);
    return answer === 'y' || answer === 'yes';
}

function rewriteSourceFile(finding, options = {}) {
    const replacement = getEnvVarReplacement(finding.envVarName, finding.filepath);

    let content;
    try {
        content = fs.readFileSync(finding.filepath, 'utf8');
    } catch (cause) {
        return {
            ok: false,
            error: new AppError('REMEDIATION_READ_FAILED', `Unable to read file for remediation: ${finding.filepath}`, {
                cause,
                recoverable: true,
                details: { filepath: finding.filepath },
            }),
        };
    }

    if (!content.includes(finding.match)) {
        return {
            ok: false,
            skipped: true,
            replacement,
        };
    }

    let nextContent = content.split(finding.match).join(replacement);
    nextContent = applyLanguageImports(nextContent, finding.filepath);

    if (options.dryRun) {
        return {
            ok: true,
            dryRun: true,
            rewritten: false,
            replacement,
        };
    }

    try {
        fs.writeFileSync(finding.filepath, nextContent, 'utf8');
    } catch (cause) {
        return {
            ok: false,
            error: new AppError('REMEDIATION_WRITE_FAILED', `Unable to write remediation to file: ${finding.filepath}`, {
                cause,
                recoverable: true,
                details: { filepath: finding.filepath },
            }),
        };
    }

    return {
        ok: true,
        dryRun: false,
        rewritten: true,
        replacement,
    };
}

async function remediate(finding, options = {}) {
    const reporter = options.reporter;
    if (reporter) reporter.finding(finding);

    const approved = await shouldRemediateInteractively(finding, options);
    if (!approved) {
        const action = options.continueOnSkip ? 'skip-remediation' : 'skip-file';
        const result = {
            filepath: finding.filepath,
            envVarName: finding.envVarName,
            skipped: true,
            action,
            dryRun: Boolean(options.dryRun),
        };
        if (reporter) reporter.remediation(result);
        return result;
    }

    const rewrite = rewriteSourceFile(finding, {
        dryRun: options.dryRun,
    });

    if (!rewrite.ok) {
        if (rewrite.error && reporter) reporter.warning(rewrite.error);
        return rewrite;
    }

    let envResult = { changed: false };
    let gitignoreResult = { changed: false };

    if (!options.dryRun) {
        envResult = ensureEnvEntry(options.projectRoot, finding.envVarName);
        gitignoreResult = ensureGitignore(options.projectRoot);
    }

    const result = {
        filepath: finding.filepath,
        envVarName: finding.envVarName,
        replacement: rewrite.replacement,
        rewritten: rewrite.rewritten,
        dryRun: Boolean(options.dryRun),
        envUpdated: envResult.changed,
        gitignoreUpdated: gitignoreResult.changed,
    };

    if (reporter) reporter.remediation(result);
    return result;
}

module.exports = {
    remediate,
    rewriteSourceFile,
};
