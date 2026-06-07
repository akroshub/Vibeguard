const fs = require('node:fs');
const path = require('node:path');

function publicFinding(finding) {
    return {
        ruleId: finding.ruleId,
        description: finding.description,
        severity: finding.severity,
        envVarName: finding.envVarName,
        filepath: finding.filepath,
        lineNumber: finding.lineNumber,
    };
}

function escapeMarkdown(value) {
    return String(value || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function markdownReport(findings, stats, projectRoot) {
    const lines = [
        '# VibeGuard Security Report',
        '',
        `Generated: ${new Date().toISOString()}`,
        '',
        `Files scanned: ${stats.filesScanned}`,
        `Findings: ${stats.findings}`,
        `Errors: ${stats.errors}`,
        '',
    ];

    if (!findings.length) {
        lines.push('No findings detected.', '');
        return lines.join('\n');
    }

    lines.push('| Severity | Rule | Type | File | Line | Env Var |');
    lines.push('| --- | --- | --- | --- | ---: | --- |');

    for (const finding of findings) {
        const relativeFile = path.relative(projectRoot, finding.filepath) || finding.filepath;
        lines.push([
            escapeMarkdown(finding.severity),
            escapeMarkdown(finding.ruleId),
            escapeMarkdown(finding.description),
            escapeMarkdown(relativeFile),
            escapeMarkdown(finding.lineNumber),
            escapeMarkdown(finding.envVarName),
        ].join(' | ').replace(/^/, '| ').replace(/$/, ' |'));
    }

    lines.push('');
    return lines.join('\n');
}

function createReporter(options = {}) {
    const logger = options.logger;
    const stdout = options.stdout || process.stdout;
    const json = Boolean(options.json);
    const quiet = Boolean(options.quiet);
    const reportType = options.report || null;
    const projectRoot = options.projectRoot || process.cwd();
    const findings = [];

    function writeJson(payload) {
        stdout.write(`${JSON.stringify(payload)}\n`);
    }

    return {
        start(projectRoot, mode) {
            if (json) {
                writeJson({ type: 'start', mode, projectRoot });
                return;
            }
            logger.info(`VibeGuard active in: ${projectRoot}`);
        },

        watching(projectRoot) {
            if (json) {
                writeJson({ type: 'watching', projectRoot });
                return;
            }
            logger.info('Watching for secrets... Press Ctrl+C to stop.');
        },

        hookInitialized(result) {
            if (json) {
                writeJson({ type: 'hook', result });
                return;
            }

            logger.info(`Git pre-commit hook installed at: ${result.hookPath}`);
            if (result.backupPath) {
                logger.info(`Existing hook backup: ${result.backupPath}`);
            }
        },

        finding(finding) {
            const safeFinding = publicFinding(finding);
            findings.push(safeFinding);

            if (json) {
                writeJson({ type: 'finding', finding: safeFinding });
                return;
            }

            if (reportType === 'md') return;
            if (quiet) return;
            logger.info('');
            logger.info('SECURITY FINDING');
            logger.info(`File     : ${safeFinding.filepath}`);
            logger.info(`Line     : ${safeFinding.lineNumber}`);
            logger.info(`Rule     : ${safeFinding.ruleId}`);
            logger.info(`Type     : ${safeFinding.description}`);
            logger.info(`Severity : ${safeFinding.severity}`);
        },

        remediation(result) {
            if (json) {
                writeJson({ type: 'remediation', result });
                return;
            }

            if (quiet) return;
            if (reportType === 'md') return;

            if (result.skipped) {
                logger.info(`Skipped remediation for ${result.filepath}`);
                return;
            }

            if (result.dryRun) {
                logger.info(`[DRY RUN] Would rewrite ${result.filepath}`);
                return;
            }

            if (result.rewritten) {
                logger.info(`Rewrote ${result.filepath} using ${result.replacement}`);
            }

            if (result.envUpdated) {
                logger.info(`Updated local .env with ${result.envVarName}`);
            }

            if (result.gitignoreUpdated) {
                logger.info('Updated .gitignore for local .env protection');
            }
        },

        warning(error) {
            logger.warn(error.message, {
                code: error.code,
                details: error.details,
            });
        },

        summary(stats) {
            if (json) {
                writeJson({ type: 'summary', stats });
                return;
            }

            if (reportType === 'md') {
                const reportPath = path.join(projectRoot, 'vsg-report.md');
                try {
                    fs.writeFileSync(reportPath, markdownReport(findings, stats, projectRoot), 'utf8');
                } catch (error) {
                    console.warn(`Warning: Unable to write Markdown report: ${error.message}`);
                    return;
                }
                if (!quiet) {
                    logger.info(`Markdown report written to: ${reportPath}`);
                }
                return;
            }

            logger.info('');
            logger.info(`Scan complete. Files scanned: ${stats.filesScanned}. Findings: ${stats.findings}. Errors: ${stats.errors}.`);
        },
    };
}

module.exports = { createReporter, publicFinding, markdownReport };
