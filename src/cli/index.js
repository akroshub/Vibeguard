const fs = require('node:fs');
const path = require('node:path');
const { AppError } = require('../errors/AppError');
const { scanProject } = require('../core/scanner');
const { watchProject } = require('../core/watcher');
const { createPreCommitHook } = require('../core/git-hook');
const { remediate } = require('../remediation/index');
const { createLogger } = require('../output/logger');
const { createReporter } = require('../output/reporter');
const { parseCliArgs } = require('./args');

function createRuntime(options) {
    const logger = createLogger({
        quiet: options.quiet,
        json: options.json,
    });

    const reporter = createReporter({
        logger,
        quiet: options.quiet,
        json: options.json,
        report: options.report,
        projectRoot: options.projectRoot,
    });

    return { logger, reporter };
}

function resolvePaths(options) {
    const scanPath = options.scanPath || options.projectRoot;
    let stat;
    try {
        stat = fs.statSync(scanPath);
    } catch (cause) {
        throw new AppError('PATH_STAT_FAILED', `Unable to inspect path: ${scanPath}`, {
            cause,
            details: { path: scanPath },
        });
    }

    return {
        ...options,
        scanPath,
        projectRoot: stat.isFile() ? path.dirname(scanPath) : scanPath,
    };
}

function validateOptions(options) {
    if (options.report && options.report !== 'md') {
        throw new AppError('UNSUPPORTED_REPORT_TYPE', `Unsupported report type: ${options.report}`, {
            details: { supported: ['md'] },
        });
    }
}

function shouldFailOnFindings(stats) {
    return process.env.VSG_FAIL_ON_FINDINGS === '1' && stats.findings > 0;
}

async function initializeHook(options, reporter) {
    const result = createPreCommitHook(options.projectRoot);
    if (!options.quiet) {
        reporter.hookInitialized(result);
    }
    return result;
}

async function run(argv = process.argv.slice(2)) {
    const options = resolvePaths(parseCliArgs(argv));
    validateOptions(options);
    const { reporter } = createRuntime(options);

    if (options.initHook) {
        return initializeHook(options, reporter);
    }

    reporter.start(options.scanPath, options.scan ? 'scan' : 'watch');

    const onFinding = async (finding) => {
        const result = await remediate(finding, {
            projectRoot: options.projectRoot,
            dryRun: options.dryRun,
            requireApproval: options.scan && !options.dryRun && !options.quiet,
            interactive: options.scan && !options.dryRun && !options.quiet && !options.json,
            reporter,
        });

        return result.action;
    };

    if (options.scan) {
        const stats = await scanProject({
            projectRoot: options.projectRoot,
            scanPath: options.scanPath,
            reporter,
            onFinding,
        });
        reporter.summary(stats);
        if (shouldFailOnFindings(stats)) {
            process.exitCode = 1;
        }
        return stats;
    }

    return watchProject({
        projectRoot: options.projectRoot,
        scanPath: options.scanPath,
        reporter,
        onFinding,
    });
}

function reportTopLevelError(error, argv = process.argv.slice(2)) {
    let options = { quiet: false, json: false };
    try {
        options = parseCliArgs(argv);
    } catch (_) {}

    const logger = createLogger(options);
    const appError = error instanceof AppError
        ? error
        : new AppError('CLI_FAILED', error.message || 'VibeGuard failed to start', {
            cause: error,
            recoverable: false,
        });

    logger.error(appError.message, {
        code: appError.code,
        details: appError.details,
    });
}

function main(argv = process.argv.slice(2)) {
    return run(argv).catch((error) => {
        reportTopLevelError(error, argv);
        process.exitCode = 1;
        return null;
    });
}

module.exports = {
    run,
    main,
};
