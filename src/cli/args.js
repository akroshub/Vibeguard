const path = require('node:path');
const { parseArgs } = require('node:util');

function parseCliArgs(argv = process.argv.slice(2)) {
    const parsed = parseArgs({
        args: argv,
        allowPositionals: false,
        options: {
            scan: {
                type: 'boolean',
                default: false,
            },
            'dry-run': {
                type: 'boolean',
                default: false,
            },
            path: {
                type: 'string',
            },
            json: {
                type: 'boolean',
                default: false,
            },
            quiet: {
                type: 'boolean',
                default: false,
            },
            'init-hook': {
                type: 'boolean',
                default: false,
            },
            report: {
                type: 'string',
            },
        },
    });

    const resolvedPath = path.resolve(parsed.values.path || process.cwd());

    return {
        scan: Boolean(parsed.values.scan),
        dryRun: Boolean(parsed.values['dry-run']),
        projectRoot: resolvedPath,
        scanPath: resolvedPath,
        json: Boolean(parsed.values.json),
        quiet: Boolean(parsed.values.quiet),
        initHook: Boolean(parsed.values['init-hook']),
        report: parsed.values.report || null,
    };
}

module.exports = { parseCliArgs };
