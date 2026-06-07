const chokidar = require('chokidar');
const { getRules } = require('../rules');
const { getWatchIgnoredPatterns } = require('./ignore-policy');
const { scanFile } = require('./scanner');

function watchProject(options) {
    const projectRoot = options.projectRoot;
    const watchPath = options.scanPath || projectRoot;
    const rules = options.rules || getRules();
    const stats = {
        filesScanned: 0,
        findings: 0,
        errors: 0,
    };

    const watcher = chokidar.watch(watchPath, {
        ignored: getWatchIgnoredPatterns(),
        persistent: true,
    });

    async function scan(filepath) {
        await scanFile(filepath, {
            rules,
            reporter: options.reporter,
            onFinding: options.onFinding,
            stats,
        }).catch((error) => {
            if (options.reporter) {
                options.reporter.warning(error);
            }
        });
    }

    watcher.on('add', scan);
    watcher.on('change', scan);

    if (options.reporter) {
        options.reporter.watching(watchPath);
    }

    return watcher;
}

module.exports = { watchProject };
