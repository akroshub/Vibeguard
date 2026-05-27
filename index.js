const fs = require('fs');
const path = require('path');
const chokidar = require('chokidar');
const { scanLineForSecrets } = require('./src/patterns');
const { remediate } = require('./src/remediation');

const WATCHED_EXTENSIONS = new Set(['.py', '.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml', '.toml', '.sh']);
const IGNORED_DIRS = new Set(['.git', 'node_modules', '__pycache__', '.venv', 'dist', 'build']);

function isIgnored(filepath) {
    const name = path.basename(filepath);
    if (name === '.env' || name.endsWith('.example') || name.endsWith('.template')) return true;
    return filepath.split(path.sep).some(part => IGNORED_DIRS.has(part));
}

function scanFile(filepath, projectRoot, dryRun) {
    if (isIgnored(filepath) || !WATCHED_EXTENSIONS.has(path.extname(filepath).toLowerCase())) return;

    try {
        const content = fs.readFileSync(filepath, 'utf8');
        const lines = content.split(/\r?\n/);

        lines.forEach((line, i) => {
            const findings = scanLineForSecrets(line);
            findings.forEach(f => {
                remediate(filepath, i + 1, f.match, f.pattern_name, f.env_var_name, f.description, projectRoot, dryRun);
            });
        });
    } catch (e) {}
}

function run(args) {
    const dryRun = args.includes('--dry-run');
    const scanOnly = args.includes('--scan');
    const watchPath = path.resolve(process.cwd());

    console.log(` VibeGuard active in: ${watchPath}`);

    if (scanOnly) {
        const getAllFiles = (dir) => {
            let results = [];
            fs.readdirSync(dir).forEach(file => {
                const fullPath = path.join(dir, file);
                if (fs.statSync(fullPath).isDirectory()) {
                    if (!IGNORED_DIRS.has(file)) results = results.concat(getAllFiles(fullPath));
                } else {
                    results.push(fullPath);
                }
            });
            return results;
        };
        getAllFiles(watchPath).forEach(f => scanFile(f, watchPath, dryRun));
        console.log(" Scan complete.");
    } else {
        const watcher = chokidar.watch(watchPath, {
            ignored: Array.from(IGNORED_DIRS).map(d => `**/${d}/**`),
            persistent: true
        });
        watcher.on('change', (p) => scanFile(p, watchPath, dryRun));
        watcher.on('add', (p) => scanFile(p, watchPath, dryRun));
        console.log("Watching for secrets... Press Ctrl+C to stop.");
    }
}

module.exports = { run };