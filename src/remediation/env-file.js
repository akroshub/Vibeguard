const fs = require('node:fs');
const path = require('node:path');

function ensureEnvEntry(projectRoot, envVarName, options = {}) {
    const envPath = path.join(projectRoot, '.env');
    const entry = `${envVarName}=REPLACE_WITH_YOUR_ACTUAL_KEY`;

    if (options.dryRun) {
        return { changed: false, dryRun: true, envPath };
    }

    if (fs.existsSync(envPath)) {
        const existing = fs.readFileSync(envPath, 'utf8');
        if (existing.includes(envVarName)) {
            return { changed: false, dryRun: false, envPath };
        }

        fs.appendFileSync(envPath, `\n${entry}\n`, 'utf8');
        return { changed: true, dryRun: false, envPath };
    }

    const header = '# .env - managed by VibeGuard\n# DO NOT commit this file\n\n';
    fs.writeFileSync(envPath, `${header}${entry}\n`, 'utf8');
    return { changed: true, dryRun: false, envPath };
}

module.exports = { ensureEnvEntry };
