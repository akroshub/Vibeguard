const fs = require('node:fs');
const path = require('node:path');

const ENV_IGNORE_BLOCK = '# Added by VibeGuard\n.env\n.env.*\n!.env.example\n';

function hasEnvIgnore(content) {
    const lines = content.split(/\r?\n/).map((line) => line.trim());
    return lines.includes('.env') && lines.includes('.env.*');
}

function ensureGitignore(projectRoot, options = {}) {
    const gitignorePath = path.join(projectRoot, '.gitignore');

    if (options.dryRun) {
        return { changed: false, dryRun: true, gitignorePath };
    }

    if (fs.existsSync(gitignorePath)) {
        const content = fs.readFileSync(gitignorePath, 'utf8');
        if (hasEnvIgnore(content)) {
            return { changed: false, dryRun: false, gitignorePath };
        }

        const separator = content.endsWith('\n') ? '' : '\n';
        fs.appendFileSync(gitignorePath, `${separator}${ENV_IGNORE_BLOCK}`, 'utf8');
        return { changed: true, dryRun: false, gitignorePath };
    }

    fs.writeFileSync(gitignorePath, ENV_IGNORE_BLOCK, 'utf8');
    return { changed: true, dryRun: false, gitignorePath };
}

module.exports = { ensureGitignore };
