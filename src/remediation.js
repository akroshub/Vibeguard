const fs = require('fs');
const path = require('path');

function printAlert(filepath, secretType, lineNumber) {
    const fp = filepath.slice(0, 46).padEnd(46);
    const st = secretType.slice(0, 46).padEnd(46);
    const ln = String(lineNumber).slice(0, 46).padEnd(46);

    console.log(`
╔══════════════════════════════════════════════════════╗
║  🚨  VIBEGUARD — SECURITY THREAT DETECTED            ║
╠══════════════════════════════════════════════════════╣
║  File     : ${fp}  ║
║  Type     : ${st}  ║
║  Line     : ${ln}  ║
║  Action   : Auto-remediating now...                  ║
╚══════════════════════════════════════════════════════╝`);
}

function getEnvVarReplacement(envVarName, ext) {
    const jsExts = ['.js', '.ts', '.jsx', '.tsx'];
    return jsExts.includes(ext) ? `process.env.${envVarName}` : `os.environ.get("${envVarName}")`;
}

function rewriteSourceFile(filepath, secretValue, envVarName, dryRun) {
    const ext = path.extname(filepath).toLowerCase();
    const replacement = getEnvVarReplacement(envVarName, ext);

    try {
        let content = fs.readFileSync(filepath, 'utf8');
        if (!content.includes(secretValue)) return false;

        let newContent = content.split(secretValue).join(replacement);

        if (ext === '.py' && !newContent.includes('import os')) {
            newContent = "import os\n" + newContent;
        }

        if (dryRun) {
            console.log(`[DRY RUN] Would rewrite ${filepath}`);
            return true;
        }

        fs.writeFileSync(filepath, newContent, 'utf8');
        console.log(`✅ Rewrote ${filepath} — secret replaced with ${replacement}`);
        return true;
    } catch (e) {
        console.error(`❌ Failed to rewrite ${filepath}: ${e.message}`);
        return false;
    }
}

function updateEnvFile(projectRoot, envVarName, dryRun) {
    const envPath = path.join(projectRoot, '.env');
    const entry = `${envVarName}=REPLACE_WITH_YOUR_ACTUAL_KEY`;

    if (dryRun) return;

    if (fs.existsSync(envPath)) {
        const existing = fs.readFileSync(envPath, 'utf8');
        if (existing.includes(envVarName)) return;
        fs.appendFileSync(envPath, `\n${entry}\n`);
    } else {
        const header = "# .env — managed by VibeGuard\n# DO NOT commit this file\n\n";
        fs.writeFileSync(envPath, header + entry + "\n");
    }
}

function updateGitignore(projectRoot, dryRun) {
    const gitignorePath = path.join(projectRoot, '.gitignore');
    const addition = "\n# Added by VibeGuard\n.env\n.env.*\n!.env.example\n";

    if (dryRun) return;

    if (fs.existsSync(gitignorePath)) {
        const content = fs.readFileSync(gitignorePath, 'utf8');
        if (content.includes('.env')) return;
        fs.appendFileSync(gitignorePath, addition);
    } else {
        fs.writeFileSync(gitignorePath, addition.trim());
    }
}

function remediate(filepath, line_number, secret_value, pattern_name, env_var_name, description, project_root, dryRun) {
    printAlert(filepath, description, line_number);
    const ok = rewriteSourceFile(filepath, secret_value, env_var_name, dryRun);
    
    if (ok || dryRun) {
        updateEnvFile(project_root, env_var_name, dryRun);
        updateGitignore(project_root, dryRun);
        if (!dryRun) console.log("✨ Remediation complete.\n");
    }
}

module.exports = { remediate };