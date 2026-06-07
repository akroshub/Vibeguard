const { scanLine } = require('./core/scanner');

function scanLineForSecrets(line) {
    return scanLine(line).map((finding) => ({
        pattern_name: finding.ruleId,
        match: finding.match,
        env_var_name: finding.envVarName,
        description: finding.description,
    }));
}

module.exports = { scanLineForSecrets };
