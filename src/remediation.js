const { remediate: remediateFinding } = require('./remediation/index');
const { createLogger } = require('./output/logger');
const { createReporter } = require('./output/reporter');

const logger = createLogger();
const reporter = createReporter({ logger });

function remediate(filepath, lineNumber, secretValue, patternName, envVarName, description, projectRoot, dryRun) {
    return remediateFinding({
        filepath,
        lineNumber,
        ruleId: patternName,
        patternName,
        match: secretValue,
        envVarName,
        env_var_name: envVarName,
        description,
        severity: 'medium',
    }, {
        projectRoot,
        dryRun,
        reporter,
    });
}

module.exports = { remediate };
