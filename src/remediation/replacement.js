const path = require('node:path');

function getEnvVarReplacement(envVarName, filepath) {
    const ext = path.extname(filepath).toLowerCase();
    const jsExts = new Set(['.js', '.ts', '.jsx', '.tsx']);

    if (jsExts.has(ext)) {
        return `process.env.${envVarName}`;
    }

    return `os.environ.get("${envVarName}")`;
}

function applyLanguageImports(content, filepath) {
    const ext = path.extname(filepath).toLowerCase();

    if (ext === '.py' && !content.includes('import os')) {
        return `import os\n${content}`;
    }

    return content;
}

module.exports = {
    getEnvVarReplacement,
    applyLanguageImports,
};
