const { apiKeyRules } = require('./api-keys');
const { tokenRules } = require('./tokens');
const { entropyRules } = require('./entropy');

const PLACEHOLDERS = new Set([
    'your-key-here',
    'YOUR_API_KEY',
    'xxx',
    'placeholder',
    'changeme',
    '<YOUR_KEY>',
    'your_api_key',
    'api_key_here',
    'insert_key_here',
    'my_secret_key',
]);

function isPlaceholder(value) {
    return PLACEHOLDERS.has(value);
}

function getRules() {
    return [
        ...apiKeyRules,
        ...tokenRules,
        ...entropyRules,
    ];
}

module.exports = {
    getRules,
    isPlaceholder,
};
