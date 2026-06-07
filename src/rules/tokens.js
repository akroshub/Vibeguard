const tokenRules = [
    {
        id: 'STRIPE_LIVE_KEY',
        description: 'Stripe Live Secret Key',
        severity: 'high',
        envVarName: 'STRIPE_SECRET_KEY',
        regex: /sk_live_[0-9a-zA-Z]{24,}/g,
        minLength: 20,
    },
    {
        id: 'STRIPE_TEST_KEY',
        description: 'Stripe Test Secret Key',
        severity: 'medium',
        envVarName: 'STRIPE_TEST_KEY',
        regex: /sk_test_[0-9a-zA-Z]{24,}/g,
        minLength: 20,
    },
    {
        id: 'GITHUB_TOKEN',
        description: 'GitHub Personal Access Token',
        severity: 'high',
        envVarName: 'GITHUB_TOKEN',
        regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
        minLength: 20,
    },
];

module.exports = { tokenRules };
