const apiKeyRules = [
    {
        id: 'OPENAI_KEY',
        description: 'OpenAI API Key',
        severity: 'high',
        envVarName: 'OPENAI_API_KEY',
        regex: /sk-[a-zA-Z0-9]{32,60}/g,
        minLength: 20,
    },
    {
        id: 'OPENAI_PROJECT_KEY',
        description: 'OpenAI Project API Key',
        severity: 'high',
        envVarName: 'OPENAI_API_KEY',
        regex: /sk-proj-[a-zA-Z0-9\-_]{50,120}/g,
        minLength: 20,
    },
    {
        id: 'ANTHROPIC_KEY',
        description: 'Anthropic API Key',
        severity: 'high',
        envVarName: 'ANTHROPIC_API_KEY',
        regex: /sk-ant-[a-zA-Z0-9\-_]{90,120}/g,
        minLength: 20,
    },
    {
        id: 'AWS_ACCESS_KEY',
        description: 'AWS Access Key ID',
        severity: 'high',
        envVarName: 'AWS_ACCESS_KEY_ID',
        regex: /AKIA[0-9A-Z]{16}/g,
        minLength: 20,
    },
    {
        id: 'AWS_SECRET_KEY',
        description: 'AWS Secret Access Key',
        severity: 'high',
        envVarName: 'AWS_SECRET_ACCESS_KEY',
        regex: /aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]/gi,
        minLength: 20,
    },
    {
        id: 'GOOGLE_API_KEY',
        description: 'Google API Key',
        severity: 'high',
        envVarName: 'GOOGLE_API_KEY',
        regex: /AIza[0-9A-Za-z\-_]{35}/g,
        minLength: 20,
    },
];

module.exports = { apiKeyRules };
