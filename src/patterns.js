 const PATTERNS = {
    OPENAI_KEY: {
        regex: /sk-[a-zA-Z0-9]{32,60}/g,
        env_var_name: "OPENAI_API_KEY",
        description: "OpenAI API Key",
    },
    OPENAI_PROJECT_KEY: {
        regex: /sk-proj-[a-zA-Z0-9\-_]{50,120}/g,
        env_var_name: "OPENAI_API_KEY",
        description: "OpenAI Project API Key",
    },
    ANTHROPIC_KEY: {
        regex: /sk-ant-[a-zA-Z0-9\-_]{90,120}/g,
        env_var_name: "ANTHROPIC_API_KEY",
        description: "Anthropic API Key",
    },
    AWS_ACCESS_KEY: {
        regex: /AKIA[0-9A-Z]{16}/g,
        env_var_name: "AWS_ACCESS_KEY_ID",
        description: "AWS Access Key ID",
    },
    AWS_SECRET_KEY: {
        regex: /aws.{0,20}secret.{0,20}['"][0-9a-zA-Z\/+]{40}['"]/gi,
        env_var_name: "AWS_SECRET_ACCESS_KEY",
        description: "AWS Secret Access Key",
    },
    STRIPE_LIVE_KEY: {
        regex: /sk_live_[0-9a-zA-Z]{24,}/g,
        env_var_name: "STRIPE_SECRET_KEY",
        description: "Stripe Live Secret Key",
    },
    STRIPE_TEST_KEY: {
        regex: /sk_test_[0-9a-zA-Z]{24,}/g,
        env_var_name: "STRIPE_TEST_KEY",
        description: "Stripe Test Secret Key",
    },
    GITHUB_TOKEN: {
        regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
        env_var_name: "GITHUB_TOKEN",
        description: "GitHub Personal Access Token",
    },
    GOOGLE_API_KEY: {
        regex: /AIza[0-9A-Za-z\-_]{35}/g,
        env_var_name: "GOOGLE_API_KEY",
        description: "Google API Key",
    },
};

const PLACEHOLDERS = new Set([
    "your-key-here", "YOUR_API_KEY", "xxx", "placeholder",
    "changeme", "<YOUR_KEY>", "your_api_key", "api_key_here",
    "insert_key_here", "my_secret_key",
]);

const ENTROPY_THRESHOLD = 4.5;
const ENTROPY_MIN_LENGTH = 32;
const ENTROPY_ASSIGNMENT_RE = /(?:=|:)\s*'"['"]/g;

function shannonEntropy(s) {
    if (!s) return 0;
    const freq = {};
    for (let char of s) freq[char] = (freq[char] || 0) + 1;
    const len = s.length;
    return -Object.values(freq).reduce((sum, f) => {
        const p = f / len;
        return sum + p * Math.log2(p);
    }, 0);
}

function scanLineForSecrets(line) {
    const results = [];
    const stripped = line.trim();

    if (stripped.startsWith("#") || stripped.startsWith("//")) return results;
    if (line.includes("process.env.") || line.includes("os.environ")) return results;

    for (const [name, meta] of Object.entries(PATTERNS)) {
        let match;
        while ((match = meta.regex.exec(line)) !== null) {
            const value = match[0];
            if (value.length < 20 || PLACEHOLDERS.has(value)) continue;
            results.push({
                pattern_name: name,
                match: value,
                env_var_name: meta.env_var_name,
                description: meta.description,
            });
        }
    }

    let entropyMatch;
    while ((entropyMatch = ENTROPY_ASSIGNMENT_RE.exec(line)) !== null) {
        const value = entropyMatch[1];
        if (PLACEHOLDERS.has(value) || value.length < ENTROPY_MIN_LENGTH) continue;
        if (shannonEntropy(value) > ENTROPY_THRESHOLD) {
            const alreadyCaught = results.some(r => r.match.includes(value) || value.includes(r.match));
            if (!alreadyCaught) {
                results.push({
                    pattern_name: "GENERIC_SECRET",
                    match: value,
                    env_var_name: "SECRET_KEY",
                    description: "High-entropy secret string",
                });
            }
        }
    }
    return results;
}

module.exports = { scanLineForSecrets };