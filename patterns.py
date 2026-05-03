import math
import re


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


PATTERNS: dict = {
    "OPENAI_KEY": {
        "regex": re.compile(r"sk-[a-zA-Z0-9]{32,60}"),
        "env_var_name": "OPENAI_API_KEY",
        "description": "OpenAI API Key",
    },
    "OPENAI_PROJECT_KEY": {
        "regex": re.compile(r"sk-proj-[a-zA-Z0-9\-_]{50,120}"),
        "env_var_name": "OPENAI_API_KEY",
        "description": "OpenAI Project API Key",
    },
    "ANTHROPIC_KEY": {
        "regex": re.compile(r"sk-ant-[a-zA-Z0-9\-_]{90,120}"),
        "env_var_name": "ANTHROPIC_API_KEY",
        "description": "Anthropic API Key",
    },
    "AWS_ACCESS_KEY": {
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "env_var_name": "AWS_ACCESS_KEY_ID",
        "description": "AWS Access Key ID",
    },
    "AWS_SECRET_KEY": {
        "regex": re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z\/+]{40}['\"]"),
        "env_var_name": "AWS_SECRET_ACCESS_KEY",
        "description": "AWS Secret Access Key",
    },
    "STRIPE_LIVE_KEY": {
        "regex": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "env_var_name": "STRIPE_SECRET_KEY",
        "description": "Stripe Live Secret Key",
    },
    "STRIPE_TEST_KEY": {
        "regex": re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),
        "env_var_name": "STRIPE_TEST_KEY",
        "description": "Stripe Test Secret Key",
    },
    "GITHUB_TOKEN": {
        "regex": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "env_var_name": "GITHUB_TOKEN",
        "description": "GitHub Personal Access Token",
    },
    "GOOGLE_API_KEY": {
        "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "env_var_name": "GOOGLE_API_KEY",
        "description": "Google API Key",
    },
}

PLACEHOLDERS: set = {
    "your-key-here", "YOUR_API_KEY", "xxx", "placeholder",
    "changeme", "<YOUR_KEY>", "your_api_key", "api_key_here",
    "insert_key_here", "my_secret_key",
}

ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LENGTH = 32
ENTROPY_ASSIGNMENT_RE = re.compile(
    r"""(?:=|:)\s*['"]([A-Za-z0-9\/+\-_=]{32,})['"]"""
)


def scan_line_for_secrets(line: str) -> list:
    """Scan a single line for known secret patterns and high-entropy strings."""
    results = []
    stripped = line.strip()

    if stripped.startswith("#") or stripped.startswith("//"):
        return results
    if "process.env." in line or "os.environ" in line:
        return results

    for pattern_name, meta in PATTERNS.items():
        for match in meta["regex"].finditer(line):
            value = match.group()
            if len(value) < 20:
                continue
            if value in PLACEHOLDERS:
                continue
            results.append({
                "pattern_name": pattern_name,
                "match": value,
                "env_var_name": meta["env_var_name"],
                "description": meta["description"],
            })

    for match in ENTROPY_ASSIGNMENT_RE.finditer(line):
        value = match.group(1)
        if value in PLACEHOLDERS or len(value) < ENTROPY_MIN_LENGTH:
            continue
        if shannon_entropy(value) > ENTROPY_THRESHOLD:
            already_caught = any(r["match"] in value or value in r["match"] for r in results)
            if not already_caught:
                results.append({
                    "pattern_name": "GENERIC_SECRET",
                    "match": value,
                    "env_var_name": "SECRET_KEY",
                    "description": "High-entropy secret string",
                })

    return results
