# VibeGuard

VibeGuard is a beta JavaScript/TypeScript secret scanner. It flags likely secrets by combining:

- AST context: the value is assigned to a sensitive-looking name such as `apiKey`, `token`, `secret`, `password`, or `auth`.
- Shannon entropy: the value is random-looking enough to pass the configured threshold.

This keeps simple placeholders like `password = "test"` and `apiKey = "your-api-key"` out of the results.

## Install

```bash
npm install
```

Or run it from another project:

```bash
npx vibe-security-akoris scan
```

## Usage

Scan the current project:

```bash
npm run scan
```

Scan without changing files:

```bash
npx vibe-security-akoris scan
```

Preview fixes without writing anything:

```bash
npx vibe-security-akoris scan --dry-run
```

Replace detected literals with `process.env.NAME` and write values to `.env`:

```bash
npx vibe-security-akoris scan --fix
```

Run non-interactively:

```bash
npx vibe-security-akoris scan --fix --yes
```

Scan a specific path:

```bash
npx vibe-security-akoris scan --path src
```

Use in CI or pre-commit hooks:

```bash
npx vibe-security-akoris scan --ci
```

## Safety Defaults

- Default mode is scan-only. Files are changed only with `--fix`.
- `--dry-run` shows the source, `.env`, and `.gitignore` changes before editing.
- Full secrets are never printed; output uses masked values like `sk-****abcd`.
- Existing `.env` values are not overwritten. If a name already exists with a different value, VibeGuard creates a suffixed name and prints a warning.
- `.gitignore` gets `.env` only when it is missing.
- Common generated paths are ignored by default, including `.git`, `node_modules`, `dist`, `build`, `coverage`, and lock files.

## Output

Findings include file path, line, column, identifier, confidence, and reason:

```text
src/app.js:12:21 apiKey confidence=medium sensitive identifier "apiKey" has entropy 4.73 above threshold 4.00
```

Exit codes:

```text
0 = no secrets found
1 = secrets found
2 = scanner/config/parse error
```

## Config

Create `.vibeguardrc` in your project root:

```json
{
  "entropyThreshold": 4.5,
  "ignoredPaths": ["fixtures/**", "vendor/**"],
  "maxFileSizeBytes": 2097152
}
```

You can also add `.vibeguardignore` with simple glob patterns.

## Pre-commit Protection

Install the Git hook:

```bash
npx --package vibe-security-akoris vibe-security-akoris-protect
```

Install without prompts:

```bash
npx --package vibe-security-akoris vibe-security-akoris-protect --yes
```

The hook scans staged JS/TS files and blocks the commit when validated secret candidates are found.

## Supported Files

VibeGuard scans `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, and `.tsx`.

## Limitations

- JavaScript and TypeScript only.
- Beta scanner: it may miss secrets and may still report false positives.
- It checks string literals in supported AST contexts, not every possible way a secret can appear.
- It intentionally avoids vendor-specific API-key regex databases.

## Feedback

Issues and feedback: https://github.com/akroshub/Vibeguard/issues
