# VibeGuard

VibeGuard is an algorithmic JavaScript/TypeScript secret scanner. The MVP intentionally avoids vendor-specific API key regexes and hardcoded cloud-provider signatures. It validates possible secrets with two independent signals:

1. AST context: the scanner parses source files and only inspects string literals assigned to identifiers or properties whose names imply sensitive intent, such as `secret`, `token`, `key`, `password`, or `auth`.
2. Shannon entropy: the string value must exceed the configured entropy threshold before VibeGuard treats it as a vulnerability.

The result is a small DevSecOps core engine focused on language structure and mathematics instead of brittle signature databases.

## How Detection Works

VibeGuard parses each supported source file with Babel and walks these AST nodes:

- `VariableDeclarator`, for code like `const authToken = "...";`
- `AssignmentExpression`, for code like `config.apiKey = "...";`
- `ObjectProperty`, for code like `{ password: "..." }`
- `ClassProperty`, for code like `token = "...";`

For each candidate, it computes Shannon entropy:

```text
H(X) = -sum(P(x_i) * log2(P(x_i)))
```

Names alone are never enough. For example, `const apiKey = "default"` is ignored because the value is too predictable, while a random base64-like token is flagged.

## Git Delta Scanning

When a `.git` directory exists, VibeGuard first asks Git for staged source files:

```bash
git diff --staged --name-only --diff-filter=ACMR
```

If staged files exist, only those files are scanned. If there are no staged JavaScript or TypeScript files, VibeGuard falls back to a full workspace source scan.

## Remediation

For confirmed findings, VibeGuard:

- Replaces the string literal with `process.env.<UPPERCASE_IDENTIFIER>`.
- Writes the real value to `.env` using quoted dotenv-compatible syntax.
- Ensures `.env*` appears in `.gitignore` exactly once.
- Writes updated files atomically through temporary files and rename operations.

Example:

```js
const serviceToken = "f9uQpL7xZ2vN4mR8sT1bC6dE3hJ5kW0y";
```

becomes:

```js
const serviceToken = process.env.SERVICE_TOKEN;
```

and `.env` receives:

```text
SERVICE_TOKEN="f9uQpL7xZ2vN4mR8sT1bC6dE3hJ5kW0y"
```

## Usage

Install dependencies:

```bash
npm install
```

Run an interactive scan:

```bash
npm run scan
```

Run the scanner in CI/pre-commit mode:

```bash
npx vibeguard scan --ci
```

CI mode prints redacted JSON, never prompts, never rewrites files, and exits with status `1` when validated secret candidates are found.

Run without changing files:

```bash
npm run dry-run
```

Automatically remediate all findings:

```bash
node bin/vsg --scan --yes
```

Scan a specific path:

```bash
node bin/vsg --path test-vault --dry-run
```

Change the entropy threshold:

```bash
node bin/vsg --threshold 4.5
```

Run the MVP test suite:

```bash
npm test
```

## Automatic Protection

VibeGuard can install a persistent Git pre-commit sentinel:

```bash
npx vibeguard-protect
```

The protector verifies that the current directory is inside a Git work tree, locates the repository hook path with Git, and offers to install a `pre-commit` hook. Existing hook content is preserved. VibeGuard adds an idempotent Sentinel block, so rerunning the installer refreshes the block instead of duplicating it.

Once installed, every commit runs:

```bash
npx vibeguard scan --ci
```

If the staged diff contains a validated high-entropy secret, the scanner exits nonzero and Git aborts the commit. The hook is written as a portable shell script for Unix and Git for Windows environments; it can invoke `npx`, `npx.cmd`, Windows PowerShell, or PowerShell Core depending on what is available.

Non-interactive installation is available for bootstrap scripts:

```bash
npx vibeguard-protect --yes
```

## Supported Files

VibeGuard scans `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, and `.tsx` files.

## Project Layout

```text
src/
  cli.js
  protector.js
  core/
    engine.js
    remediator.js
  utils/
    entropy.js
    git.js
test-vault/
  generic-secrets.js
  safe-code.js
  test.js
```
