# VibeGuard

VibeGuard is a CLI security tool that detects exposed API keys and secrets in source files before they reach production.

## Installation

Install VibeGuard globally from GitHub:

```bash
npm install -g git+https://github.com/akroshub/Vibeguard.git
```

After installation, verify that the CLI is available:

```bash
vsg --scan --dry-run
```

## Usage

Scan the current project once:

```bash
vsg --scan
```

Run a safe dry-run scan without modifying files:

```bash
vsg --dry-run
```

Watch the current project for changes:

```bash
vsg
```

Install the Git pre-commit hook:

```bash
vsg --init-hook
```
