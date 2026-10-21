# Contributing to gitambush

Thank you for your interest in contributing to `gitambush`!

`gitambush` is a zero-dependency security tool engineered to detect Git boobytraps, GitSpawn exploits (CVE-2026), malicious filter drivers, and rogue hooks before developers or AI coding agents open untrusted code.

---

## Development Setup

`gitambush` requires Node.js 18.0.0 or later and has **zero external runtime or development dependencies**.

```bash
# Clone the repository
git clone https://github.com/Nithinfgs/gitambush.git
cd gitambush

# Run the test suite
npm test

# Run a local scan on the repository
node ./bin/gitambush.js scan .
```

---

## Architecture Principles

1. **Zero Runtime Dependencies**: The core scanner, parsers, and neutralizer must never import external npm packages. Use native Node standard library APIs (`node:fs`, `node:path`, `node:crypto`, `node:child_process`).
2. **Cleanroom Non-Git Execution**: The scanner must NEVER invoke the `git` binary to inspect untrusted metadata files (`.git/config`, `.gitattributes`, `.gitmodules`). Doing so would trigger the very execution vulnerabilities (like `core.fsmonitor`) that `gitambush` is designed to detect!
3. **Surgical Neutralization**: The `--neutralize` command must safely comment out malicious directives and create backups (`.ambush-backup-<timestamp>`) without corrupting valid Git history or commit trees.
4. **Fast & Deterministic**: Scans should execute in under 100 milliseconds.

---

## Adding New Rules

Rules are defined in `src/rules.js`:

1. Assign a rule ID using the category taxonomy:
   - `GA1xx`: GitSpawn & Configuration Command Injection
   - `GA2xx`: Filter & Attribute Driver Poisoning
   - `GA3xx`: Submodule Traps & Protocol Injection
   - `GA4xx`: Hook & Filesystem Execution Traps
2. Provide a descriptive title, severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), CVE/CWE identifier, description, and remediation text.
3. Implement detection logic in `src/scanner.js`.
4. Add unit and integration tests in `test/scanner.test.js` and `test/neutralizer.test.js`.

---

## Submitting Pull Requests

1. Ensure all tests pass: `npm test`.
2. Follow standard JavaScript conventions (clean ES modules, 2-space indentation).
3. Update `CHANGELOG.md` with your changes under the `[Unreleased]` section.
4. Open a pull request against `main`.
