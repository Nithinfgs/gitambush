# Changelog

All notable changes to `gitambush` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-21

### Added
- **Cleanroom INI & Metadata Parsers**:
  - Zero-dependency parser for Git INI configs, sections, and subsections (`.git/config`).
  - `.gitattributes` pattern and filter driver binding parser.
  - `.gitmodules` submodule configuration parser.
- **GitSpawn & Boobytrap Detection Rules (GA1xx-GA4xx)**:
  - `GA101`: `core.fsmonitor` background execution (CVE-2026-FSMONITOR).
  - `GA102`: `core.hooksPath` directory redirect (CWE-426).
  - `GA103`: `core.pager` & `pager.*` custom command execution (CWE-78).
  - `GA104`: `core.editor` & `sequence.editor` command injection (CWE-78).
  - `GA105`: `diff.external` & `diff.<driver>.command` execution (CVE-2026-106058).
  - `GA106`: `merge.<driver>.driver` arbitrary execution (CWE-78).
  - `GA107`: `credential.helper` rogue token harvesting scripts (CWE-522).
  - `GA108`: `alias.*` shell execution escapes (`!command`).
  - `GA109`: `include.path` & `includeIf` config smuggling and traversal (CVE-2025-48384).
  - `GA110`: `core.sshCommand` & `ssh.variant` hijack (CVE-2023-4759).
  - `GA201`: `filter.<driver>.clean|smudge|process` execution (CVE-2026-46399).
  - `GA202`: Weaponized `.gitattributes` custom driver bindings (CVE-2026-102437).
  - `GA203`: Shell placeholder interpolation injection (`%f`/`%s`).
  - `GA301`: Submodule shell update injection (`update = !...`).
  - `GA302`: Submodule dangerous protocol handlers (`ext::`, `file://`).
  - `GA303`: Submodule path traversal (`path = ../...`).
  - `GA401`: Rogue executable hooks in `.git/hooks/*`.
  - `GA402`: `.git` and `.git/hooks` symlink traversal escapes (CVE-2024-32002).
  - `GA403`: Case-folding collision directory attacks (APFS/NTFS).
  - `GA404`: Detached `gitdir:` pointer escape.
  - `GA405`: Concealed worktree config injection (`.git/worktrees/*/config`).
- **Core CLI Commands**:
  - `gitambush scan [path]`: Deep forensic scan with configurable severity thresholds.
  - `gitambush neutralize [path]`: Surgical defanging with automatic `.ambush-backup` creation.
  - `gitambush clone <repo-url> [dest]`: Quarantine clone and pre-checkout sanitization.
  - `gitambush rules`: Complete catalog of detection rules, CVEs, and remediations.
- **Multi-Format Reporting**:
  - Rich ANSI colored terminal output with severity badges and snippets.
  - Standard JSON output for developer toolchain integration.
  - SARIF 2.1.0 output for native GitHub Code Scanning alerts.
- **GitHub Action**:
  - Composite action `action.yml` for CI/CD PR scanning.
