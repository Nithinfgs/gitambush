/**
 * gitambush Rule Definitions
 *
 * Rules are categorized as:
 * - GA1xx: GitSpawn & Configuration Command Injection
 * - GA2xx: Filter & Attribute Driver Poisoning
 * - GA3xx: Submodule Traps & Protocol Injection
 * - GA4xx: Hook & Filesystem Execution Traps
 */

export const Severity = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO'
};

export const SeverityOrder = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

export const RULES = {
  // GA1xx: Configuration Command Injection (GitSpawn)
  GA101: {
    id: 'GA101',
    title: 'GitSpawn Command Execution (core.fsmonitor)',
    category: 'GitSpawn / Config RCE',
    severity: Severity.CRITICAL,
    cve: 'CVE-2026-FSMONITOR',
    description: 'core.fsmonitor specifies an external program that Git executes automatically on "git status", "git diff", and "git add" before any user confirmation or AI agent trust prompt.',
    remediation: 'Remove "core.fsmonitor" from .git/config or unset via "git config --unset core.fsmonitor".'
  },
  GA102: {
    id: 'GA102',
    title: 'Arbitrary Hooks Path Override (core.hooksPath)',
    category: 'Config RCE',
    severity: Severity.CRITICAL,
    cve: 'CWE-426',
    description: 'core.hooksPath redirects Git hook discovery to an untrusted directory in the workspace or filesystem, allowing automatic execution of rogue hook scripts.',
    remediation: 'Remove "core.hooksPath" to restore default .git/hooks directory.'
  },
  GA103: {
    id: 'GA103',
    title: 'Malicious External Pager (core.pager / pager.*)',
    category: 'Config RCE',
    severity: Severity.HIGH,
    cve: 'CWE-78',
    description: 'core.pager or pager.<cmd> is set to an arbitrary script or executable that Git spawns automatically whenever log, diff, or branch listings are displayed.',
    remediation: 'Unset custom pager commands or reset to system default (less / more).'
  },
  GA104: {
    id: 'GA104',
    title: 'External Editor Hijacking (core.editor / sequence.editor)',
    category: 'Config RCE',
    severity: Severity.HIGH,
    cve: 'CWE-78',
    description: 'core.editor or sequence.editor is configured with an arbitrary binary or shell command that executes during commit message editing, rebase, or tag creation.',
    remediation: 'Remove core.editor and sequence.editor overrides from repository config.'
  },
  GA105: {
    id: 'GA105',
    title: 'External Diff Driver Execution (diff.external / diff.<driver>.command)',
    category: 'Config RCE',
    severity: Severity.CRITICAL,
    cve: 'CVE-2026-106058',
    description: 'diff.external or a custom diff.<driver>.command invokes an arbitrary shell binary when inspecting diffs, triggering RCE during routine agent diff operations.',
    remediation: 'Remove diff.external and diff driver commands from .git/config.'
  },
  GA106: {
    id: 'GA106',
    title: 'Custom Merge Driver Execution (merge.<driver>.driver)',
    category: 'Config RCE',
    severity: Severity.HIGH,
    cve: 'CWE-78',
    description: 'merge.<driver>.driver runs custom shell commands whenever git merge, cherry-pick, or rebase touches files with matching attributes.',
    remediation: 'Remove merge.<driver>.driver definitions from repository config.'
  },
  GA107: {
    id: 'GA107',
    title: 'Rogue Credential Helper (credential.helper)',
    category: 'Credential Theft / RCE',
    severity: Severity.CRITICAL,
    cve: 'CWE-522',
    description: 'credential.helper is configured with a custom script that executes on remote fetch/push operations, capable of exfiltrating personal access tokens or executing payloads.',
    remediation: 'Remove repository-level credential.helper; rely only on user-level credential storage.'
  },
  GA108: {
    id: 'GA108',
    title: 'Dangerous Shell Alias Escape (alias.* with !)',
    category: 'Command Injection',
    severity: Severity.HIGH,
    cve: 'CWE-78',
    description: 'Git alias begins with "!" which triggers execution via host shell (sh -c) when the alias is invoked.',
    remediation: 'Audit or remove repository-scoped aliases with "!" shell escapes.'
  },
  GA109: {
    id: 'GA109',
    title: 'Configuration File Smuggling (include.path / includeIf)',
    category: 'Config Traversal',
    severity: Severity.HIGH,
    cve: 'CVE-2025-48384',
    description: 'include.path or includeIf.*.path references external config files or directory traversals outside the repository root.',
    remediation: 'Remove untrusted include directives from repository configuration.'
  },
  GA110: {
    id: 'GA110',
    title: 'SSH Command / Protocol Driver Hijack (core.sshCommand / ssh.variant)',
    category: 'Command Injection',
    severity: Severity.CRITICAL,
    cve: 'CVE-2023-4759',
    description: 'core.sshCommand or ssh.variant overrides SSH execution binary, allowing arbitrary command execution when communicating with remote git servers.',
    remediation: 'Remove core.sshCommand from repository-level configuration.'
  },

  // GA2xx: Filter & Attribute Driver Poisoning
  GA201: {
    id: 'GA201',
    title: 'Arbitrary Filter Driver Execution (filter.<driver>.clean|smudge|process)',
    category: 'Filter Poisoning',
    severity: Severity.CRITICAL,
    cve: 'CVE-2026-46399',
    description: 'filter.<driver>.clean, smudge, or process configures an external program that executes automatically when checking out or staging files.',
    remediation: 'Remove untrusted clean/smudge/process filter drivers from .git/config.'
  },
  GA202: {
    id: 'GA202',
    title: 'Weaponized .gitattributes Driver Binding',
    category: 'Attribute Binding',
    severity: Severity.HIGH,
    cve: 'CVE-2026-102437',
    description: '.gitattributes binds files to custom filter, diff, or merge drivers that require external command invocation.',
    remediation: 'Audit .gitattributes for non-standard filter, diff, or merge driver bindings.'
  },
  GA203: {
    id: 'GA203',
    title: 'Command Substitution Injection in Filter Arguments (%f)',
    category: 'Filter Injection',
    severity: Severity.HIGH,
    cve: 'CWE-78',
    description: 'Filter or diff command uses unsafe "%f" or "%s" placeholder expansion subject to filename shell command injection.',
    remediation: 'Sanitize filter commands to avoid direct shell interpolation of filename placeholders.'
  },

  // GA3xx: Submodule Traps
  GA301: {
    id: 'GA301',
    title: 'Submodule Shell Update Injection (.gitmodules update = !)',
    category: 'Submodule Traps',
    severity: Severity.CRITICAL,
    cve: 'CWE-78',
    description: '.gitmodules configures "update = !command" which executes arbitrary shell commands when "git submodule update" is run.',
    remediation: 'Remove "update = !..." lines from .gitmodules.'
  },
  GA302: {
    id: 'GA302',
    title: 'Dangerous Submodule Protocol (ext:: / file://)',
    category: 'Protocol Smuggling',
    severity: Severity.CRITICAL,
    cve: 'CVE-2022-24765',
    description: 'Submodule URL uses "ext::", "file://", or malformed protocol handlers that can execute local commands or access sensitive files.',
    remediation: 'Change submodule URLs to safe https:// or git@ protocols.'
  },
  GA303: {
    id: 'GA303',
    title: 'Submodule Path Traversal Escape',
    category: 'Path Traversal',
    severity: Severity.HIGH,
    cve: 'CWE-22',
    description: 'Submodule "path" contains "../" directory traversal sequences designed to escape repository bounds.',
    remediation: 'Ensure submodule path resides strictly inside repository tree.'
  },

  // GA4xx: Hook & Filesystem Execution Traps
  GA401: {
    id: 'GA401',
    title: 'Executable Hook in Repository (.git/hooks/*)',
    category: 'Hook Traps',
    severity: Severity.HIGH,
    cve: 'CWE-426',
    description: 'Executable hook script detected in .git/hooks/ (post-checkout, post-merge, pre-commit, etc.) that executes automatically on standard Git operations.',
    remediation: 'Remove execute permission (chmod -x) or disable with .disabled suffix.'
  },
  GA402: {
    id: 'GA402',
    title: 'Directory Traversal Symlink (.git symlink escape)',
    category: 'Symlink Escape',
    severity: Severity.CRITICAL,
    cve: 'CVE-2024-32002',
    description: '.git or .git/hooks is a symbolic link pointing outside the repository workspace boundary.',
    remediation: 'Delete untrusted symlinks pointing outside workspace root.'
  },
  GA403: {
    id: 'GA403',
    title: 'Case-Folding Collision Hook Attack (.git/Hooks vs .git/hooks)',
    category: 'Filesystem Collision',
    severity: Severity.HIGH,
    cve: 'CVE-2021-21300',
    description: 'Case-variant Git directory or file detected (.git/Hooks, .GIT/config) capable of triggering collisions on macOS (APFS) or Windows (NTFS).',
    remediation: 'Remove non-standard case-variant directory entries.'
  },
  GA404: {
    id: 'GA404',
    title: 'Detached or Escaped gitdir Pointer (.git file traversal)',
    category: 'Gitdir Hijack',
    severity: Severity.HIGH,
    cve: 'CWE-22',
    description: '.git file contains "gitdir:" pointing outside the repository boundary to an unexpected location on disk.',
    remediation: 'Verify gitdir destination and confine to project workspace.'
  },
  GA405: {
    id: 'GA405',
    title: 'Concealed Worktree Configuration Injection (.git/worktrees/*/config)',
    category: 'Worktree Traps',
    severity: Severity.HIGH,
    cve: 'CWE-426',
    description: 'Worktree-specific configuration file contains command execution or hooks override directives.',
    remediation: 'Inspect and clean .git/worktrees/*/config files.'
  }
};

/**
 * Get rule by ID or return null
 */
export function getRule(id) {
  return RULES[id] || null;
}

/**
 * Returns true if severity meets or exceeds threshold
 */
export function meetsThreshold(severity, minSeverity) {
  const sevScore = SeverityOrder[severity] ?? -1;
  const minScore = SeverityOrder[minSeverity] ?? 0;
  return sevScore >= minScore;
}
