/**
 * gitambush Core Scanner
 *
 * Cleanroom static analyzer for Git repository boobytraps.
 * NEVER invokes the "git" executable on untrusted metadata.
 */

import fs from 'node:fs';
import path from 'node:path';
import { parseGitConfig, findConfigEntries } from './parsers/ini.js';
import { parseGitAttributes } from './parsers/gitattributes.js';
import { parseGitModules } from './parsers/gitmodules.js';
import { RULES, Severity, meetsThreshold } from './rules.js';

const STANDARD_GIT_HOOKS = new Set([
  'applypatch-msg',
  'pre-applypatch',
  'post-applypatch',
  'pre-commit',
  'pre-merge-commit',
  'prepare-commit-msg',
  'commit-msg',
  'post-commit',
  'pre-rebase',
  'post-checkout',
  'post-merge',
  'pre-push',
  'pre-receive',
  'update',
  'post-receive',
  'post-update',
  'push-to-checkout',
  'pre-auto-gc',
  'post-rewrite',
  'sendemail-validate',
  'fsmonitor-watchman'
]);

export function scanRepository(repoPath, options = {}) {
  const absolutePath = path.resolve(repoPath);
  const findings = [];
  const minSeverity = options.minSeverity || Severity.INFO;

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Target path does not exist: ${absolutePath}`);
  }

  const gitEntryPath = path.join(absolutePath, '.git');
  let actualGitDir = null;

  // 1. Check if .git exists and is a directory or file pointer
  if (fs.existsSync(gitEntryPath)) {
    const stat = fs.lstatSync(gitEntryPath);

    // Symlink escape check on .git itself
    if (stat.isSymbolicLink()) {
      const linkTarget = fs.readlinkSync(gitEntryPath);
      const resolvedTarget = path.resolve(absolutePath, linkTarget);
      const relative = path.relative(absolutePath, resolvedTarget);
      if (relative.startsWith('..') || path.isAbsolute(linkTarget)) {
        findings.push(createFinding('GA402', gitEntryPath, 1, linkTarget, {
          detail: `Symlink points outside repository: ${linkTarget}`
        }));
      }
      actualGitDir = resolvedTarget;
    } else if (stat.isFile()) {
      // .git file (e.g. submodule or worktree)
      const content = fs.readFileSync(gitEntryPath, 'utf8').trim();
      const match = content.match(/^gitdir:\s*(.+)$/i);
      if (match) {
        const rawTarget = match[1].trim();
        const resolvedTarget = path.resolve(absolutePath, rawTarget);
        const relative = path.relative(absolutePath, resolvedTarget);
        if (relative.startsWith('..')) {
          findings.push(createFinding('GA404', gitEntryPath, 1, content, {
            detail: `gitdir pointer escapes repository workspace: ${rawTarget}`
          }));
        }
        if (fs.existsSync(resolvedTarget)) {
          actualGitDir = resolvedTarget;
        }
      }
    } else if (stat.isDirectory()) {
      actualGitDir = gitEntryPath;
    }
  }

  // 2. Scan .git/config if git directory is located
  if (actualGitDir && fs.existsSync(actualGitDir)) {
    scanGitDir(actualGitDir, absolutePath, findings);
  }

  // 3. Scan .gitattributes in repository root
  const attributesPath = path.join(absolutePath, '.gitattributes');
  if (fs.existsSync(attributesPath)) {
    scanAttributesFile(attributesPath, findings);
  }

  // 4. Scan .gitmodules in repository root
  const modulesPath = path.join(absolutePath, '.gitmodules');
  if (fs.existsSync(modulesPath)) {
    scanModulesFile(modulesPath, absolutePath, findings);
  }

  // Filter findings based on minimum severity
  const filteredFindings = findings.filter(f => meetsThreshold(f.severity, minSeverity));

  // Sort findings by severity order (CRITICAL first), then rule ID, then file
  filteredFindings.sort((a, b) => {
    const sevDiff = (b.severityScore || 0) - (a.severityScore || 0);
    if (sevDiff !== 0) return sevDiff;
    return a.ruleId.localeCompare(b.ruleId);
  });

  const stats = calculateStats(filteredFindings);

  return {
    targetPath: absolutePath,
    scannedGitDir: actualGitDir,
    totalFindings: filteredFindings.length,
    stats,
    findings: filteredFindings
  };
}

function scanGitDir(gitDir, repoRoot, findings) {
  // Check for Case-Folding collision attacks (e.g. .git/Hooks vs .git/hooks)
  try {
    const entries = fs.readdirSync(gitDir);
    for (const entry of entries) {
      if (entry !== 'hooks' && entry.toLowerCase() === 'hooks') {
        findings.push(createFinding('GA403', path.join(gitDir, entry), 1, entry, {
          detail: `Case-variant hooks directory detected: "${entry}". Can trigger execution on case-insensitive filesystems (APFS/NTFS).`
        }));
      }
      if (entry !== 'config' && entry.toLowerCase() === 'config') {
        findings.push(createFinding('GA403', path.join(gitDir, entry), 1, entry, {
          detail: `Case-variant config file detected: "${entry}".`
        }));
      }
    }
  } catch {
    // Ignore read errors
  }

  // Scan .git/config
  const configPath = path.join(gitDir, 'config');
  let configuredHooksPath = null;

  if (fs.existsSync(configPath)) {
    configuredHooksPath = scanConfigFile(configPath, findings);
  }

  // Scan Hooks directory
  const hooksDir = configuredHooksPath 
    ? path.resolve(repoRoot, configuredHooksPath)
    : path.join(gitDir, 'hooks');

  if (fs.existsSync(hooksDir)) {
    scanHooksDir(hooksDir, repoRoot, findings);
  }

  // Scan worktrees configs if any (.git/worktrees/*/config)
  const worktreesDir = path.join(gitDir, 'worktrees');
  if (fs.existsSync(worktreesDir) && fs.statSync(worktreesDir).isDirectory()) {
    try {
      const wtList = fs.readdirSync(worktreesDir);
      for (const wt of wtList) {
        const wtConfig = path.join(worktreesDir, wt, 'config');
        if (fs.existsSync(wtConfig)) {
          const wtFindings = [];
          scanConfigFile(wtConfig, wtFindings);
          for (const f of wtFindings) {
            findings.push({
              ...f,
              ruleId: 'GA405',
              title: RULES.GA405.title,
              category: RULES.GA405.category,
              description: `Concealed worktree configuration in "${wt}": ${f.description}`
            });
          }
        }
      }
    } catch {
      // Ignore worktrees read errors
    }
  }
}

function scanConfigFile(configPath, findings) {
  let configuredHooksPath = null;
  let content = '';

  try {
    content = fs.readFileSync(configPath, 'utf8');
  } catch (err) {
    return null;
  }

  const parsed = parseGitConfig(content);

  for (const sec of parsed.sections) {
    const secName = sec.name;

    // GA101: core.fsmonitor (GitSpawn)
    if (secName === 'core') {
      for (const entry of sec.entries) {
        if (entry.key === 'fsmonitor') {
          findings.push(createFinding('GA101', configPath, entry.line, entry.raw, {
            detail: `core.fsmonitor is set to: "${entry.value}". Executes external binary during git status/diff.`
          }));
        }

        // GA102: core.hooksPath
        if (entry.key === 'hookspath') {
          configuredHooksPath = entry.value;
          findings.push(createFinding('GA102', configPath, entry.line, entry.raw, {
            detail: `core.hooksPath is redirected to: "${entry.value}". Bypasses standard .git/hooks directory.`
          }));
        }

        // GA103: core.pager
        if (entry.key === 'pager') {
          findings.push(createFinding('GA103', configPath, entry.line, entry.raw, {
            detail: `core.pager is set to custom executable: "${entry.value}".`
          }));
        }

        // GA104: core.editor
        if (entry.key === 'editor') {
          findings.push(createFinding('GA104', configPath, entry.line, entry.raw, {
            detail: `core.editor is set to custom command: "${entry.value}".`
          }));
        }

        // GA110: core.sshCommand
        if (entry.key === 'sshcommand') {
          findings.push(createFinding('GA110', configPath, entry.line, entry.raw, {
            detail: `core.sshCommand overrides SSH client: "${entry.value}".`
          }));
        }
      }
    }

    // GA103: pager.<subcommand>
    if (secName === 'pager') {
      for (const entry of sec.entries) {
        findings.push(createFinding('GA103', configPath, entry.line, entry.raw, {
          detail: `pager.${entry.key} overrides pager: "${entry.value}".`
        }));
      }
    }

    // GA104: sequence.editor
    if (secName === 'sequence') {
      for (const entry of sec.entries) {
        if (entry.key === 'editor') {
          findings.push(createFinding('GA104', configPath, entry.line, entry.raw, {
            detail: `sequence.editor is set to custom command: "${entry.value}".`
          }));
        }
      }
    }

    // GA105: diff.external & diff.<driver>.command
    if (secName === 'diff') {
      for (const entry of sec.entries) {
        if (entry.key === 'external') {
          findings.push(createFinding('GA105', configPath, entry.line, entry.raw, {
            detail: `diff.external is configured: "${entry.value}". Executes on git diff.`
          }));
        }
        if (entry.key === 'command') {
          findings.push(createFinding('GA105', configPath, entry.line, entry.raw, {
            detail: `diff.${sec.subsection || 'driver'}.command executes: "${entry.value}".`
          }));
        }
      }
    }

    // GA106: merge.<driver>.driver
    if (secName === 'merge') {
      for (const entry of sec.entries) {
        if (entry.key === 'driver') {
          findings.push(createFinding('GA106', configPath, entry.line, entry.raw, {
            detail: `merge.${sec.subsection || 'driver'}.driver executes: "${entry.value}".`
          }));
        }
      }
    }

    // GA107: credential.helper
    if (secName === 'credential') {
      for (const entry of sec.entries) {
        if (entry.key === 'helper') {
          findings.push(createFinding('GA107', configPath, entry.line, entry.raw, {
            detail: `credential.helper configured locally in repository: "${entry.value}".`
          }));
        }
      }
    }

    // GA108: alias.* with shell escape (!)
    if (secName === 'alias') {
      for (const entry of sec.entries) {
        if (entry.value.trim().startsWith('!')) {
          findings.push(createFinding('GA108', configPath, entry.line, entry.raw, {
            detail: `alias.${entry.key} executes shell command: "${entry.value}".`
          }));
        }
      }
    }

    // GA109: include.path / includeIf
    if (secName === 'include' || secName.startsWith('includeif')) {
      for (const entry of sec.entries) {
        if (entry.key === 'path') {
          const isTraversal = entry.value.includes('..') || path.isAbsolute(entry.value);
          findings.push(createFinding('GA109', configPath, entry.line, entry.raw, {
            detail: `Config includes external file "${entry.value}"${isTraversal ? ' (traversal detected)' : ''}.`
          }));
        }
      }
    }

    // GA110: ssh.variant
    if (secName === 'ssh') {
      for (const entry of sec.entries) {
        if (entry.key === 'variant') {
          findings.push(createFinding('GA110', configPath, entry.line, entry.raw, {
            detail: `ssh.variant overridden: "${entry.value}".`
          }));
        }
      }
    }

    // GA201: filter.<driver>.clean / smudge / process
    if (secName === 'filter') {
      for (const entry of sec.entries) {
        if (entry.key === 'clean' || entry.key === 'smudge' || entry.key === 'process') {
          const isLfs = sec.subsection === 'lfs' && 
                        (entry.value.startsWith('git-lfs') || entry.value.startsWith('git lfs')) &&
                        !/[;&|`$\n]/.test(entry.value);

          if (!isLfs) {
            findings.push(createFinding('GA201', configPath, entry.line, entry.raw, {
              detail: `filter.${sec.subsection || 'driver'}.${entry.key} runs external command: "${entry.value}".`
            }));
          }

          // GA203: check for command substitution with %f
          if (entry.value.includes('%f') || entry.value.includes('%s')) {
            if (/[;&|`$\\]/.test(entry.value)) {
              findings.push(createFinding('GA203', configPath, entry.line, entry.raw, {
                detail: `Filter command combines shell chaining with "%f/%s" placeholder expansion: "${entry.value}".`
              }));
            }
          }
        }
      }
    }
  }

  return configuredHooksPath;
}

function scanAttributesFile(attrPath, findings) {
  let content = '';
  try {
    content = fs.readFileSync(attrPath, 'utf8');
  } catch {
    return;
  }

  const parsed = parseGitAttributes(content);
  for (const rule of parsed.rules) {
    const attrs = rule.attributes;
    for (const [key, val] of Object.entries(attrs)) {
      if (typeof val === 'string') {
        const lowerVal = val.toLowerCase();
        // Ignore standard git-lfs bindings
        if (key === 'filter' && lowerVal !== 'lfs') {
          findings.push(createFinding('GA202', attrPath, rule.line, rule.raw, {
            detail: `Pattern "${rule.pattern}" binds custom filter driver "${val}".`
          }));
        } else if (key === 'diff' && lowerVal !== 'lfs' && lowerVal !== 'binary') {
          findings.push(createFinding('GA202', attrPath, rule.line, rule.raw, {
            detail: `Pattern "${rule.pattern}" binds custom diff driver "${val}".`
          }));
        } else if (key === 'merge' && lowerVal !== 'lfs' && lowerVal !== 'binary' && lowerVal !== 'ours' && lowerVal !== 'union') {
          findings.push(createFinding('GA202', attrPath, rule.line, rule.raw, {
            detail: `Pattern "${rule.pattern}" binds custom merge driver "${val}".`
          }));
        }
      }
    }
  }
}

function scanModulesFile(modulesPath, repoRoot, findings) {
  let content = '';
  try {
    content = fs.readFileSync(modulesPath, 'utf8');
  } catch {
    return;
  }

  const parsed = parseGitModules(content);
  for (const sub of parsed.submodules) {
    // GA301: update = !command
    if (sub.update && sub.update.trim().startsWith('!')) {
      findings.push(createFinding('GA301', modulesPath, sub.headerLine, `update = ${sub.update}`, {
        detail: `Submodule "${sub.name}" executes shell update command: "${sub.update}".`
      }));
    }

    // GA302: dangerous protocol
    if (sub.url) {
      const trimmedUrl = sub.url.trim().toLowerCase();
      if (trimmedUrl.startsWith('ext::') || trimmedUrl.startsWith('file://')) {
        findings.push(createFinding('GA302', modulesPath, sub.headerLine, `url = ${sub.url}`, {
          detail: `Submodule "${sub.name}" uses dangerous protocol handler: "${sub.url}".`
        }));
      }
    }

    // GA303: path traversal
    if (sub.path) {
      if (sub.path.includes('..') || path.isAbsolute(sub.path)) {
        findings.push(createFinding('GA303', modulesPath, sub.headerLine, `path = ${sub.path}`, {
          detail: `Submodule "${sub.name}" path escapes repository root: "${sub.path}".`
        }));
      }
    }
  }
}

function scanHooksDir(hooksDir, repoRoot, findings) {
  try {
    // Symlink escape check on hooks directory
    const hookDirStat = fs.lstatSync(hooksDir);
    if (hookDirStat.isSymbolicLink()) {
      const linkTarget = fs.readlinkSync(hooksDir);
      const resolved = path.resolve(path.dirname(hooksDir), linkTarget);
      const rel = path.relative(repoRoot, resolved);
      if (rel.startsWith('..') || path.isAbsolute(linkTarget)) {
        findings.push(createFinding('GA402', hooksDir, 1, linkTarget, {
          detail: `Hooks directory is a symlink pointing outside repository: ${linkTarget}`
        }));
        return;
      }
    }

    const files = fs.readdirSync(hooksDir);
    for (const file of files) {
      // Ignore sample templates
      if (file.endsWith('.sample') || file.endsWith('.disabled') || file === '.gitkeep') {
        continue;
      }

      const hookFilePath = path.join(hooksDir, file);
      const fileStat = fs.lstatSync(hookFilePath);

      if (fileStat.isSymbolicLink()) {
        const target = fs.readlinkSync(hookFilePath);
        const resolved = path.resolve(hooksDir, target);
        const rel = path.relative(repoRoot, resolved);
        if (rel.startsWith('..')) {
          findings.push(createFinding('GA402', hookFilePath, 1, target, {
            detail: `Hook symlink "${file}" escapes repository: ${target}`
          }));
          continue;
        }
      }

      // Check if file is executable (Unix) or has script content
      const isExecutable = (fileStat.mode & 0o111) !== 0;
      let hasScriptHeader = false;

      try {
        const buffer = Buffer.alloc(128);
        const fd = fs.openSync(hookFilePath, 'r');
        fs.readSync(fd, buffer, 0, 128, 0);
        fs.closeSync(fd);
        const header = buffer.toString('utf8');
        hasScriptHeader = header.startsWith('#!') || header.startsWith('@echo') || header.startsWith('REM');
      } catch {
        // Ignore read error
      }

      if (STANDARD_GIT_HOOKS.has(file) && (isExecutable || hasScriptHeader)) {
        findings.push(createFinding('GA401', hookFilePath, 1, file, {
          detail: `Active executable hook script "${file}" executes automatically when standard Git actions fire.`
        }));
      }
    }
  } catch {
    // Ignore hooks directory errors
  }
}

function createFinding(ruleId, filePath, line, snippet, extra = {}) {
  const rule = RULES[ruleId] || {
    id: ruleId,
    title: 'Unknown Rule',
    category: 'General',
    severity: Severity.MEDIUM,
    cve: 'N/A',
    description: '',
    remediation: ''
  };

  const severityOrder = {
    [Severity.CRITICAL]: 4,
    [Severity.HIGH]: 3,
    [Severity.MEDIUM]: 2,
    [Severity.LOW]: 1,
    [Severity.INFO]: 0
  };

  return {
    ruleId,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    severityScore: severityOrder[rule.severity] || 0,
    cve: rule.cve,
    description: extra.detail || rule.description,
    remediation: rule.remediation,
    file: filePath,
    line: line || 1,
    snippet: snippet ? String(snippet).trim() : ''
  };
}

function calculateStats(findings) {
  const stats = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const f of findings) {
    const sev = f.severity.toLowerCase();
    if (stats[sev] !== undefined) {
      stats[sev]++;
    }
  }

  return stats;
}
