/**
 * gitambush Boobytrap Neutralizer
 *
 * Surgically defangs GitSpawn, malicious filters, rogue hooks, and submodule traps
 * while preserving valid repository commit history and benign configs.
 */

import fs from 'node:fs';
import path from 'node:path';
import { scanRepository } from './scanner.js';

export function neutralizeRepository(repoPath, options = {}) {
  const dryRun = Boolean(options.dryRun);
  const scanResult = scanRepository(repoPath, { minSeverity: 'INFO' });
  const actions = [];
  const backups = [];

  if (scanResult.findings.length === 0) {
    return {
      repoPath: scanResult.targetPath,
      dryRun,
      threatsFound: 0,
      threatsNeutralized: 0,
      remainingThreats: 0,
      backups: [],
      actions: []
    };
  }

  const gitDir = scanResult.scannedGitDir;
  const configPath = gitDir ? path.join(gitDir, 'config') : null;
  const modulesPath = path.join(scanResult.targetPath, '.gitmodules');

  // 1. Neutralize .git/config
  if (configPath && fs.existsSync(configPath)) {
    const configFindings = scanResult.findings.filter(f => f.file === configPath);
    if (configFindings.length > 0) {
      const configAction = neutralizeConfigFile(configPath, configFindings, dryRun);
      if (configAction) {
        actions.push(configAction);
        if (configAction.backupPath) backups.push(configAction.backupPath);
      }
    }
  }

  // 2. Neutralize .gitmodules
  if (fs.existsSync(modulesPath)) {
    const moduleFindings = scanResult.findings.filter(f => f.file === modulesPath);
    if (moduleFindings.length > 0) {
      const moduleAction = neutralizeModulesFile(modulesPath, moduleFindings, dryRun);
      if (moduleAction) {
        actions.push(moduleAction);
        if (moduleAction.backupPath) backups.push(moduleAction.backupPath);
      }
    }
  }

  // 3. Neutralize executable hooks in .git/hooks/
  const hookFindings = scanResult.findings.filter(f => f.ruleId === 'GA401');
  for (const hf of hookFindings) {
    const hookPath = hf.file;
    if (fs.existsSync(hookPath)) {
      const disabledPath = `${hookPath}.disabled`;
      if (!dryRun) {
        try {
          // Remove executable permissions
          const stat = fs.statSync(hookPath);
          fs.chmodSync(hookPath, stat.mode & ~0o111);
          // Rename to .disabled
          fs.renameSync(hookPath, disabledPath);
        } catch (err) {
          actions.push({
            target: hookPath,
            type: 'HOOK_DISABLE_FAILED',
            description: `Failed to neutralize hook: ${err.message}`
          });
          continue;
        }
      }
      actions.push({
        target: hookPath,
        type: 'HOOK_DEFANGED',
        linesCommented: 1,
        description: `Disabled executable hook and renamed to "${path.basename(disabledPath)}"`
      });
    }
  }

  // Verification re-scan if not dry-run
  let remainingFindings = scanResult.findings.length;
  if (!dryRun) {
    const postScan = scanRepository(repoPath, { minSeverity: 'INFO' });
    remainingFindings = postScan.findings.length;
  }

  const threatsNeutralized = actions
    .filter(a => !a.type.endsWith('_FAILED'))
    .reduce((sum, a) => sum + (a.linesCommented || 1), 0);

  return {
    repoPath: scanResult.targetPath,
    dryRun,
    threatsFound: scanResult.findings.length,
    threatsNeutralized,
    remainingThreats: remainingFindings,
    backups,
    actions
  };
}

function neutralizeConfigFile(configPath, findings, dryRun) {
  try {
    const originalContent = fs.readFileSync(configPath, 'utf8');
    const lines = originalContent.split(/\r?\n/);
    const linesToComment = new Set(findings.map(f => f.line));
    let modified = false;

    const newLines = lines.map((line, idx) => {
      const lineNum = idx + 1;
      if (linesToComment.has(lineNum)) {
        modified = true;
        return `# [gitambush-neutralized] ${line}`;
      }
      return line;
    });

    if (!modified) return null;

    let backupPath = null;
    if (!dryRun) {
      const timestamp = Date.now();
      backupPath = `${configPath}.ambush-backup-${timestamp}`;
      fs.writeFileSync(backupPath, originalContent, 'utf8');
      fs.writeFileSync(configPath, newLines.join('\n'), 'utf8');
    }

    return {
      target: configPath,
      type: 'CONFIG_NEUTRALIZED',
      backupPath,
      linesCommented: linesToComment.size,
      description: `Commented out ${linesToComment.size} weaponized configuration directives.`
    };
  } catch (err) {
    return {
      target: configPath,
      type: 'CONFIG_NEUTRALIZE_FAILED',
      description: `Failed to neutralize config: ${err.message}`
    };
  }
}

function neutralizeModulesFile(modulesPath, findings, dryRun) {
  try {
    const originalContent = fs.readFileSync(modulesPath, 'utf8');
    const lines = originalContent.split(/\r?\n/);
    let modified = false;
    let count = 0;

    const newLines = lines.map(line => {
      const trimmed = line.trim();
      if (trimmed.startsWith('update') && trimmed.includes('=')) {
        const val = trimmed.split('=')[1].trim();
        if (val.startsWith('!')) {
          modified = true;
          count++;
          return `    # [gitambush-neutralized] ${trimmed}`;
        }
      }
      return line;
    });

    if (!modified) return null;

    let backupPath = null;
    if (!dryRun) {
      const timestamp = Date.now();
      backupPath = `${modulesPath}.ambush-backup-${timestamp}`;
      fs.writeFileSync(backupPath, originalContent, 'utf8');
      fs.writeFileSync(modulesPath, newLines.join('\n'), 'utf8');
    }

    return {
      target: modulesPath,
      type: 'MODULES_NEUTRALIZED',
      backupPath,
      linesCommented: count,
      description: 'Stripped shell update directives from .gitmodules.'
    };
  } catch (err) {
    return {
      target: modulesPath,
      type: 'MODULES_NEUTRALIZE_FAILED',
      description: `Failed to neutralize modules: ${err.message}`
    };
  }
}
