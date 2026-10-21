/**
 * gitambush Safe Clone Wrapper
 *
 * Clones remote repositories in a quarantined sandbox, neutralizes any weaponized
 * GitSpawn directives or malicious filter drivers BEFORE checkout occurs.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { neutralizeRepository } from './neutralizer.js';
import { scanRepository } from './scanner.js';

export function safeClone(repoUrl, targetDir, options = {}) {
  if (!repoUrl) {
    throw new Error('Repository URL is required for clone.');
  }

  // Derive target folder name if not provided
  let destination = targetDir;
  if (!destination) {
    const cleanUrl = repoUrl.replace(/\/+$/, '');
    const parts = cleanUrl.split('/');
    const last = parts[parts.length - 1].replace(/\.git$/i, '');
    destination = last || 'cloned-repo';
  }

  const resolvedTarget = path.resolve(destination);

  if (fs.existsSync(resolvedTarget)) {
    throw new Error(`Destination directory already exists: ${resolvedTarget}`);
  }

  // Create quarantined staging directory in OS temp
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitambush-quarantine-'));

  try {
    // 1. Clone with --no-checkout so no filters or hooks trigger
    const cloneResult = spawnSync('git', ['clone', '--no-checkout', repoUrl, quarantineDir], {
      stdio: 'pipe',
      encoding: 'utf8'
    });

    if (cloneResult.status !== 0) {
      throw new Error(`Git clone failed: ${cloneResult.stderr || cloneResult.stdout}`);
    }

    // 2. Pre-scan quarantined repository
    const preScan = scanRepository(quarantineDir, { minSeverity: 'INFO' });

    // 3. Neutralize any boobytraps before moving
    let neutralizationReport = null;
    if (preScan.findings.length > 0) {
      neutralizationReport = neutralizeRepository(quarantineDir, { dryRun: false });
    }

    // 4. Move sanitized directory to final destination
    fs.mkdirSync(path.dirname(resolvedTarget), { recursive: true });
    fs.renameSync(quarantineDir, resolvedTarget);

    // 5. Safe checkout now that all boobytraps are neutralized
    const checkoutResult = spawnSync('git', ['checkout'], {
      cwd: resolvedTarget,
      stdio: 'pipe',
      encoding: 'utf8'
    });

    return {
      repoUrl,
      targetDir: resolvedTarget,
      quarantinedThreatsDetected: preScan.findings.length,
      threatsNeutralized: neutralizationReport ? neutralizationReport.threatsNeutralized : 0,
      checkoutSuccess: checkoutResult.status === 0,
      findings: preScan.findings
    };
  } catch (err) {
    // Clean up quarantine on failure
    try {
      if (fs.existsSync(quarantineDir)) {
        fs.rmSync(quarantineDir, { recursive: true, force: true });
      }
    } catch {
      // Ignore cleanup error
    }
    throw err;
  }
}
