import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { neutralizeRepository } from '../src/neutralizer.js';
import { scanRepository } from '../src/scanner.js';
import { createIsolatedFixtures } from './helpers.js';

describe('gitambush Neutralizer', () => {
  let fixtures;

  beforeEach(() => {
    fixtures = createIsolatedFixtures();
  });

  afterEach(() => {
    if (fixtures) fixtures.cleanup();
  });

  it('performs dry-run without altering target files', () => {
    const targetPath = path.join(fixtures.baseDir, 'gitspawn-fsmonitor');
    const configPath = path.join(targetPath, '.git', 'config');
    const originalContent = fs.readFileSync(configPath, 'utf8');

    const result = neutralizeRepository(targetPath, { dryRun: true });
    assert.equal(result.dryRun, true);
    assert.equal(result.threatsFound, 1);
    assert.equal(result.threatsNeutralized, 1);

    const currentContent = fs.readFileSync(configPath, 'utf8');
    assert.equal(currentContent, originalContent, 'File should not change during dry-run');
  });

  it('neutralizes GitSpawn core.fsmonitor and creates backup', () => {
    const targetPath = path.join(fixtures.baseDir, 'gitspawn-fsmonitor');
    const configPath = path.join(targetPath, '.git', 'config');

    const result = neutralizeRepository(targetPath, { dryRun: false });
    assert.equal(result.threatsFound, 1);
    assert.equal(result.threatsNeutralized, 1);
    assert.equal(result.remainingThreats, 0);
    assert.equal(result.backups.length, 1);
    assert.ok(fs.existsSync(result.backups[0]), 'Backup file should exist');

    // Verify config content is commented out
    const updatedContent = fs.readFileSync(configPath, 'utf8');
    assert.match(updatedContent, /# \[gitambush-neutralized\]\s*fsmonitor = \/tmp\/evil_payload\.sh/);

    // Verify post-neutralization scan is 100% clean
    const postScan = scanRepository(targetPath);
    assert.equal(postScan.totalFindings, 0);
  });

  it('neutralizes executable hooks by removing execution bits and appending .disabled', () => {
    const targetPath = path.join(fixtures.baseDir, 'hook-trap');
    const hookPath = path.join(targetPath, '.git', 'hooks', 'post-checkout');
    const disabledPath = `${hookPath}.disabled`;

    const result = neutralizeRepository(targetPath, { dryRun: false });
    assert.equal(result.threatsNeutralized, 1);
    assert.ok(!fs.existsSync(hookPath), 'Original hook should be renamed');
    assert.ok(fs.existsSync(disabledPath), 'Disabled hook should exist');

    const stat = fs.statSync(disabledPath);
    assert.equal(stat.mode & 0o111, 0, 'Executable bits should be stripped');

    const postScan = scanRepository(targetPath);
    assert.equal(postScan.totalFindings, 0);
  });

  it('neutralizes complex multitrap repository', () => {
    const targetPath = path.join(fixtures.baseDir, 'multi-trap');
    const result = neutralizeRepository(targetPath, { dryRun: false });
    assert.ok(result.threatsNeutralized >= 5);

    const postScan = scanRepository(targetPath);
    assert.equal(postScan.totalFindings, 0, 'All threats should be neutralized');
  });
});
