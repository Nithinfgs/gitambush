import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { runCli } from '../src/cli.js';
import { createIsolatedFixtures } from './helpers.js';

describe('gitambush CLI', () => {
  let fixtures;

  beforeEach(() => {
    fixtures = createIsolatedFixtures();
  });

  afterEach(() => {
    if (fixtures) fixtures.cleanup();
  });

  it('prints help and returns code 0', async () => {
    const code = await runCli(['--help']);
    assert.equal(code, 0);
  });

  it('prints version and returns code 0', async () => {
    const code = await runCli(['--version']);
    assert.equal(code, 0);
  });

  it('lists rules catalog and returns code 0', async () => {
    const code = await runCli(['rules']);
    assert.equal(code, 0);
  });

  it('scans benign repository and exits 0', async () => {
    const targetPath = path.join(fixtures.baseDir, 'benign-repo');
    const code = await runCli(['scan', targetPath]);
    assert.equal(code, 0);
  });

  it('scans GitSpawn repository and exits 1 (findings at or above high)', async () => {
    const targetPath = path.join(fixtures.baseDir, 'gitspawn-fsmonitor');
    const code = await runCli(['scan', targetPath]);
    assert.equal(code, 1);
  });

  it('respects --format json output', async () => {
    const targetPath = path.join(fixtures.baseDir, 'benign-repo');
    const code = await runCli(['scan', targetPath, '--format', 'json']);
    assert.equal(code, 0);
  });

  it('respects --format sarif output', async () => {
    const targetPath = path.join(fixtures.baseDir, 'benign-repo');
    const code = await runCli(['scan', targetPath, '--format', 'sarif']);
    assert.equal(code, 0);
  });

  it('neutralizes boobytraps and subsequent scan exits 0', async () => {
    const targetPath = path.join(fixtures.baseDir, 'gitspawn-fsmonitor');
    const neutCode = await runCli(['neutralize', targetPath]);
    assert.equal(neutCode, 0);

    const scanCode = await runCli(['scan', targetPath]);
    assert.equal(scanCode, 0, 'Should exit 0 after neutralization');
  });
});
