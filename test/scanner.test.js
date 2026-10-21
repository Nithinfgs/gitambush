import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { scanRepository } from '../src/scanner.js';
import { createIsolatedFixtures } from './helpers.js';

describe('gitambush Scanner', () => {
  let fixtures;

  before(() => {
    fixtures = createIsolatedFixtures();
  });

  after(() => {
    if (fixtures) fixtures.cleanup();
  });

  it('reports zero findings on a benign repository', () => {
    const benignPath = path.join(fixtures.baseDir, 'benign-repo');
    const result = scanRepository(benignPath);
    assert.equal(result.totalFindings, 0);
    assert.equal(result.findings.length, 0);
    assert.equal(result.stats.critical, 0);
  });

  it('detects GA101 (GitSpawn core.fsmonitor) as CRITICAL', () => {
    const targetPath = path.join(fixtures.baseDir, 'gitspawn-fsmonitor');
    const result = scanRepository(targetPath);
    assert.equal(result.totalFindings, 1);
    assert.equal(result.findings[0].ruleId, 'GA101');
    assert.equal(result.findings[0].severity, 'CRITICAL');
    assert.equal(result.findings[0].cve, 'CVE-2026-FSMONITOR');
    assert.match(result.findings[0].snippet, /fsmonitor/i);
  });

  it('detects GA201 and GA202 on filter poison repository', () => {
    const targetPath = path.join(fixtures.baseDir, 'filter-poison');
    const result = scanRepository(targetPath);
    assert.ok(result.totalFindings >= 2);

    const ga201s = result.findings.filter(f => f.ruleId === 'GA201');
    assert.ok(ga201s.length >= 1, 'Should find GA201 filter driver execution');

    const ga202s = result.findings.filter(f => f.ruleId === 'GA202');
    assert.ok(ga202s.length >= 1, 'Should find GA202 .gitattributes driver binding');
  });

  it('detects GA301, GA302, GA303 on submodule traps', () => {
    const targetPath = path.join(fixtures.baseDir, 'submodule-trap');
    const result = scanRepository(targetPath);
    assert.ok(result.totalFindings >= 3);

    const ruleIds = new Set(result.findings.map(f => f.ruleId));
    assert.ok(ruleIds.has('GA301'), 'Should detect update = !');
    assert.ok(ruleIds.has('GA302'), 'Should detect dangerous protocol ext::');
    assert.ok(ruleIds.has('GA303'), 'Should detect path traversal ../../');
  });

  it('detects GA401 on executable post-checkout hook', () => {
    const targetPath = path.join(fixtures.baseDir, 'hook-trap');
    const result = scanRepository(targetPath);
    assert.equal(result.totalFindings, 1);
    assert.equal(result.findings[0].ruleId, 'GA401');
    assert.equal(result.findings[0].severity, 'HIGH');
  });

  it('detects GA108 on shell alias escape (!)', () => {
    const targetPath = path.join(fixtures.baseDir, 'alias-escape');
    const result = scanRepository(targetPath);
    assert.equal(result.totalFindings, 1);
    assert.equal(result.findings[0].ruleId, 'GA108');
    assert.match(result.findings[0].description, /alias\.st/i);
  });

  it('detects multiple vectors on multitrap repository', () => {
    const targetPath = path.join(fixtures.baseDir, 'multi-trap');
    const result = scanRepository(targetPath);
    assert.ok(result.totalFindings >= 6);

    const ruleIds = new Set(result.findings.map(f => f.ruleId));
    assert.ok(ruleIds.has('GA101'), 'core.fsmonitor');
    assert.ok(ruleIds.has('GA102'), 'core.hooksPath');
    assert.ok(ruleIds.has('GA103'), 'core.pager');
    assert.ok(ruleIds.has('GA104'), 'core.editor');
    assert.ok(ruleIds.has('GA105'), 'diff.external');
    assert.ok(ruleIds.has('GA107'), 'credential.helper');
    assert.ok(ruleIds.has('GA108'), 'alias shell escape');
    assert.ok(ruleIds.has('GA110'), 'sshCommand');
    assert.ok(ruleIds.has('GA401'), 'executable pre-commit hook');
  });
});
