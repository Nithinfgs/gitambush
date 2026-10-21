import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { scanRepository } from '../src/scanner.js';
import { formatTerminal } from '../src/formatters/terminal.js';
import { formatJson } from '../src/formatters/json.js';
import { formatSarif } from '../src/formatters/sarif.js';
import { createIsolatedFixtures } from './helpers.js';

describe('gitambush Formatters', () => {
  let fixtures;

  before(() => {
    fixtures = createIsolatedFixtures();
  });

  after(() => {
    if (fixtures) fixtures.cleanup();
  });

  it('formats clean terminal output', () => {
    const benignPath = path.join(fixtures.baseDir, 'benign-repo');
    const result = scanRepository(benignPath);
    const terminal = formatTerminal(result);
    assert.match(terminal, /Clean!/);
  });

  it('formats warning terminal output on boobytrap', () => {
    const targetPath = path.join(fixtures.baseDir, 'gitspawn-fsmonitor');
    const result = scanRepository(targetPath);
    const terminal = formatTerminal(result);
    assert.match(terminal, /CRITICAL/);
    assert.match(terminal, /GA101/);
    assert.match(terminal, /CVE-2026-FSMONITOR/);
  });

  it('formats valid JSON output', () => {
    const targetPath = path.join(fixtures.baseDir, 'gitspawn-fsmonitor');
    const result = scanRepository(targetPath);
    const jsonStr = formatJson(result);
    const parsed = JSON.parse(jsonStr);
    assert.equal(parsed.totalFindings, 1);
    assert.equal(parsed.findings[0].ruleId, 'GA101');
  });

  it('formats valid SARIF 2.1.0 output with schema and rules', () => {
    const targetPath = path.join(fixtures.baseDir, 'gitspawn-fsmonitor');
    const result = scanRepository(targetPath);
    const sarifStr = formatSarif(result);
    const parsed = JSON.parse(sarifStr);

    assert.equal(parsed.version, '2.1.0');
    assert.ok(parsed.$schema.includes('sarif-schema-2.1.0.json'));
    assert.equal(parsed.runs.length, 1);
    assert.equal(parsed.runs[0].tool.driver.name, 'gitambush');
    assert.ok(parsed.runs[0].tool.driver.rules.length > 10);
    assert.equal(parsed.runs[0].results.length, 1);
    assert.equal(parsed.runs[0].results[0].ruleId, 'GA101');
    assert.equal(parsed.runs[0].results[0].level, 'error');
  });
});
