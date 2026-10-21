import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseGitConfig, findConfigEntries } from '../src/parsers/ini.js';

describe('Git Config INI Parser', () => {
  it('parses standard git sections and key-value pairs', () => {
    const raw = `
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
`;
    const result = parseGitConfig(raw);
    assert.equal(result.sections.length, 1);
    assert.equal(result.sections[0].name, 'core');
    assert.equal(result.sections[0].subsection, null);
    assert.equal(result.sections[0].entries.length, 3);
    assert.equal(result.sections[0].entries[0].key, 'repositoryformatversion');
    assert.equal(result.sections[0].entries[0].value, '0');
  });

  it('handles subsections in quotes correctly', () => {
    const raw = `
[filter "lfs"]
\tclean = git-lfs clean -- %f
\tsmudge = git-lfs smudge -- %f
[diff "custom-diff"]
\tcommand = /usr/bin/my-diff
`;
    const result = parseGitConfig(raw);
    assert.equal(result.sections.length, 2);
    assert.equal(result.sections[0].name, 'filter');
    assert.equal(result.sections[0].subsection, 'lfs');
    assert.equal(result.sections[1].name, 'diff');
    assert.equal(result.sections[1].subsection, 'custom-diff');
  });

  it('strips inline comments while preserving quoted strings', () => {
    const raw = `
[core]
\tfsmonitor = "/tmp/my evil#path.sh" ; inline comment
\tpager = less -R # comment here
`;
    const result = parseGitConfig(raw);
    const fsmon = result.sections[0].entries.find(e => e.key === 'fsmonitor');
    assert.equal(fsmon.value, '/tmp/my evil#path.sh');

    const pager = result.sections[0].entries.find(e => e.key === 'pager');
    assert.equal(pager.value, 'less -R');
  });

  it('finds config entries matching query', () => {
    const raw = `
[core]
\tfsmonitor = evil.sh
[filter "pwn"]
\tsmudge = evil_smudge
`;
    const parsed = parseGitConfig(raw);
    const found = findConfigEntries(parsed, 'core', 'fsmonitor');
    assert.equal(found.length, 1);
    assert.equal(found[0].value, 'evil.sh');

    const filterSmudge = findConfigEntries(parsed, 'filter', 'smudge', 'pwn');
    assert.equal(filterSmudge.length, 1);
    assert.equal(filterSmudge[0].value, 'evil_smudge');
  });
});
