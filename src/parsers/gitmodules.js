/**
 * Zero-dependency .gitmodules Parser
 */

import { parseGitConfig } from './ini.js';

export function parseGitModules(content) {
  const parsed = parseGitConfig(content);
  const submodules = [];

  for (const sec of parsed.sections) {
    if (sec.name === 'submodule') {
      const sub = {
        name: sec.subsection || 'unknown',
        headerLine: sec.headerLine,
        path: null,
        url: null,
        update: null,
        branch: null,
        rawEntries: sec.entries
      };

      for (const entry of sec.entries) {
        if (entry.key === 'path') sub.path = entry.value;
        if (entry.key === 'url') sub.url = entry.value;
        if (entry.key === 'update') sub.update = entry.value;
        if (entry.key === 'branch') sub.branch = entry.value;
      }

      submodules.push(sub);
    }
  }

  return {
    submodules,
    rawLines: parsed.rawLines
  };
}
