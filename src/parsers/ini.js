/**
 * Zero-dependency Git Configuration INI Parser
 *
 * Correctly parses Git INI dialect including:
 * - Sections with and without subsections: [core], [filter "lfs"], [diff "custom"]
 * - Comments: lines starting with # or ; and inline comments
 * - Value stripping and quote handling
 * - Line-number tracking for precise finding reporting
 * - Raw line preservation for surgical neutralization
 */

export function parseGitConfig(content) {
  const lines = content.split(/\r?\n/);
  const sections = [];
  let currentSection = null;

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    // Skip empty lines or pure comment lines
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) {
      continue;
    }

    // Check for section header: [section] or [section "subsection"]
    const sectionMatch = trimmed.match(/^\[([a-zA-Z0-9_-]+)(?:\s+"([^"]+)")?\]\s*(?:[#;].*)?$/);
    if (sectionMatch) {
      currentSection = {
        name: sectionMatch[1].toLowerCase(),
        subsection: sectionMatch[2] || null,
        headerLine: lineNumber,
        headerRaw: rawLine,
        entries: []
      };
      sections.push(currentSection);
      continue;
    }

    // Key-value pair
    if (currentSection) {
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx !== -1) {
        const key = trimmed.slice(0, eqIdx).trim().toLowerCase();
        let valuePart = trimmed.slice(eqIdx + 1).trim();

        // Strip inline comments if not inside quotes
        let inQuotes = false;
        let cleanValue = '';
        for (let j = 0; j < valuePart.length; j++) {
          const ch = valuePart[j];
          if (ch === '"' && (j === 0 || valuePart[j - 1] !== '\\')) {
            inQuotes = !inQuotes;
            cleanValue += ch;
          } else if ((ch === '#' || ch === ';') && !inQuotes) {
            break;
          } else {
            cleanValue += ch;
          }
        }
        cleanValue = cleanValue.trim();

        // Strip surrounding quotes if present
        if (cleanValue.startsWith('"') && cleanValue.endsWith('"') && cleanValue.length >= 2) {
          cleanValue = cleanValue.slice(1, -1);
        }

        currentSection.entries.push({
          key,
          value: cleanValue,
          line: lineNumber,
          raw: rawLine
        });
      } else {
        // Boolean flag without = (e.g. "bare")
        const key = trimmed.replace(/[#;].*$/, '').trim().toLowerCase();
        if (key) {
          currentSection.entries.push({
            key,
            value: 'true',
            line: lineNumber,
            raw: rawLine
          });
        }
      }
    }
  }

  return {
    sections,
    rawLines: lines
  };
}

/**
 * Find all occurrences of a key within section and optional subsection
 */
export function findConfigEntries(parsedConfig, sectionName, keyName, subsection = null) {
  const matches = [];
  const targetSec = sectionName.toLowerCase();
  const targetKey = keyName ? keyName.toLowerCase() : null;

  for (const sec of parsedConfig.sections) {
    if (sec.name !== targetSec) continue;
    if (subsection !== null && sec.subsection !== subsection) continue;

    for (const entry of sec.entries) {
      if (!targetKey || entry.key === targetKey) {
        matches.push({
          section: sec.name,
          subsection: sec.subsection,
          key: entry.key,
          value: entry.value,
          line: entry.line,
          raw: entry.raw
        });
      }
    }
  }

  return matches;
}
