/**
 * Zero-dependency .gitattributes Parser
 */

export function parseGitAttributes(content) {
  const lines = content.split(/\r?\n/);
  const rules = [];

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    // Split on whitespace while handling quoted patterns
    const tokens = [];
    let currentToken = '';
    let inQuotes = false;

    for (let j = 0; j < trimmed.length; j++) {
      const ch = trimmed[j];
      if (ch === '"') {
        inQuotes = !inQuotes;
        currentToken += ch;
      } else if (/\s/.test(ch) && !inQuotes) {
        if (currentToken) {
          tokens.push(currentToken);
          currentToken = '';
        }
      } else {
        currentToken += ch;
      }
    }
    if (currentToken) {
      tokens.push(currentToken);
    }

    if (tokens.length >= 2) {
      const pattern = tokens[0];
      const attributes = {};

      for (let k = 1; k < tokens.length; k++) {
        const token = tokens[k];
        if (token.includes('=')) {
          const [attrKey, attrVal] = token.split('=');
          attributes[attrKey.trim().toLowerCase()] = attrVal.trim();
        } else if (token.startsWith('-')) {
          attributes[token.slice(1).trim().toLowerCase()] = false;
        } else if (token.startsWith('!')) {
          attributes[token.slice(1).trim().toLowerCase()] = 'unspecified';
        } else {
          attributes[token.trim().toLowerCase()] = true;
        }
      }

      rules.push({
        pattern,
        attributes,
        line: lineNumber,
        raw: rawLine
      });
    }
  }

  return {
    rules,
    rawLines: lines
  };
}
