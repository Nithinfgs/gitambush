/**
 * gitambush Terminal Formatter
 *
 * Rich ANSI colored output with severity badges, vulnerability details,
 * and actionable remediation steps.
 */

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  underline: '\x1b[4m',

  // Colors
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',

  // Bright / Background
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgMagenta: '\x1b[45m',
  bgGreen: '\x1b[42m',
  bgCyan: '\x1b[46m'
};

const SEVERITY_COLORS = {
  CRITICAL: `${ANSI.bgRed}${ANSI.white}${ANSI.bold} CRITICAL ${ANSI.reset}`,
  HIGH: `${ANSI.red}${ANSI.bold}[HIGH]${ANSI.reset}`,
  MEDIUM: `${ANSI.yellow}${ANSI.bold}[MEDIUM]${ANSI.reset}`,
  LOW: `${ANSI.cyan}${ANSI.bold}[LOW]${ANSI.reset}`,
  INFO: `${ANSI.blue}${ANSI.bold}[INFO]${ANSI.reset}`
};

export function formatTerminal(scanResult) {
  const lines = [];

  lines.push('');
  lines.push(`${ANSI.bold}${ANSI.cyan}⚡ gitambush v1.0.0${ANSI.reset} — Git Boobytrap & GitSpawn Forensic Auditor`);
  lines.push(`${ANSI.dim}Target: ${scanResult.targetPath}${ANSI.reset}`);
  lines.push('');

  if (scanResult.findings.length === 0) {
    lines.push(`  ${ANSI.green}${ANSI.bold}✓ Clean!${ANSI.reset} No Git boobytraps or GitSpawn vectors detected.`);
    lines.push(`  ${ANSI.dim}Repository is safe for AI agents and terminal navigation.${ANSI.reset}`);
    lines.push('');
    return lines.join('\n');
  }

  lines.push(`  ${ANSI.red}${ANSI.bold}⚠️  WARNING:${ANSI.reset} Found ${scanResult.findings.length} boobytrap / execution vector(s) in repository!`);
  lines.push('');

  for (let i = 0; i < scanResult.findings.length; i++) {
    const f = scanResult.findings[i];
    const badge = SEVERITY_COLORS[f.severity] || f.severity;
    const relFile = f.file.startsWith(scanResult.targetPath) 
      ? f.file.slice(scanResult.targetPath.length).replace(/^[/\\]/, '') 
      : f.file;

    lines.push(`  ${ANSI.bold}${i + 1}. ${f.ruleId}: ${f.title}${ANSI.reset} ${badge}`);
    lines.push(`     ${ANSI.dim}Location:${ANSI.reset} ${ANSI.cyan}${relFile}${f.line ? `:${f.line}` : ''}${ANSI.reset}`);
    if (f.cve && f.cve !== 'N/A') {
      lines.push(`     ${ANSI.dim}Reference:${ANSI.reset} ${ANSI.magenta}${f.cve}${ANSI.reset}`);
    }
    lines.push(`     ${ANSI.dim}Details:${ANSI.reset}   ${f.description}`);
    if (f.snippet) {
      lines.push(`     ${ANSI.dim}Snippet:${ANSI.reset}   ${ANSI.yellow}${f.snippet}${ANSI.reset}`);
    }
    lines.push(`     ${ANSI.dim}Fix:${ANSI.reset}       ${ANSI.green}${f.remediation}${ANSI.reset}`);
    lines.push('');
  }

  // Summary box
  lines.push(`  ${ANSI.bold}Summary:${ANSI.reset}`);
  const s = scanResult.stats;
  lines.push(`    ${ANSI.red}${ANSI.bold}Critical:${ANSI.reset} ${s.critical}   ${ANSI.red}High:${ANSI.reset} ${s.high}   ${ANSI.yellow}Medium:${ANSI.reset} ${s.medium}   ${ANSI.cyan}Low:${ANSI.reset} ${s.low}`);
  lines.push('');
  lines.push(`  ${ANSI.dim}Run "${ANSI.cyan}gitambush neutralize${ANSI.dim}" to safely defang these execution traps.${ANSI.reset}`);
  lines.push('');

  return lines.join('\n');
}

export function formatNeutralizeTerminal(report) {
  const lines = [];
  lines.push('');
  lines.push(`${ANSI.bold}${ANSI.cyan}🛡️ gitambush Neutralizer${ANSI.reset}`);
  lines.push(`${ANSI.dim}Repository: ${report.repoPath}${ANSI.reset}`);
  lines.push('');

  if (report.threatsFound === 0) {
    lines.push(`  ${ANSI.green}✓ Clean!${ANSI.reset} No threats found to neutralize.`);
    lines.push('');
    return lines.join('\n');
  }

  if (report.dryRun) {
    lines.push(`  ${ANSI.yellow}${ANSI.bold}[DRY RUN]${ANSI.reset} The following ${report.threatsNeutralized} actions would be taken:`);
  } else {
    lines.push(`  ${ANSI.green}${ANSI.bold}✓ Successfully neutralized ${report.threatsNeutralized} boobytrap(s)!${ANSI.reset}`);
  }
  lines.push('');

  for (const act of report.actions) {
    const icon = act.type.endsWith('_FAILED') ? `${ANSI.red}✗${ANSI.reset}` : `${ANSI.green}✓${ANSI.reset}`;
    lines.push(`    ${icon} ${ANSI.bold}${act.type}${ANSI.reset}: ${act.description}`);
    if (act.backupPath) {
      lines.push(`      ${ANSI.dim}Backup created at: ${act.backupPath}${ANSI.reset}`);
    }
  }

  lines.push('');
  if (!report.dryRun) {
    if (report.remainingThreats === 0) {
      lines.push(`  ${ANSI.green}${ANSI.bold}Repository is now sanitized and safe to open in AI agents.${ANSI.reset}`);
    } else {
      lines.push(`  ${ANSI.yellow}Notice: ${report.remainingThreats} residual item(s) require manual review.${ANSI.reset}`);
    }
  }
  lines.push('');

  return lines.join('\n');
}
