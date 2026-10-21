/**
 * gitambush CLI Runner
 */

import { scanRepository } from './scanner.js';
import { neutralizeRepository } from './neutralizer.js';
import { safeClone } from './cloner.js';
import { RULES, SeverityOrder } from './rules.js';
import { formatTerminal, formatNeutralizeTerminal } from './formatters/terminal.js';
import { formatJson } from './formatters/json.js';
import { formatSarif } from './formatters/sarif.js';

const HELP_TEXT = `
gitambush — Git Boobytrap & GitSpawn Forensic Auditor (Zero Dependencies)

USAGE:
  gitambush [command] [options] [path]

COMMANDS:
  scan [path]              Scan a repository for GitSpawn, malicious filters & hooks (default)
  neutralize [path]        Surgically defang detected boobytraps while preserving history
  clone <repo-url> [dest]  Quarantine-clone remote repo and sanitize before checkout
  rules                    Print catalog of all detection rules, CVEs, and descriptions

OPTIONS:
  -f, --format <format>    Output format: "terminal", "json", "sarif" (default: "terminal")
  --fail-on <level>        Exit code 1 if findings meet level: critical, high, medium, low (default: high)
  --min-severity <level>   Minimum severity to report (default: info)
  --dry-run                Preview neutralization actions without modifying disk
  -q, --quiet              Suppress banner and non-essential output
  -v, --version            Display version number
  -h, --help               Display this help guide

EXAMPLES:
  gitambush scan .
  gitambush scan /path/to/downloaded-repo --format sarif > results.sarif
  gitambush neutralize ./untrusted-repo
  gitambush clone https://github.com/evil-actor/repo.git ./safe-repo
  gitambush rules
`;

export async function runCli(argv = process.argv.slice(2)) {
  const parsed = parseArgs(argv);

  if (parsed.help) {
    console.log(HELP_TEXT);
    return 0;
  }

  if (parsed.version) {
    console.log('gitambush v1.0.0');
    return 0;
  }

  const command = parsed.command;

  try {
    switch (command) {
      case 'rules': {
        printRules();
        return 0;
      }

      case 'neutralize': {
        const targetPath = parsed.positionals[0] || '.';
        const report = neutralizeRepository(targetPath, { dryRun: parsed.dryRun });
        console.log(formatNeutralizeTerminal(report));
        return 0;
      }

      case 'clone': {
        const repoUrl = parsed.positionals[0];
        const dest = parsed.positionals[1];
        if (!repoUrl) {
          console.error('Error: Repository URL is required for "clone".');
          console.error('Usage: gitambush clone <repo-url> [target-dir]');
          return 2;
        }
        console.log(`\nCloning into quarantine: ${repoUrl}...`);
        const cloneReport = safeClone(repoUrl, dest);
        console.log(`✓ Safe clone complete! Destination: ${cloneReport.targetDir}`);
        if (cloneReport.quarantinedThreatsDetected > 0) {
          console.log(`⚠️  Neutralized ${cloneReport.threatsNeutralized} boobytrap(s) before checkout.`);
        } else {
          console.log('✓ Clean: No boobytraps detected in cloned repository.');
        }
        return 0;
      }

      case 'scan':
      default: {
        const targetPath = parsed.positionals[0] || '.';
        const scanResult = scanRepository(targetPath, { minSeverity: parsed.minSeverity });

        let output = '';
        if (parsed.format === 'json') {
          output = formatJson(scanResult);
        } else if (parsed.format === 'sarif') {
          output = formatSarif(scanResult);
        } else {
          output = formatTerminal(scanResult);
        }

        console.log(output);

        // Determine exit code
        const failScore = SeverityOrder[parsed.failOn] ?? 3; // default High (3)
        const hasFailingFinding = scanResult.findings.some(f => (f.severityScore || 0) >= failScore);

        return hasFailingFinding ? 1 : 0;
      }
    }
  } catch (err) {
    console.error(`\nError: ${err.message}`);
    return 2;
  }
}

function parseArgs(args) {
  const result = {
    command: 'scan',
    positionals: [],
    format: 'terminal',
    failOn: 'HIGH',
    minSeverity: 'INFO',
    dryRun: false,
    quiet: false,
    help: false,
    version: false
  };

  const knownCommands = new Set(['scan', 'neutralize', 'clone', 'rules']);
  let i = 0;

  // Check if first arg is a known command
  if (args.length > 0 && knownCommands.has(args[0])) {
    result.command = args[0];
    i = 1;
  }

  for (; i < args.length; i++) {
    const arg = args[i];

    if (arg === '-h' || arg === '--help') {
      result.help = true;
    } else if (arg === '-v' || arg === '--version') {
      result.version = true;
    } else if (arg === '--dry-run') {
      result.dryRun = true;
    } else if (arg === '-q' || arg === '--quiet') {
      result.quiet = true;
    } else if (arg === '-f' || arg === '--format') {
      result.format = (args[++i] || 'terminal').toLowerCase();
    } else if (arg === '--fail-on') {
      result.failOn = (args[++i] || 'high').toUpperCase();
    } else if (arg === '--min-severity') {
      result.minSeverity = (args[++i] || 'info').toUpperCase();
    } else if (!arg.startsWith('-')) {
      result.positionals.push(arg);
    }
  }

  return result;
}

function printRules() {
  console.log('\ngitambush Detection Rules Catalog:\n');
  const list = Object.values(RULES);
  for (const r of list) {
    const cve = r.cve && r.cve !== 'N/A' ? ` [${r.cve}]` : '';
    console.log(`  ${r.id}: ${r.title} (${r.severity})${cve}`);
    console.log(`    Category: ${r.category}`);
    console.log(`    ${r.description}`);
    console.log(`    Fix: ${r.remediation}\n`);
  }
}
