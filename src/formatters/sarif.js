/**
 * gitambush SARIF 2.1.0 Formatter
 *
 * Emits standard SARIF log for native integration with GitHub Code Scanning alerts.
 */

import path from 'node:path';
import { RULES } from '../rules.js';

export function formatSarif(scanResult) {
  const sarifRules = Object.values(RULES).map(r => ({
    id: r.id,
    name: r.id,
    shortDescription: {
      text: r.title
    },
    fullDescription: {
      text: r.description
    },
    defaultConfiguration: {
      level: mapSeverityToSarifLevel(r.severity)
    },
    help: {
      text: `${r.description}\n\nRemediation:\n${r.remediation}`
    },
    properties: {
      category: r.category,
      cve: r.cve
    }
  }));

  const results = scanResult.findings.map(f => {
    let relUri = f.file;
    if (f.file.startsWith(scanResult.targetPath)) {
      relUri = f.file.slice(scanResult.targetPath.length).replace(/^[/\\]/, '');
    }
    // Normalize Windows backslashes to forward slashes for SARIF URI
    relUri = relUri.split(path.sep).join('/');

    return {
      ruleId: f.ruleId,
      level: mapSeverityToSarifLevel(f.severity),
      message: {
        text: f.description
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: relUri,
              uriBaseId: '%SRCROOT%'
            },
            region: {
              startLine: f.line || 1,
              startColumn: 1,
              snippet: f.snippet ? { text: f.snippet } : undefined
            }
          }
        }
      ]
    };
  });

  const sarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'gitambush',
            version: '1.0.0',
            informationUri: 'https://github.com/Nithinfgs/gitambush',
            rules: sarifRules
          }
        },
        results
      }
    ]
  };

  return JSON.stringify(sarifLog, null, 2);
}

function mapSeverityToSarifLevel(sev) {
  switch (sev) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
    default:
      return 'note';
  }
}
