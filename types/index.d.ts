/**
 * TypeScript Type Definitions for gitambush
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Finding {
  ruleId: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  severityScore: number;
  cve: string;
  description: string;
  remediation: string;
  file: string;
  line: number;
  snippet: string;
}

export interface ScanStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanResult {
  targetPath: string;
  scannedGitDir: string | null;
  totalFindings: number;
  stats: ScanStats;
  findings: Finding[];
}

export interface ScanOptions {
  minSeverity?: SeverityLevel | string;
}

export interface NeutralizeOptions {
  dryRun?: boolean;
}

export interface NeutralizeAction {
  target: string;
  type: string;
  backupPath?: string | null;
  linesCommented?: number;
  description: string;
}

export interface NeutralizeResult {
  repoPath: string;
  dryRun: boolean;
  threatsFound: number;
  threatsNeutralized: number;
  remainingThreats?: number;
  backups: string[];
  actions: NeutralizeAction[];
}

export interface CloneResult {
  repoUrl: string;
  targetDir: string;
  quarantinedThreatsDetected: number;
  threatsNeutralized: number;
  checkoutSuccess: boolean;
  findings: Finding[];
}

export interface RuleDefinition {
  id: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  cve: string;
  description: string;
  remediation: string;
}

export declare const RULES: Record<string, RuleDefinition>;
export declare const Severity: Record<SeverityLevel, SeverityLevel>;

export declare function scanRepository(repoPath: string, options?: ScanOptions): ScanResult;
export declare function neutralizeRepository(repoPath: string, options?: NeutralizeOptions): NeutralizeResult;
export declare function safeClone(repoUrl: string, targetDir?: string): CloneResult;
export declare function getRule(id: string): RuleDefinition | null;
export declare function meetsThreshold(severity: string, minSeverity: string): boolean;
export declare function formatTerminal(scanResult: ScanResult): string;
export declare function formatNeutralizeTerminal(report: NeutralizeResult): string;
export declare function formatJson(scanResult: ScanResult): string;
export declare function formatSarif(scanResult: ScanResult): string;
