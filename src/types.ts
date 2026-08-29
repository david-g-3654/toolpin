/**
 * Core data model shared by collectors, rules, and reporters.
 *
 * The scanner is a two-phase pipeline:
 *   1. collectors turn a target (directory, MCP client config, live server) into `Artifact`s
 *   2. rules read `Artifact`s and emit `Finding`s
 *
 * Everything in between is plain data, so a consumer can embed the engine without the CLI.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** How sure we are that the match is a real problem rather than a lookalike. */
export type Confidence = 'high' | 'medium' | 'low';

export type Category =
  | 'tool-poisoning'
  | 'prompt-injection'
  | 'credential-exposure'
  | 'exfiltration'
  | 'command-execution'
  | 'supply-chain'
  | 'configuration'
  | 'transport'
  | 'obfuscation'
  | 'skill'
  | 'drift';

/**
 * What a piece of text *is*. Rules subscribe to kinds rather than to file
 * extensions, because the same sentence means something very different in a
 * README (documentation) than in a tool description (instructions the model obeys).
 */
export type ArtifactKind =
  | 'tool-name'
  | 'tool-description'
  | 'param-description'
  | 'prompt'
  | 'resource'
  | 'server-instructions'
  | 'skill'
  | 'skill-frontmatter'
  | 'source'
  | 'manifest'
  | 'config'
  | 'doc';

export type Language = 'js' | 'ts' | 'py' | 'md' | 'json' | 'yaml' | 'shell' | 'other';

/** A unit of text with enough provenance to point a human (or SARIF) back at it. */
export interface Artifact {
  kind: ArtifactKind;
  /** Absolute path of the file this text came from. */
  file: string;
  /** The text a rule should analyse. */
  text: string;
  /** 1-based line in `file` where `text` starts. Offsets are computed relative to this. */
  lineOffset: number;
  language: Language;
  /** Logical server this artifact belongs to (config key, package name, or directory name). */
  serverId?: string;
  /** Tool / prompt / resource name, when the artifact is scoped to one. */
  toolName?: string;
  /** Free-form structured payload for structural rules (parsed JSON, frontmatter, …). */
  data?: unknown;
}

export interface Location {
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  snippet?: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** One sentence: what is wrong here, in this file. */
  message: string;
  location: Location;
  /** The matched text, redacted if it looks like a secret. */
  evidence?: string;
  remediation: string;
  references?: string[];
  serverId?: string;
  toolName?: string;
  /** Stable hash of (rule, file, evidence) used for baselines and dedupe. */
  fingerprint: string;
}

/** A logical scan target: one MCP server, one skill, or one directory. */
export interface Target {
  id: string;
  /** Human label shown in reports. */
  name: string;
  kind: 'server' | 'skill' | 'directory' | 'client-config';
  /** Path on disk, or the launch command for a configured server. */
  path: string;
  /** How this target was launched, when it came from a client config. */
  command?: { command: string; args: string[]; env?: Record<string, string>; url?: string; type?: string };
  /** sha256 over the target's tool surface, used by the trust registry and lockfile. */
  fingerprint?: string;
  tools?: ToolDescriptor[];
}

export interface ToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: unknown;
  /** Where the descriptor came from: static parse of source, or a live handshake. */
  origin: 'static' | 'introspect';
}

export interface ScanOptions {
  /** Paths to scan. */
  paths: string[];
  /** Also scan MCP client configs discovered on this machine. */
  includeClientConfigs: boolean;
  /** Launch servers and read their real tool list. Off by default: it executes code. */
  introspect: boolean;
  introspectTimeoutMs: number;
  /** Rule ids or categories to skip. */
  ignore: string[];
  /** Gitignore-style path patterns to exclude, on top of any .toolpinignore file. */
  exclude: string[];
  /** Minimum severity to report. */
  minSeverity: Severity;
  /** Cap on bytes read per file. */
  maxFileBytes: number;
  /** Path to a baseline file of fingerprints to suppress. */
  baseline?: string;
  /** Path to a lockfile for drift / rug-pull detection. */
  lockfile?: string;
  /** Extra trust-registry files to load on top of the bundled one. */
  registries: string[];
  noRegistry: boolean;
}

export interface ScanResult {
  version: string;
  scannedAt: string;
  targets: Target[];
  findings: Finding[];
  stats: {
    filesScanned: number;
    artifactsAnalyzed: number;
    durationMs: number;
    bySeverity: Record<Severity, number>;
  };
  /** Letter grade derived from findings, for the badge / summary line. */
  grade: string;
  trust: TrustVerdict[];
  errors: string[];
}

export interface TrustVerdict {
  targetId: string;
  status: 'trusted' | 'unknown' | 'caution' | 'malicious';
  reason: string;
  source?: string;
  fingerprintMatch?: boolean;
}

/** Context handed to every rule. */
export interface RuleContext {
  artifacts: Artifact[];
  targets: Target[];
  options: ScanOptions;
  /** Read a file that the collector already loaded, if available. */
  fileText(path: string): string | undefined;
}

export interface Rule {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** Artifact kinds this rule inspects. Empty means "runs once over the whole context". */
  kinds: ArtifactKind[];
  remediation: string;
  references?: string[];
  /** Per-artifact check. */
  check?(artifact: Artifact, ctx: RuleContext): Finding[];
  /** Whole-scan check, for cross-artifact analysis (shadowing, drift, …). */
  checkAll?(ctx: RuleContext): Finding[];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};
