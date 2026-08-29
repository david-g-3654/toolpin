import { createHash } from 'node:crypto';
import type { Artifact, Finding, Location, Rule } from '../types.js';

/** Convert a character index inside `text` into a 1-based line/column. */
export function indexToPosition(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;
  const stop = Math.min(index, text.length);
  for (let i = 0; i < stop; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: index - lastNewline };
}

/** Build a SARIF-friendly location for a match at `index` inside an artifact. */
export function locate(artifact: Artifact, index: number, length: number): Location {
  const start = indexToPosition(artifact.text, index);
  const end = indexToPosition(artifact.text, index + length);
  const lineStart = artifact.text.lastIndexOf('\n', Math.max(0, index - 1)) + 1;
  let lineEnd = artifact.text.indexOf('\n', index);
  if (lineEnd === -1) lineEnd = artifact.text.length;
  return {
    file: artifact.file,
    line: start.line + artifact.lineOffset - 1,
    column: start.column,
    endLine: end.line + artifact.lineOffset - 1,
    endColumn: end.column,
    snippet: truncate(artifact.text.slice(lineStart, lineEnd).trim(), 200),
  };
}

export function truncate(s: string, max: number): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1)}…`;
}

/**
 * Redact anything that looks like a live credential so reports and SARIF
 * uploads never become a second copy of the secret.
 */
/**
 * Replace invisible characters with a visible marker. Printing the raw bytes
 * would reproduce, in the report, the exact concealment the report is about.
 */
export function revealInvisible(s: string): string {
  let out = '';
  let runCount = 0;
  let runCp = -1;
  const flush = () => {
    if (!runCount) return;
    out += `[U+${runCp.toString(16).toUpperCase().padStart(4, '0')}x${runCount}]`;
    runCount = 0;
    runCp = -1;
  };
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    const invisible =
      (cp >= 0x200b && cp <= 0x200f) ||
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2060 && cp <= 0x2069) ||
      cp === 0xfeff ||
      cp === 0x00ad ||
      (cp >= 0xe000 && cp <= 0xf8ff) ||
      (cp >= 0xe0000 && cp <= 0xe007f);
    if (!invisible) {
      flush();
      out += ch;
      continue;
    }
    if (cp !== runCp) flush();
    runCp = cp;
    runCount++;
  }
  flush();
  return out;
}

export function redact(s: string): string {
  return revealInvisible(s)
    .replace(/(sk-[A-Za-z0-9_-]{6})[A-Za-z0-9_-]+/g, '$1_REDACTED')
    .replace(/(gh[pousr]_[A-Za-z0-9]{4})[A-Za-z0-9]+/g, '$1_REDACTED')
    .replace(/(xox[abprs]-[A-Za-z0-9]{4})[A-Za-z0-9-]+/g, '$1_REDACTED')
    .replace(/(AKIA)[0-9A-Z]{12,}/g, '$1_REDACTED')
    .replace(/(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*/g, '$1_REDACTED')
    .replace(/((?:api[_-]?key|secret|token|password)\s*[:=]\s*["']?)([^"'\s,}]{8,})/gi, '$1_REDACTED');
}

/** Shannon entropy in bits per character - used to separate real keys from placeholders. */
export function entropy(s: string): number {
  if (!s.length) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function sha256(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

export function fingerprintOf(ruleId: string, file: string, evidence: string): string {
  return sha256(`${ruleId} ${file} ${evidence.replace(/\s+/g, ' ').trim()}`).slice(0, 16);
}

/**
 * Characters that are invisible or direction-changing in a terminal and in most
 * chat UIs, but fully visible to the model reading the tool description.
 * This is the primary carrier for hidden tool-poisoning payloads.
 */
export const INVISIBLE_CHARS: Array<{ re: RegExp; name: string }> = [
  { re: /[\u200B-\u200F]/g, name: 'zero-width space / directional mark' },
  { re: /[\u202A-\u202E]/g, name: 'bidirectional override' },
  { re: /[\u2066-\u2069]/g, name: 'bidirectional isolate' },
  { re: /[\u2060-\u2064]/g, name: 'word joiner / invisible operator' },
  { re: /\uFEFF/g, name: 'byte order mark' },
  { re: /[\uE000-\uF8FF]/g, name: 'private use area' },
  { re: /[\u{E0000}-\u{E007F}]/gu, name: 'unicode tag character' },
  { re: /\u00AD/g, name: 'soft hyphen' },
];

/** Detect a name written in mixed scripts (Cyrillic 'a' inside an ASCII word, etc). */
export function mixedScripts(s: string): string[] {
  const scripts: string[] = [];
  if (/[a-zA-Z]/.test(s)) scripts.push('Latin');
  if (/[\u0400-\u04FF]/.test(s)) scripts.push('Cyrillic');
  if (/[\u0370-\u03FF]/.test(s)) scripts.push('Greek');
  if (/[\u0530-\u058F]/.test(s)) scripts.push('Armenian');
  if (/[\u4E00-\u9FFF]/.test(s)) scripts.push('Han');
  return scripts;
}

export interface PatternSpec {
  re: RegExp;
  /** Overrides the rule default when one pattern is stronger evidence than another. */
  severity?: Finding['severity'];
  confidence?: Finding['confidence'];
  /** Extra message detail appended after the rule title. */
  note?: string;
  /** Reject a match after the fact (e.g. placeholder values, commented-out code). */
  refine?(match: RegExpExecArray, artifact: Artifact): boolean;
}

/**
 * Turn a list of regexes into a rule `check`. Each distinct match location
 * produces one finding; repeated identical evidence in one artifact collapses.
 */
export function patternCheck(rule: Omit<Rule, 'check' | 'checkAll'>, patterns: PatternSpec[]) {
  return (artifact: Artifact): Finding[] => {
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const spec of patterns) {
      const flags = spec.re.flags.includes('g') ? spec.re.flags : `${spec.re.flags}g`;
      const re = new RegExp(spec.re.source, flags);
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(artifact.text)) !== null && guard++ < 200) {
        if (m[0].length === 0) {
          re.lastIndex++;
          continue;
        }
        if (spec.refine && !spec.refine(m, artifact)) continue;
        const evidence = redact(truncate(m[0], 240));
        const key = `${rule.id}:${evidence}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const location = locate(artifact, m.index, m[0].length);
        out.push({
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: spec.severity ?? rule.severity,
          confidence: spec.confidence ?? rule.confidence,
          message: spec.note ? `${rule.title} - ${spec.note}` : rule.title,
          location,
          evidence,
          remediation: rule.remediation,
          references: rule.references,
          serverId: artifact.serverId,
          toolName: artifact.toolName,
          fingerprint: fingerprintOf(rule.id, artifact.file, evidence),
        });
      }
    }
    return out;
  };
}

/** Convenience for structural rules that build findings by hand. */
export function makeFinding(
  rule: Pick<Rule, 'id' | 'title' | 'category' | 'severity' | 'confidence' | 'remediation' | 'references'>,
  opts: {
    message: string;
    location: Location;
    evidence?: string;
    severity?: Finding['severity'];
    confidence?: Finding['confidence'];
    serverId?: string;
    toolName?: string;
  },
): Finding {
  const evidence = opts.evidence ? redact(truncate(opts.evidence, 240)) : undefined;
  return {
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: opts.severity ?? rule.severity,
    confidence: opts.confidence ?? rule.confidence,
    message: opts.message,
    location: opts.location,
    evidence,
    remediation: rule.remediation,
    references: rule.references,
    serverId: opts.serverId,
    toolName: opts.toolName,
    fingerprint: fingerprintOf(rule.id, opts.location.file, evidence ?? opts.message),
  };
}

/** Line (1-based) of the first occurrence of `needle` in `haystack`. */
export function lineOf(haystack: string, needle: string, from = 0): number {
  const idx = haystack.indexOf(needle, from);
  if (idx === -1) return 1;
  return indexToPosition(haystack, idx).line;
}

/**
 * Bundled or minified output, where a "line" can be the whole program.
 * Proximity heuristics are meaningless here: everything is within N lines of
 * everything else, so any rule built on a line window must opt out.
 */
export function isMinified(text: string): boolean {
  const lines = text.split('\n');
  if (lines.length === 0) return false;
  let longest = 0;
  for (const line of lines) if (line.length > longest) longest = line.length;
  return longest > 2000 || text.length / lines.length > 400;
}

/** Test and fixture files legitimately contain credential-shaped literals. */
export function isTestPath(file: string): boolean {
  return /(?:^|[/\\])(?:__tests__|__mocks__|tests?|spec|fixtures?|e2e|examples?)[/\\]|\.(?:test|spec)\.[jt]sx?$|_test\.py$|test_[^/\\]*\.py$/i.test(
    file,
  );
}
