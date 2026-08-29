import { relative } from 'node:path';
import type { Finding, ScanResult, Severity } from '../types.js';

const useColor = process.env['NO_COLOR'] === undefined && process.env['TERM'] !== 'dumb';
const c = (code: string) => (s: string) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);
const dim = c('2');
const bold = c('1');
const red = c('31');
const brightRed = c('91');
const yellow = c('33');
const blue = c('34');
const green = c('32');
const gray = c('90');

const SEVERITY_STYLE: Record<Severity, (s: string) => string> = {
  critical: brightRed,
  high: red,
  medium: yellow,
  low: blue,
  info: gray,
};

const MARK: Record<Severity, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED ',
  low: 'LOW ',
  info: 'INFO',
};

export function renderTerminal(result: ScanResult, cwd = process.cwd()): string {
  const lines: string[] = [];
  const rel = (p: string) => {
    const r = relative(cwd, p);
    return r && !r.startsWith('..') ? r : p;
  };

  lines.push('');
  lines.push(bold(`toolpin ${result.version}`) + dim(`  ${result.stats.filesScanned} files, ${result.targets.length} targets, ${result.stats.durationMs}ms`));

  if (!result.findings.length) {
    lines.push('');
    lines.push(green('  No findings.'));
  }

  // Findings arrive severity-ordered; group them by file so a file is shown once,
  // with the most alarming file first.
  const groups = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const list = groups.get(f.location.file) ?? [];
    list.push(f);
    groups.set(f.location.file, list);
  }
  for (const [file, findings] of groups) {
    lines.push('');
    lines.push(bold(rel(file)));
    for (const f of findings) {
      const style = SEVERITY_STYLE[f.severity];
      const scope = f.toolName ? dim(` [${f.toolName}]`) : '';
      lines.push(`  ${style(MARK[f.severity])} ${dim(`${f.location.line}:${f.location.column}`)}  ${f.message}${scope}`);
      lines.push(`       ${dim(`${f.ruleId} · confidence ${f.confidence}`)}`);
      if (f.evidence) lines.push(`       ${gray(`> ${f.evidence}`)}`);
    }
  }

  // Trust verdicts worth surfacing.
  const notable = result.trust.filter((t) => t.status !== 'unknown');
  if (notable.length) {
    lines.push('');
    lines.push(bold('Trust registry'));
    for (const t of notable) {
      const style = t.status === 'malicious' ? brightRed : t.status === 'caution' ? yellow : green;
      lines.push(`  ${style(t.status.toUpperCase())} ${t.targetId} ${dim(`- ${t.reason}`)}`);
    }
  }

  if (result.errors.length) {
    lines.push('');
    lines.push(bold('Notes'));
    for (const e of result.errors.slice(0, 10)) lines.push(`  ${dim(e)}`);
    if (result.errors.length > 10) lines.push(`  ${dim(`... and ${result.errors.length - 10} more`)}`);
  }

  lines.push('');
  lines.push(summaryLine(result));
  lines.push('');
  return lines.join('\n');
}

export function summaryLine(result: ScanResult): string {
  const s = result.stats.bySeverity;
  const parts: string[] = [];
  if (s.critical) parts.push(brightRed(`${s.critical} critical`));
  if (s.high) parts.push(red(`${s.high} high`));
  if (s.medium) parts.push(yellow(`${s.medium} medium`));
  if (s.low) parts.push(blue(`${s.low} low`));
  if (s.info) parts.push(gray(`${s.info} info`));
  const gradeStyle = result.grade === 'A' ? green : result.grade === 'B' || result.grade === 'C' ? yellow : brightRed;
  const counts = parts.length ? parts.join(', ') : green('no findings');
  return `  ${bold('Grade')} ${gradeStyle(result.grade)}   ${counts}`;
}

/** Compact one-line-per-finding output for piping into grep. */
export function renderCompact(findings: Finding[]): string {
  return findings
    .map((f) => `${f.location.file}:${f.location.line}:${f.location.column}: ${f.severity}: [${f.ruleId}] ${f.message}`)
    .join('\n');
}
