import { relative } from 'node:path';
import type { ScanResult, Severity } from '../types.js';

const ICON: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

/** Markdown suitable for a PR comment or a CI job summary. */
export function renderMarkdown(result: ScanResult, root = process.cwd()): string {
  const rel = (p: string) => {
    const r = relative(root, p);
    return r && !r.startsWith('..') ? r : p;
  };
  const s = result.stats.bySeverity;
  const out: string[] = [];

  out.push(`## toolpin: grade ${result.grade}`);
  out.push('');
  out.push(
    `${result.findings.length} finding${result.findings.length === 1 ? '' : 's'} across ${result.targets.length} target${
      result.targets.length === 1 ? '' : 's'
    } (${result.stats.filesScanned} files, ${result.stats.durationMs} ms).`,
  );
  out.push('');
  out.push('| Critical | High | Medium | Low | Info |');
  out.push('|---:|---:|---:|---:|---:|');
  out.push(`| ${s.critical} | ${s.high} | ${s.medium} | ${s.low} | ${s.info} |`);

  if (result.findings.length) {
    out.push('');
    out.push('| Severity | Rule | Location | Finding |');
    out.push('|---|---|---|---|');
    for (const f of result.findings.slice(0, 100)) {
      const location = `\`${rel(f.location.file)}:${f.location.line}\``;
      out.push(`| ${ICON[f.severity]} | \`${f.ruleId}\` | ${location} | ${escapePipes(f.message)} |`);
    }
    if (result.findings.length > 100) out.push('');
    if (result.findings.length > 100) out.push(`_... and ${result.findings.length - 100} more._`);
  }

  const notable = result.trust.filter((t) => t.status !== 'unknown');
  if (notable.length) {
    out.push('');
    out.push('### Trust registry');
    for (const t of notable) out.push(`- **${t.status}** \`${t.targetId}\` - ${t.reason}`);
  }

  if (result.errors.length) {
    out.push('');
    out.push('<details><summary>Scanner notes</summary>');
    out.push('');
    for (const e of result.errors) out.push(`- ${escapePipes(e)}`);
    out.push('');
    out.push('</details>');
  }
  out.push('');
  return out.join('\n');
}

function escapePipes(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}
