import { pathToFileURL } from 'node:url';
import { relative, isAbsolute } from 'node:path';
import type { Finding, ScanResult, Severity } from '../types.js';
import { allRules } from '../rules/index.js';

const LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** SARIF security-severity, the 0-10 scale GitHub code scanning sorts on. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '7.5',
  medium: '5.0',
  low: '3.0',
  info: '1.0',
};

/**
 * SARIF 2.1.0. Paths are emitted relative to the scan root with a
 * `srcroot` uriBaseId so GitHub code scanning can map them onto the repo.
 */
export function renderSarif(result: ScanResult, root = process.cwd()): string {
  const usedRules = new Map<string, Finding>();
  for (const f of result.findings) if (!usedRules.has(f.ruleId)) usedRules.set(f.ruleId, f);

  const ruleIndex = new Map<string, number>();
  const rules = [...usedRules.keys()].map((id, i) => {
    ruleIndex.set(id, i);
    const definition = allRules.find((r) => r.id === id);
    const sample = usedRules.get(id)!;
    return {
      id,
      name: toPascalCase(definition?.title ?? sample.title),
      shortDescription: { text: definition?.title ?? sample.title },
      fullDescription: { text: `${definition?.title ?? sample.title}. ${definition?.remediation ?? sample.remediation}` },
      help: {
        text: definition?.remediation ?? sample.remediation,
        markdown: `**${definition?.title ?? sample.title}**\n\n${definition?.remediation ?? sample.remediation}`,
      },
      properties: {
        tags: ['security', 'mcp', definition?.category ?? sample.category],
        'security-severity': SECURITY_SEVERITY[definition?.severity ?? sample.severity],
        precision: definition?.confidence ?? sample.confidence,
      },
      defaultConfiguration: { level: LEVEL[definition?.severity ?? sample.severity] },
    };
  });

  const results = result.findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
    level: LEVEL[f.severity],
    message: { text: f.evidence ? `${f.message} (evidence: ${f.evidence})` : f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toUri(f.location.file, root), uriBaseId: 'SRCROOT' },
          region: {
            startLine: Math.max(1, f.location.line),
            startColumn: Math.max(1, f.location.column),
            ...(f.location.endLine ? { endLine: Math.max(1, f.location.endLine) } : {}),
            ...(f.location.snippet ? { snippet: { text: f.location.snippet } } : {}),
          },
        },
        ...(f.toolName ? { logicalLocations: [{ name: f.toolName, kind: 'member' }] } : {}),
      },
    ],
    partialFingerprints: { toolpinFingerprint: f.fingerprint },
    properties: {
      confidence: f.confidence,
      category: f.category,
      ...(f.serverId ? { serverId: f.serverId } : {}),
    },
  }));

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'toolpin',
            version: result.version,
            informationUri: 'https://github.com/david-g-3654/toolpin',
            rules,
          },
        },
        originalUriBaseIds: { SRCROOT: { uri: `${pathToFileURL(root).href.replace(/\/?$/, '/')}` } },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: result.scannedAt,
            ...(result.errors.length
              ? { toolExecutionNotifications: result.errors.map((e) => ({ level: 'note', message: { text: e } })) }
              : {}),
          },
        ],
        results,
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function toUri(file: string, root: string): string {
  if (!isAbsolute(file)) return file.split('\\').join('/');
  const rel = relative(root, file);
  return (rel && !rel.startsWith('..') ? rel : file).split('\\').join('/');
}

function toPascalCase(s: string): string {
  return s
    .replace(/[^A-Za-z0-9 ]/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join('');
}
