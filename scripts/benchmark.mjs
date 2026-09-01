#!/usr/bin/env node
/**
 * False-positive benchmark.
 *
 * Downloads a corpus of widely used, presumably-clean MCP servers from npm and
 * scans each one. A security scanner's noise rate is the number that decides
 * whether anyone keeps it in CI, so it should be measured and published rather
 * than asserted.
 *
 *   node scripts/benchmark.mjs            # table to stdout
 *   node scripts/benchmark.mjs --json     # machine-readable
 *
 * Packages are fetched with `npm pack` and extracted. They are never installed
 * and never executed: no lifecycle scripts run.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../dist/index.js';

const run = promisify(execFile);

export const CORPUS = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-everything',
  '@playwright/mcp',
  '@upstash/context7-mcp',
  '@notionhq/notion-mcp-server',
  'firecrawl-mcp',
  'exa-mcp-server',
  'tavily-mcp',
  'mcp-server-kubernetes',
  'figma-developer-mcp',
  'mcp-remote',
];

async function fetchPackage(spec, into) {
  const dir = join(into, spec.replace(/[@/]/g, '_'));
  await run('mkdir', ['-p', dir]);
  try {
    await run('npm', ['pack', spec, '--silent'], { cwd: dir });
  } catch {
    return undefined;
  }
  const tarballs = (await readdir(dir)).filter((f) => f.endsWith('.tgz'));
  if (!tarballs.length) return undefined;
  await run('tar', ['xzf', tarballs[0]], { cwd: dir });
  const pkg = join(dir, 'package');
  return existsSync(pkg) ? pkg : undefined;
}

async function main() {
  const asJson = process.argv.includes('--json');
  const workdir = await mkdtemp(join(tmpdir(), 'toolpin-bench-'));
  const rows = [];

  try {
    for (const spec of CORPUS) {
      const path = await fetchPackage(spec, workdir);
      if (!path) {
        rows.push({ package: spec, error: 'download failed' });
        continue;
      }
      const result = await scan({ paths: [path] });
      const findings = result.findings.map((f) => ({
        rule: f.ruleId,
        severity: f.severity,
        confidence: f.confidence,
        message: f.message,
      }));
      rows.push({
        package: spec,
        files: result.stats.filesScanned,
        tools: result.targets[0]?.tools?.length ?? 0,
        grade: result.grade,
        findings,
      });
    }
  } finally {
    await rm(workdir, { recursive: true, force: true });
  }

  const scanned = rows.filter((r) => !r.error);
  const total = scanned.reduce((n, r) => n + r.findings.length, 0);
  const clean = scanned.filter((r) => r.findings.length === 0).length;
  const critical = scanned.reduce((n, r) => n + r.findings.filter((f) => f.severity === 'critical').length, 0);
  const summary = {
    packages: scanned.length,
    clean,
    totalFindings: total,
    critical,
    findingsPerPackage: scanned.length ? +(total / scanned.length).toFixed(2) : 0,
  };

  if (asJson) {
    process.stdout.write(`${JSON.stringify({ summary, rows }, null, 2)}\n`);
    return;
  }

  process.stdout.write(`\n${'PACKAGE'.padEnd(48)}${'FILES'.padStart(6)}${'TOOLS'.padStart(6)}  FINDINGS\n`);
  for (const r of rows) {
    if (r.error) {
      process.stdout.write(`${r.package.padEnd(48)}${'-'.padStart(6)}${'-'.padStart(6)}  ${r.error}\n`);
      continue;
    }
    const detail = r.findings.length
      ? r.findings.map((f) => `${f.rule}(${f.severity[0]}/${f.confidence[0]})`).join(' ')
      : 'clean';
    process.stdout.write(`${r.package.padEnd(48)}${String(r.files).padStart(6)}${String(r.tools).padStart(6)}  ${detail}\n`);
  }
  process.stdout.write(
    `\n${summary.packages} packages · ${summary.clean} fully clean · ` +
      `${summary.totalFindings} findings (${summary.findingsPerPackage}/package) · ${summary.critical} critical\n\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`benchmark failed: ${err.message}\n`);
  process.exitCode = 1;
});
