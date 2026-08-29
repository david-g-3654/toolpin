import { parseArgs } from 'node:util';
import { writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ScanOptions, ScanResult, Severity } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { VERSION, scan } from './engine/scanner.js';
import { buildLock, writeLock } from './engine/lockfile.js';
import { renderTerminal, renderCompact, summaryLine } from './report/terminal.js';
import { renderSarif } from './report/sarif.js';
import { renderMarkdown } from './report/markdown.js';
import { allRules } from './rules/index.js';
import { bundledRegistryPath, loadRegistry, packageOf } from './registry/trust.js';

const HELP = `
toolpin ${VERSION} - security scanner for MCP servers and agent skills

USAGE
  toolpin <command> [paths...] [options]

COMMANDS
  scan [paths...]     Scan directories, servers, or skills (default)
  config              Scan the MCP servers configured on this machine
  pin [paths...]      Record the current tool surface to a lockfile
  trust [paths...]    Show trust-registry verdicts and tool-surface fingerprints
  rules               List every rule the scanner knows about

OPTIONS
  -f, --format <fmt>       pretty | json | sarif | markdown | compact   (default: pretty)
  -o, --output <file>      Write the report to a file instead of stdout
  -s, --severity <level>   Minimum severity to report                   (default: low)
      --fail-on <level>    Exit non-zero at or above this severity      (default: high)
  -i, --ignore <ids>       Rule ids, id prefixes, or categories to skip (repeatable)
  -x, --exclude <glob>     Paths to skip, gitignore-style (repeatable)
                           Also read from a .toolpinignore file in the scan root
      --client-configs     Also scan MCP client configs found on this machine
      --introspect         Launch each configured server and read its live tool list
      --introspect-timeout <ms>                                          (default: 10000)
      --lock <file>        Compare the tool surface against a lockfile
      --baseline <file>    Suppress fingerprints listed in this file
      --registry <file>    Additional trust registry to load (repeatable)
      --no-registry        Skip trust-registry evaluation entirely
      --max-file-size <n>  Skip files larger than n bytes               (default: 1000000)
      --no-color           Disable ANSI colour
  -h, --help               Show this help
  -v, --version            Show the version

EXIT CODES
  0  clean (or only findings below --fail-on)
  1  findings at or above --fail-on
  2  usage or internal error

EXAMPLES
  toolpin .                             Scan the server in this directory
  toolpin config                        Audit what your agent already runs
  toolpin config --introspect           ... and ask each server what it exposes
  toolpin scan . -f sarif -o mcp.sarif  Produce a SARIF report for CI
  toolpin pin --client-configs          Pin the current tool surface
  toolpin config --lock toolpin.lock  Detect a changed tool description

toolpin is offline by default: it makes no network requests and sends no telemetry.
`;

interface Cli {
  command: string;
  paths: string[];
  options: Partial<ScanOptions>;
  format: string;
  output?: string;
  failOn: Severity;
}

function isSeverity(s: string): s is Severity {
  return s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'info';
}

function parse(argv: string[]): Cli | { help: true } | { version: true } {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      format: { type: 'string', short: 'f' },
      output: { type: 'string', short: 'o' },
      severity: { type: 'string', short: 's' },
      'fail-on': { type: 'string' },
      ignore: { type: 'string', short: 'i', multiple: true },
      exclude: { type: 'string', short: 'x', multiple: true },
      'client-configs': { type: 'boolean' },
      introspect: { type: 'boolean' },
      'introspect-timeout': { type: 'string' },
      lock: { type: 'string' },
      baseline: { type: 'string' },
      registry: { type: 'string', multiple: true },
      'no-registry': { type: 'boolean' },
      'max-file-size': { type: 'string' },
      'no-color': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });

  if (values.help) return { help: true };
  if (values.version) return { version: true };

  const KNOWN = new Set(['scan', 'config', 'pin', 'trust', 'rules']);
  let command = 'scan';
  const rest = [...positionals];
  if (rest.length && KNOWN.has(rest[0] ?? '')) command = rest.shift()!;

  if (values['no-color']) process.env['NO_COLOR'] = '1';

  const severity = values.severity ?? 'low';
  if (!isSeverity(severity)) throw new Error(`invalid --severity "${severity}"`);
  const failOn = values['fail-on'] ?? 'high';
  if (!isSeverity(failOn)) throw new Error(`invalid --fail-on "${failOn}"`);

  const format = values.format ?? 'pretty';
  if (!['pretty', 'json', 'sarif', 'markdown', 'compact'].includes(format)) {
    throw new Error(`invalid --format "${format}"`);
  }

  // `config` is scan with no filesystem paths and client configs enabled.
  const paths = rest.length ? rest : command === 'config' ? [] : ['.'];
  const lock = values.lock ?? (existsSync('toolpin.lock') ? 'toolpin.lock' : undefined);

  return {
    command,
    paths,
    format,
    output: values.output,
    failOn,
    options: {
      paths,
      includeClientConfigs: Boolean(values['client-configs']) || command === 'config',
      introspect: Boolean(values.introspect),
      introspectTimeoutMs: values['introspect-timeout'] ? Number(values['introspect-timeout']) : 10_000,
      ignore: (values.ignore ?? []).flatMap((v) => v.split(',')),
      exclude: (values.exclude ?? []).flatMap((v) => v.split(',')),
      minSeverity: severity,
      maxFileBytes: values['max-file-size'] ? Number(values['max-file-size']) : 1_000_000,
      baseline: values.baseline,
      lockfile: lock,
      registries: (values.registry ?? []).map((p) => resolve(p)),
      noRegistry: Boolean(values['no-registry']),
    },
  };
}

async function emit(text: string, output?: string): Promise<void> {
  if (output) {
    await writeFile(output, text, 'utf8');
    process.stderr.write(`report written to ${output}\n`);
  } else {
    process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
  }
}

function render(result: ScanResult, format: string): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify(result, null, 2)}\n`;
    case 'sarif':
      return renderSarif(result);
    case 'markdown':
      return renderMarkdown(result);
    case 'compact':
      return renderCompact(result.findings);
    default:
      return renderTerminal(result);
  }
}

async function commandRules(format: string): Promise<void> {
  if (format === 'json') {
    const payload = allRules.map(({ id, title, category, severity, confidence, kinds, remediation }) => ({
      id,
      title,
      category,
      severity,
      confidence,
      appliesTo: kinds,
      remediation,
    }));
    await emit(`${JSON.stringify(payload, null, 2)}\n`);
    return;
  }
  const lines = [`${allRules.length} rules`, ''];
  let category = '';
  for (const rule of [...allRules].sort((a, b) => a.category.localeCompare(b.category) || a.id.localeCompare(b.id))) {
    if (rule.category !== category) {
      category = rule.category;
      lines.push(`${category}`);
    }
    lines.push(`  ${rule.id.padEnd(14)} ${rule.severity.padEnd(8)} ${rule.title}`);
  }
  await emit(`${lines.join('\n')}\n`);
}

async function commandTrust(result: ScanResult, registries: string[], noRegistry: boolean): Promise<void> {
  const registry = noRegistry ? { schemaVersion: 1, entries: [], indicators: [] } : await loadRegistry([bundledRegistryPath(), ...registries]);
  const lines: string[] = [];
  lines.push(`registry: ${registry.entries.length} attestations, ${registry.indicators?.length ?? 0} indicators`);
  lines.push('');
  for (const target of result.targets) {
    const verdict = result.trust.find((t) => t.targetId === target.id);
    const pkg = packageOf(target);
    lines.push(`${target.name}`);
    lines.push(`  status       ${verdict?.status ?? 'unknown'}${verdict?.reason ? ` - ${verdict.reason}` : ''}`);
    if (pkg) lines.push(`  package      ${pkg}`);
    lines.push(`  source       ${target.path}`);
    lines.push(`  tools        ${target.tools?.length ?? 0}`);
    if (target.fingerprint) lines.push(`  fingerprint  ${target.fingerprint}`);
    lines.push('');
  }
  lines.push('Add an attestation by copying a fingerprint into a registry file and passing --registry.');
  await emit(`${lines.join('\n')}\n`);
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  let cli: Cli | { help: true } | { version: true };
  try {
    cli = parse(argv);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n\nRun "toolpin --help" for usage.\n`);
    return 2;
  }
  if ('help' in cli) {
    process.stdout.write(`${HELP}\n`);
    return 0;
  }
  if ('version' in cli) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  if (cli.command === 'rules') {
    await commandRules(cli.format);
    return 0;
  }

  if (cli.options.introspect) {
    process.stderr.write(
      'warning: --introspect launches each configured server, which executes its code.\n' +
        '         Only use it on servers you are prepared to run.\n',
    );
  }

  let result: ScanResult;
  try {
    result = await scan(cli.options, {
      onProgress: (message) => {
        if (cli.format === 'pretty' && !cli.output && process.stderr.isTTY) {
          process.stderr.write(`  ${message}\n`);
        }
      },
    });
  } catch (err) {
    process.stderr.write(`error: scan failed: ${(err as Error).message}\n`);
    return 2;
  }

  if (cli.command === 'pin') {
    const pinnable = result.targets.filter((t) => t.tools?.length);
    if (!pinnable.length) {
      process.stderr.write(
        'error: no tool definitions found to pin.\n' +
          '       Scan a server directory, or use --client-configs --introspect to read live tool lists.\n',
      );
      return 2;
    }
    const path = cli.options.lockfile ?? 'toolpin.lock';
    await writeLock(path, buildLock(pinnable));
    const toolCount = pinnable.reduce((n, t) => n + (t.tools?.length ?? 0), 0);
    process.stdout.write(`pinned ${toolCount} tools across ${pinnable.length} servers to ${path}\n`);
    return 0;
  }

  if (cli.command === 'trust') {
    await commandTrust(result, cli.options.registries ?? [], Boolean(cli.options.noRegistry));
    return 0;
  }

  await emit(render(result, cli.format), cli.output);

  // A written report still deserves a one-line verdict on the terminal.
  if (cli.output && cli.format !== 'pretty') process.stderr.write(`${summaryLine(result)}\n`);

  const worst = result.findings.reduce((max, f) => Math.max(max, SEVERITY_ORDER[f.severity]), -1);
  const malicious = result.trust.some((t) => t.status === 'malicious');
  return worst >= SEVERITY_ORDER[cli.failOn] || malicious ? 1 : 0;
}

const invokedDirectly = process.argv[1] && /toolpin|cli\.(?:js|ts)$/.test(process.argv[1]);
if (invokedDirectly) {
  // Assigning exitCode rather than calling process.exit() lets buffered stdout
  // drain first; process.exit() truncates a large report mid-write when stdout
  // is a pipe.
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`error: ${err?.stack ?? err}\n`);
      process.exitCode = 2;
    },
  );
}
