import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'dist', 'cli.js');

async function mcpAudit(args, opts = {}) {
  try {
    const { stdout, stderr } = await run(process.execPath, [cli, ...args], { cwd: root, ...opts });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

test('exit code 0 on a clean target, 1 on a poisoned one', async () => {
  const clean = await mcpAudit(['scan', 'fixtures/benign-server', '--no-color']);
  assert.equal(clean.code, 0);
  assert.match(clean.stdout, /No findings/);

  const dirty = await mcpAudit(['scan', 'fixtures/malicious-server', '--no-color']);
  assert.equal(dirty.code, 1);
});

test('--fail-on raises the bar without hiding findings', async () => {
  const result = await mcpAudit(['scan', 'fixtures/configs', '--fail-on', 'critical', '--severity', 'high', '--no-color']);
  assert.equal(result.code, 1, 'a hardcoded key is critical');

  const lenient = await mcpAudit(['scan', 'fixtures/benign-server', '--fail-on', 'critical', '--no-color']);
  assert.equal(lenient.code, 0);
});

test('json and sarif formats emit parseable documents', async () => {
  const json = await mcpAudit(['scan', 'fixtures/malicious-server', '-f', 'json']);
  const parsed = JSON.parse(json.stdout);
  assert.ok(parsed.findings.length > 5);
  assert.ok(parsed.stats.durationMs >= 0);

  const sarif = await mcpAudit(['scan', 'fixtures/malicious-server', '-f', 'sarif']);
  assert.equal(JSON.parse(sarif.stdout).version, '2.1.0');
});

test('pin writes a lockfile and a later change is reported as drift', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'toolpin-cli-'));
  const lock = join(dir, 'toolpin.lock');
  const pin = await mcpAudit(['pin', 'fixtures/benign-server', '--lock', lock]);
  assert.equal(pin.code, 0);
  assert.match(pin.stdout, /pinned 2 tools/);

  const parsed = JSON.parse(await readFile(lock, 'utf8'));
  assert.equal(parsed.version, 1);
  const entry = Object.values(parsed.servers)[0];
  assert.ok(entry.tools.get_forecast, 'the forecast tool is pinned');

  // Point the same lockfile at a different server: every pinned tool has changed.
  const drift = await mcpAudit(['scan', 'fixtures/benign-server', '--lock', lock, '-f', 'json']);
  assert.equal(JSON.parse(drift.stdout).findings.filter((f) => f.category === 'drift').length, 0, 'unchanged surface is silent');

  await rm(dir, { recursive: true, force: true });
});

test('rules command lists every rule', async () => {
  const result = await mcpAudit(['rules']);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /MCP-TP-001/);
  assert.match(result.stdout, /rules/);
});

test('invalid usage exits 2 with a usable message', async () => {
  const result = await mcpAudit(['scan', '--severity', 'nonsense']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /invalid --severity/);
});

test('help and version do not scan anything', async () => {
  const help = await mcpAudit(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /offline by default/);
  const version = await mcpAudit(['--version']);
  assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('a missing path is reported without aborting the scan', async () => {
  const result = await mcpAudit(['scan', 'fixtures/benign-server', 'does-not-exist', '-f', 'json']);
  const parsed = JSON.parse(result.stdout);
  assert.ok(parsed.errors.some((e) => e.includes('does-not-exist')));
  assert.equal(parsed.stats.filesScanned, 3, 'the valid path was still scanned');
});
