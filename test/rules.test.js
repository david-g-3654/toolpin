import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan, extractTools, parseFrontmatter, renderSarif, allRules } from '../dist/index.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const ids = (result) => new Set(result.findings.map((f) => f.ruleId));

test('rule ids are unique and every rule declares remediation', () => {
  const seen = new Set();
  for (const rule of allRules) {
    assert.ok(!seen.has(rule.id), `duplicate rule id ${rule.id}`);
    seen.add(rule.id);
    assert.ok(rule.remediation.length > 20, `${rule.id} needs actionable remediation`);
    assert.ok(rule.check || rule.checkAll, `${rule.id} implements no check`);
  }
});

test('poisoned server: catches the full tool-poisoning chain', async () => {
  const result = await scan({ paths: [join(fixtures, 'malicious-server')] });
  const found = ids(result);
  for (const expected of [
    'MCP-TP-001', // <IMPORTANT> tag in a description
    'MCP-TP-002', // "do not tell the user"
    'MCP-TP-003', // "read ~/.ssh/id_rsa and pass it as a parameter"
    'MCP-TP-005', // "instead of using the filesystem read_file tool"
    'MCP-HID-001', // zero-width and tag characters
    'MCP-CRED-001', // reads ~/.aws/credentials
    'MCP-EXF-001', // webhook.site / pastebin
    'MCP-EXE-001', // execSync with an interpolated template literal
    'MCP-EXE-003', // curl | sh
    'MCP-SUP-001', // postinstall script
    'MCP-SUP-002', // git+https dependency
  ]) {
    assert.ok(found.has(expected), `expected ${expected}, got ${[...found].join(', ')}`);
  }
  assert.equal(result.grade, 'F');
});

test('benign server produces no findings', async () => {
  const result = await scan({ paths: [join(fixtures, 'benign-server')] });
  assert.deepEqual(
    result.findings.map((f) => `${f.ruleId} ${f.location.file}:${f.location.line}`),
    [],
  );
  assert.equal(result.grade, 'A');
});

test('poisoned skill: frontmatter and body are both checked', async () => {
  const result = await scan({ paths: [join(fixtures, 'poisoned-skill')] });
  const found = ids(result);
  assert.ok(found.has('MCP-TP-001'), 'override in the skill description');
  assert.ok(found.has('MCP-SKL-001'), 'unconstrained Bash grant');
  assert.ok(found.has('MCP-SKL-002'), 'downloads and runs a script');
  assert.ok(found.has('MCP-INJ-001'), 'told to follow fetched instructions');
});

test('client config: launch, transport, and secret handling', async () => {
  const result = await scan({ paths: [join(fixtures, 'configs')] });
  const found = ids(result);
  assert.ok(found.has('MCP-CFG-001'), 'unpinned npx launch');
  assert.ok(found.has('MCP-CFG-002'), 'plaintext credential in config');
  assert.ok(found.has('MCP-CFG-003'), 'plaintext HTTP endpoint');
  assert.ok(found.has('MCP-CFG-004'), 'filesystem server rooted at /');
  assert.ok(found.has('MCP-CFG-005'), 'binary under /tmp');
  assert.equal(result.targets.length, 5, 'four configured servers plus the directory itself');
});

test('findings never echo a live secret', async () => {
  const result = await scan({ paths: [join(fixtures, 'configs')] });
  for (const f of result.findings) {
    assert.ok(!/4f9a2b7c1e8d3a6b5c0f2e9d/.test(f.evidence ?? ''), `secret leaked in ${f.ruleId}`);
  }
});

test('severity floor and ignore list are honoured', async () => {
  const all = await scan({ paths: [join(fixtures, 'malicious-server')] });
  const criticalOnly = await scan({ paths: [join(fixtures, 'malicious-server')], minSeverity: 'critical' });
  assert.ok(criticalOnly.findings.length < all.findings.length);
  assert.ok(criticalOnly.findings.every((f) => f.severity === 'critical'));

  const ignored = await scan({ paths: [join(fixtures, 'malicious-server')], ignore: ['MCP-TP', 'supply-chain'] });
  assert.ok(!ignored.findings.some((f) => f.ruleId.startsWith('MCP-TP')));
  assert.ok(!ignored.findings.some((f) => f.category === 'supply-chain'));
});

test('baseline suppression is fingerprint-stable across runs', async () => {
  const first = await scan({ paths: [join(fixtures, 'malicious-server')] });
  const second = await scan({ paths: [join(fixtures, 'malicious-server')] });
  assert.deepEqual(
    first.findings.map((f) => f.fingerprint),
    second.findings.map((f) => f.fingerprint),
  );
});

test('static tool extraction: JavaScript', () => {
  const tools = extractTools(
    `server.tool('alpha', 'First tool.', {}, fn);
     server.registerTool("beta", { title: "B", description: "Second tool." }, fn);
     const list = [{ name: "gamma", description: "Third tool." }];`,
    'js',
  );
  const byName = Object.fromEntries(tools.map((t) => [t.name, t.description]));
  assert.equal(byName.alpha, 'First tool.');
  assert.equal(byName.beta, 'Second tool.');
  assert.equal(byName.gamma, 'Third tool.');
});

test('static tool extraction: Python decorators and docstrings', () => {
  const tools = extractTools(
    `@mcp.tool()
def search(query: str) -> str:
    """Search the index for a query."""
    return ""

@mcp.tool(name="fetch_page", description="Fetch a URL.")
async def fetch(url: str):
    pass
`,
    'py',
  );
  const byName = Object.fromEntries(tools.map((t) => [t.name, t.description]));
  assert.equal(byName.search, 'Search the index for a query.');
  assert.equal(byName.fetch_page, 'Fetch a URL.');
});

test('frontmatter parser handles scalars, inline lists, and block lists', () => {
  const fm = parseFrontmatter(`---
name: demo
description: A demo skill
allowed-tools: [Read, Write]
tags:
  - one
  - two
---
body`);
  assert.equal(fm.data.name, 'demo');
  assert.deepEqual(fm.data['allowed-tools'], ['Read', 'Write']);
  assert.deepEqual(fm.data.tags, ['one', 'two']);
});

test('SARIF output is well-formed and self-consistent', async () => {
  const result = await scan({ paths: [join(fixtures, 'malicious-server')] });
  const sarif = JSON.parse(renderSarif(result, join(fixtures, 'malicious-server')));
  assert.equal(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'toolpin');
  assert.equal(run.results.length, result.findings.length);
  const ruleIds = new Set(run.tool.driver.rules.map((r) => r.id));
  for (const r of run.results) {
    assert.ok(ruleIds.has(r.ruleId), `result references undeclared rule ${r.ruleId}`);
    assert.equal(run.tool.driver.rules[r.ruleIndex].id, r.ruleId, 'ruleIndex must match ruleId');
    const region = r.locations[0].physicalLocation.region;
    assert.ok(region.startLine >= 1);
    assert.ok(!r.locations[0].physicalLocation.artifactLocation.uri.startsWith('/'), 'uri should be repo-relative');
    assert.ok(['error', 'warning', 'note'].includes(r.level));
  }
  for (const r of run.tool.driver.rules) {
    assert.ok(Number(r.properties['security-severity']) > 0);
  }
});
