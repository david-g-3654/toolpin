/**
 * Tests the composite action's shell script by extracting it from action.yml and
 * running it against the fixtures with a simulated runner environment.
 *
 * Action YAML is otherwise only exercised in CI, where a typo costs a push.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Pull the `run: |` body out of the action's first step. */
async function extractRunScript() {
  const yml = await readFile(join(root, 'action.yml'), 'utf8');
  const start = yml.indexOf('      run: |');
  assert.ok(start !== -1, 'action.yml should contain a run block');
  const lines = yml.slice(start).split('\n').slice(1);
  const body = [];
  for (const line of lines) {
    if (line.trim() === '') {
      body.push('');
      continue;
    }
    if (!line.startsWith('        ')) break; // dedent ends the block
    body.push(line.slice(8));
  }
  return body.join('\n');
}

async function runAction(env, cwd) {
  const dir = await mkdtemp(join(tmpdir(), 'toolpin-action-'));
  const script = join(dir, 'step.sh');
  await writeFile(script, await extractRunScript());
  const outputs = join(dir, 'outputs.txt');
  const summary = join(dir, 'summary.md');
  await writeFile(outputs, '');
  await writeFile(summary, '');
  const base = {
    ...process.env,
    GITHUB_ACTION_PATH: root,
    GITHUB_OUTPUT: outputs,
    GITHUB_STEP_SUMMARY: summary,
    TOOLPIN_PATH: '.',
    TOOLPIN_FAIL_ON: 'high',
    TOOLPIN_SEVERITY: 'low',
    TOOLPIN_IGNORE: '',
    TOOLPIN_EXCLUDE: '',
    TOOLPIN_CLIENT_CONFIGS: 'false',
    TOOLPIN_SARIF: join(dir, 'toolpin.sarif'),
    TOOLPIN_SUMMARY: 'true',
    TOOLPIN_VERSION: 'latest',
    ...env,
  };
  let code = 0;
  let stdout = '';
  try {
    ({ stdout } = await run('bash', [script], { cwd: cwd ?? dir, env: base }));
  } catch (err) {
    code = err.code ?? 1;
    stdout = err.stdout ?? '';
  }
  const parsed = Object.fromEntries(
    (await readFile(outputs, 'utf8'))
      .split('\n')
      .filter(Boolean)
      .map((l) => l.split('=')),
  );
  return { code, stdout, outputs: parsed, summary: await readFile(summary, 'utf8'), sarif: base.TOOLPIN_SARIF, dir };
}

test('action: clean target passes and reports grade A', async () => {
  const r = await runAction({ TOOLPIN_PATH: join(root, 'fixtures', 'benign-server') });
  assert.equal(r.code, 0);
  assert.equal(r.outputs.grade, 'A');
  assert.equal(r.outputs.findings, '0');
  assert.equal(r.outputs.critical, '0');
  assert.ok(existsSync(r.sarif), 'SARIF is written even when clean, so the Security tab clears resolved alerts');
  await rm(r.dir, { recursive: true, force: true });
});

test('action: poisoned target fails the gate and still emits an uploadable SARIF', async () => {
  const r = await runAction({ TOOLPIN_PATH: join(root, 'fixtures', 'malicious-server') });
  assert.equal(r.code, 1, 'the job should fail');
  assert.equal(r.outputs.grade, 'F');
  assert.ok(Number(r.outputs.critical) > 0);

  const sarif = JSON.parse(await readFile(r.sarif, 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.length > 0, 'a failing scan must still upload its findings');
  await rm(r.dir, { recursive: true, force: true });
});

test('action: emits workflow annotations for the PR diff', async () => {
  const r = await runAction({ TOOLPIN_PATH: join(root, 'fixtures', 'malicious-server') });
  const annotations = r.stdout.split('\n').filter((l) => l.startsWith('::error file=') || l.startsWith('::warning file='));
  assert.ok(annotations.length > 0, 'findings should annotate the diff even without SARIF upload');
  assert.ok(annotations.every((a) => /file=[^,]+,line=\d+/.test(a)), 'each annotation needs a file and line');
  assert.ok(annotations.some((a) => a.includes('MCP-')), 'the rule id belongs in the annotation');
  await rm(r.dir, { recursive: true, force: true });
});

test('action: fail-on gates without hiding findings', async () => {
  const lenient = await runAction({ TOOLPIN_PATH: join(root, 'fixtures', 'configs'), TOOLPIN_FAIL_ON: 'never' });
  assert.equal(lenient.code, 0, 'fail-on: never reports without failing');
  assert.ok(Number(lenient.outputs.findings) > 0, 'findings are still reported');

  const strict = await runAction({ TOOLPIN_PATH: join(root, 'fixtures', 'configs'), TOOLPIN_FAIL_ON: 'critical' });
  assert.equal(strict.code, 1);
  await rm(lenient.dir, { recursive: true, force: true });
  await rm(strict.dir, { recursive: true, force: true });
});

test('action: writes a job summary table', async () => {
  const r = await runAction({ TOOLPIN_PATH: join(root, 'fixtures', 'poisoned-skill') });
  assert.match(r.summary, /## toolpin: grade/);
  assert.match(r.summary, /\| Critical \| High \| Medium \| Low \| Info \|/);
  assert.match(r.summary, /MCP-/);
  await rm(r.dir, { recursive: true, force: true });
});

test('action: ignore and exclude inputs are passed through', async () => {
  const all = await runAction({ TOOLPIN_PATH: join(root, 'fixtures', 'malicious-server'), TOOLPIN_FAIL_ON: 'never' });
  const filtered = await runAction({
    TOOLPIN_PATH: join(root, 'fixtures', 'malicious-server'),
    TOOLPIN_FAIL_ON: 'never',
    TOOLPIN_IGNORE: 'MCP-TP,supply-chain',
  });
  assert.ok(Number(filtered.outputs.findings) < Number(all.outputs.findings));

  const excluded = await runAction({
    TOOLPIN_PATH: join(root, 'fixtures'),
    TOOLPIN_FAIL_ON: 'never',
    TOOLPIN_EXCLUDE: 'malicious-server/,poisoned-skill/,configs/',
  });
  assert.equal(excluded.outputs.findings, '0');
  await rm(all.dir, { recursive: true, force: true });
  await rm(filtered.dir, { recursive: true, force: true });
  await rm(excluded.dir, { recursive: true, force: true });
});

test('action: an invalid fail-on value is a configuration error, not a pass', async () => {
  const r = await runAction({ TOOLPIN_PATH: join(root, 'fixtures', 'benign-server'), TOOLPIN_FAIL_ON: 'severe' });
  assert.equal(r.code, 2);
  assert.match(r.stdout, /invalid fail-on/);
  await rm(r.dir, { recursive: true, force: true });
});

test('action.yml declares every input its script reads', async () => {
  const yml = await readFile(join(root, 'action.yml'), 'utf8');
  const script = await extractRunScript();
  const used = new Set([...script.matchAll(/\$\{?(TOOLPIN_[A-Z_]+)\}?/g)].map((m) => m[1]));
  const declared = new Set([...yml.matchAll(/^\s{8}(TOOLPIN_[A-Z_]+):/gm)].map((m) => m[1]));
  for (const name of used) {
    assert.ok(declared.has(name), `${name} is used by the script but never set in the env: block`);
  }
});
