import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import type { Artifact, Finding, ScanOptions, ScanResult, Target, ToolDescriptor } from '../types.js';
import { allRules, isIgnored } from '../rules/index.js';
import { hasLockfile, isSourceCheckout, walk, type WalkedFile } from '../collect/walk.js';
import { extractTools, toolArtifacts } from '../collect/tools.js';
import { isSkillFile, skillArtifacts } from '../collect/skills.js';
import {
  candidateConfigPaths,
  configArtifacts,
  parseConfig,
  projectConfigPaths,
  stripJsonComments,
} from '../collect/clientConfig.js';
import { introspectArtifacts, introspectStdio, toolsetFingerprint } from '../collect/introspect.js';
import { detectDrift, readLock } from './lockfile.js';
import { atLeast, countBySeverity, grade, sortFindings } from './score.js';
import { evaluateTrust, loadRegistry, bundledRegistryPath } from '../registry/trust.js';
import { buildMatcher, readIgnoreFile } from '../util/ignore.js';

export const VERSION = '0.1.0';

export const DEFAULT_OPTIONS: ScanOptions = {
  paths: ['.'],
  includeClientConfigs: false,
  introspect: false,
  introspectTimeoutMs: 10_000,
  ignore: [],
  exclude: [],
  minSeverity: 'low',
  maxFileBytes: 1_000_000,
  registries: [],
  noRegistry: false,
};

export interface ScanHooks {
  onProgress?(message: string): void;
}

export async function scan(input: Partial<ScanOptions>, hooks: ScanHooks = {}): Promise<ScanResult> {
  const options: ScanOptions = { ...DEFAULT_OPTIONS, ...input };
  const started = Date.now();
  const artifacts: Artifact[] = [];
  const targets: Target[] = [];
  const errors: string[] = [];
  const fileCache = new Map<string, string>();
  let filesScanned = 0;

  // ---- 1. directories and files -------------------------------------------
  for (const rawPath of options.paths) {
    const root = resolve(rawPath);
    if (!existsSync(root)) {
      errors.push(`path not found: ${rawPath}`);
      continue;
    }
    hooks.onProgress?.(`scanning ${root}`);
    const exclude = buildMatcher([...(await readIgnoreFile(root)), ...options.exclude]);
    let files: WalkedFile[];
    try {
      files = await walk(root, {
        maxFileBytes: options.maxFileBytes,
        maxFiles: 5000,
        includeDependencies: false,
        exclude,
      });
    } catch (err) {
      errors.push(`failed to read ${rawPath}: ${(err as Error).message}`);
      continue;
    }
    filesScanned += files.length;

    const serverId = basename(root) || root;
    const directoryTools: ToolDescriptor[] = [];

    for (const file of files) {
      fileCache.set(file.path, file.text);
      artifacts.push(...artifactsForFile(file, serverId, directoryTools, errors));
    }

    targets.push({
      id: serverId,
      name: serverId,
      kind: 'directory',
      path: root,
      tools: directoryTools,
      fingerprint: directoryTools.length ? toolsetFingerprint(directoryTools) : undefined,
    });

    // Project-local MCP configs describe what this repo asks an agent to run.
    for (const candidate of projectConfigPaths(root)) {
      const config = await parseConfig(candidate.path, candidate.client);
      if (!config) continue;
      fileCache.set(config.path, config.raw);
      const { artifacts: configArts, targets: configTargets } = configArtifacts(config);
      artifacts.push(...configArts);
      targets.push(...configTargets);
    }
  }

  // ---- 2. installed client configurations ---------------------------------
  if (options.includeClientConfigs) {
    for (const candidate of candidateConfigPaths()) {
      if (!existsSync(candidate.path)) continue;
      const config = await parseConfig(candidate.path, candidate.client);
      if (!config) continue;
      hooks.onProgress?.(`reading ${candidate.client} config (${config.servers.length} servers)`);
      fileCache.set(config.path, config.raw);
      const { artifacts: configArts, targets: configTargets } = configArtifacts(config);
      artifacts.push(...configArts);
      targets.push(...configTargets);
      filesScanned++;
    }
  }

  // ---- 3. optional live handshake -----------------------------------------
  if (options.introspect) {
    for (const target of targets) {
      if (target.kind !== 'client-config' || !target.command?.command) continue;
      hooks.onProgress?.(`introspecting ${target.name}`);
      const result = await introspectStdio(target, options.introspectTimeoutMs);
      if (result.error) {
        errors.push(`introspect ${target.name}: ${result.error}`);
        continue;
      }
      target.tools = result.tools;
      target.fingerprint = toolsetFingerprint(result.tools);
      artifacts.push(...introspectArtifacts(target, result));
    }
  }

  // ---- 4. rules ------------------------------------------------------------
  const ctx = {
    artifacts,
    targets,
    options,
    fileText: (path: string) => fileCache.get(path),
  };

  const findings: Finding[] = [];
  const active = allRules.filter((rule) => !isIgnored(rule, options.ignore));
  for (const rule of active) {
    try {
      if (rule.check && rule.kinds.length) {
        for (const artifact of artifacts) {
          if (!rule.kinds.includes(artifact.kind)) continue;
          findings.push(...rule.check(artifact, ctx));
        }
      }
      if (rule.checkAll) findings.push(...rule.checkAll(ctx));
    } catch (err) {
      errors.push(`rule ${rule.id} failed: ${(err as Error).message}`);
    }
  }

  // ---- 5. drift against a pinned tool surface ------------------------------
  if (options.lockfile && existsSync(options.lockfile)) {
    const lock = await readLock(options.lockfile);
    if (lock) findings.push(...detectDrift(lock, targets, options.lockfile));
    else errors.push(`lockfile ${options.lockfile} is not readable or has an unsupported version`);
  }

  // ---- 6. trust registry ---------------------------------------------------
  let trust: ScanResult['trust'] = [];
  if (!options.noRegistry) {
    const registry = await loadRegistry([bundledRegistryPath(), ...options.registries]);
    trust = evaluateTrust(registry, targets);
  }

  // ---- 7. filter and score -------------------------------------------------
  let visible = dedupe(findings).filter((f) => atLeast(f.severity, options.minSeverity));
  if (options.baseline && existsSync(options.baseline)) {
    const suppressed = await readBaseline(options.baseline);
    visible = visible.filter((f) => !suppressed.has(f.fingerprint));
  }
  visible = sortFindings(visible);

  return {
    version: VERSION,
    scannedAt: new Date().toISOString(),
    targets,
    findings: visible,
    stats: {
      filesScanned,
      artifactsAnalyzed: artifacts.length,
      durationMs: Date.now() - started,
      bySeverity: countBySeverity(visible),
    },
    grade: grade(visible),
    trust,
    errors,
  };
}

function artifactsForFile(
  file: WalkedFile,
  serverId: string,
  toolSink: ToolDescriptor[],
  errors: string[],
): Artifact[] {
  const out: Artifact[] = [];
  const name = basename(file.path);

  if (name === 'package.json') {
    try {
      const pkg = JSON.parse(file.text) as Record<string, unknown>;
      out.push({
        kind: 'manifest',
        file: file.path,
        text: file.text,
        lineOffset: 1,
        language: 'json',
        serverId,
        data: {
          ...pkg,
          __hasLockfile: hasLockfile(dirname(file.path)),
          __isSourceCheckout: isSourceCheckout(dirname(file.path)),
        },
      });
    } catch (err) {
      errors.push(`invalid JSON in ${file.path}: ${(err as Error).message}`);
    }
    return out;
  }

  if (file.language === 'md') {
    if (isSkillFile(file)) return skillArtifacts(file, serverId);
    out.push({ kind: 'doc', file: file.path, text: file.text, lineOffset: 1, language: 'md', serverId });
    return out;
  }

  if (file.language === 'json' || file.language === 'yaml') {
    // Only JSON configs that actually declare servers are interesting here;
    // project configs are picked up separately with full parsing.
    if (/"(?:mcpServers|context_servers)"/.test(file.text)) {
      try {
        JSON.parse(stripJsonComments(file.text));
      } catch {
        errors.push(`invalid JSON in ${file.path}`);
      }
    }
    return out;
  }

  // Source file: the whole text, plus any tool definitions we can extract.
  out.push({
    kind: 'source',
    file: file.path,
    text: file.text,
    lineOffset: 1,
    language: file.language,
    serverId,
  });

  const tools = extractTools(file.text, file.language);
  if (tools.length) {
    out.push(...toolArtifacts(file.path, file.text, tools, serverId, file.language));
    for (const tool of tools) {
      if (!toolSink.some((t) => t.name === tool.name)) {
        toolSink.push({ name: tool.name, description: tool.description, origin: 'static' });
      }
    }
  }
  return out;
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.fingerprint}:${f.location.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

async function readBaseline(path: string): Promise<Set<string>> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as { fingerprints?: string[] };
    return new Set(parsed.fingerprints ?? []);
  } catch {
    return new Set();
  }
}
