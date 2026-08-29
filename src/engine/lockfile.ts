/**
 * Tool-surface pinning.
 *
 * An MCP "rug pull" does not change the package you installed -- it changes what
 * the server says its tools do, after you approved them. The lockfile records the
 * exact tool surface at approval time so the next scan can prove it is unchanged.
 */
import { readFile, writeFile } from 'node:fs/promises';
import type { Finding, Target, ToolDescriptor } from '../types.js';
import { sha256, truncate } from '../util/text.js';
import { toolsetFingerprint } from '../collect/introspect.js';

export interface LockEntry {
  name: string;
  fingerprint: string;
  tools: Record<string, string>;
  pinnedAt: string;
}

export interface Lockfile {
  version: 1;
  servers: Record<string, LockEntry>;
}

const DRIFT_REMEDIATION =
  'Re-read the changed descriptions before using the server again, then re-pin with ' +
  '`toolpin pin`. A silent change to a tool description changes what the agent will do ' +
  'with no code change and no new install.';

export function buildLock(targets: Target[]): Lockfile {
  const servers: Record<string, LockEntry> = {};
  const pinnedAt = new Date().toISOString();
  for (const target of targets) {
    if (!target.tools?.length) continue;
    const tools: Record<string, string> = {};
    for (const tool of target.tools) tools[tool.name] = sha256(tool.description ?? '');
    servers[target.id] = {
      name: target.name,
      fingerprint: target.fingerprint ?? toolsetFingerprint(target.tools),
      tools,
      pinnedAt,
    };
  }
  return { version: 1, servers };
}

export async function readLock(path: string): Promise<Lockfile | undefined> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as Lockfile;
    return parsed?.version === 1 && parsed.servers ? parsed : undefined;
  } catch {
    return undefined;
  }
}

export async function writeLock(path: string, lock: Lockfile): Promise<void> {
  await writeFile(path, `${JSON.stringify(lock, null, 2)}\n`, 'utf8');
}

function finding(
  id: string,
  title: string,
  severity: Finding['severity'],
  message: string,
  file: string,
  target: Target,
  toolName?: string,
): Finding {
  return {
    ruleId: id,
    title,
    category: 'drift',
    severity,
    confidence: 'high',
    message,
    location: { file, line: 1, column: 1 },
    remediation: DRIFT_REMEDIATION,
    serverId: target.id,
    toolName,
    fingerprint: sha256(`${id} ${target.id} ${toolName ?? ''} ${message}`).slice(0, 16),
  };
}

/** Compare the current tool surface against a pinned lockfile. */
export function detectDrift(lock: Lockfile, targets: Target[], lockPath: string): Finding[] {
  const out: Finding[] = [];
  for (const target of targets) {
    // Report against the server itself; the lockfile is only where the pin lives.
    const where = target.path || lockPath;
    const pinned = lock.servers[target.id];
    if (!pinned) continue;
    const current: ToolDescriptor[] = target.tools ?? [];
    const currentFingerprint = target.fingerprint ?? toolsetFingerprint(current);
    if (currentFingerprint === pinned.fingerprint) continue;

    const currentByName = new Map(current.map((t) => [t.name, t]));
    for (const [name, hash] of Object.entries(pinned.tools)) {
      const tool = currentByName.get(name);
      if (!tool) {
        out.push(
          finding('MCP-DRIFT-003', 'Pinned tool has disappeared', 'low', `Tool "${name}" was pinned for "${target.name}" but is no longer exposed`, where, target, name),
        );
        continue;
      }
      const now = sha256(tool.description ?? '');
      if (now === hash) continue;
      out.push(
        finding(
          'MCP-DRIFT-001',
          'Tool description changed since it was pinned',
          'critical',
          `Description of "${name}" changed since ${pinned.pinnedAt.slice(0, 10)}. New text: "${truncate(tool.description ?? '', 120)}"`,
          where,
          target,
          name,
        ),
      );
    }
    for (const tool of current) {
      if (tool.name in pinned.tools) continue;
      out.push(
        finding(
          'MCP-DRIFT-002',
          'New tool appeared after pinning',
          'high',
          `Server "${target.name}" now exposes "${tool.name}", which was not present when it was pinned`,
          where,
          target,
          tool.name,
        ),
      );
    }
  }
  return out;
}
