/**
 * Trust registry.
 *
 * Offline-first by construction: a registry is a plain JSON file, the bundled one
 * ships with the package, and nothing is fetched unless the user asks. A verdict
 * is an attestation about a specific server, keyed by package name or by the
 * hash of its tool surface -- never by "it looked fine when we ran it".
 */
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { Target, TrustVerdict } from '../types.js';

export interface RegistryEntry {
  id: string;
  /** npm/PyPI package, binary name, or remote URL this entry is about. */
  match?: { package?: string; url?: string; command?: string };
  status: 'trusted' | 'caution' | 'malicious';
  reason: string;
  source?: string;
  /** Known-good tool-surface fingerprints. */
  fingerprints?: string[];
}

export interface RegistryIndicator {
  id: string;
  pattern: string;
  status: 'caution' | 'malicious';
  reason: string;
}

export interface Registry {
  schemaVersion: number;
  name?: string;
  updatedAt?: string;
  entries: RegistryEntry[];
  indicators?: RegistryIndicator[];
}

const EMPTY: Registry = { schemaVersion: 1, entries: [], indicators: [] };

export function bundledRegistryPath(): string {
  return join(dirname(fileURLToPath(import.meta.url)), 'data', 'registry.json');
}

export async function loadRegistry(paths: string[]): Promise<Registry> {
  const merged: Registry = { schemaVersion: 1, entries: [], indicators: [] };
  for (const path of paths) {
    try {
      const parsed = JSON.parse(await readFile(path, 'utf8')) as Registry;
      if (!parsed || typeof parsed !== 'object') continue;
      merged.entries.push(...(parsed.entries ?? []));
      merged.indicators?.push(...(parsed.indicators ?? []));
      merged.name ??= parsed.name;
      merged.updatedAt ??= parsed.updatedAt;
    } catch {
      // A missing or malformed registry must never fail a scan.
    }
  }
  return merged.entries.length || merged.indicators?.length ? merged : EMPTY;
}

/** The package a launch command actually resolves to, if we can tell. */
export function packageOf(target: Target): string | undefined {
  const cmd = target.command;
  if (!cmd) return undefined;
  const runner = /^(?:npx|bunx|pnpx|dlx|uvx|uv|yarn|deno)$/i.test((cmd.command ?? '').split(/[/\\]/).pop() ?? '');
  if (runner) {
    const pkg = (cmd.args ?? []).find((a) => !a.startsWith('-') && !['dlx', 'run', 'tool', 'x'].includes(a));
    return pkg?.replace(/@[\d.]+$|==.*$/, '');
  }
  if (cmd.command) return cmd.command.split(/[/\\]/).pop();
  return undefined;
}

export function evaluateTrust(registry: Registry, targets: Target[]): TrustVerdict[] {
  const out: TrustVerdict[] = [];
  for (const target of targets) {
    const pkg = packageOf(target);
    const url = target.command?.url;
    const haystack = [target.command?.command, ...(target.command?.args ?? []), url ?? ''].filter(Boolean).join(' ');

    const entry = registry.entries.find(
      (e) =>
        (e.match?.package && pkg && e.match.package.toLowerCase() === pkg.toLowerCase()) ||
        (e.match?.url && url && url.startsWith(e.match.url)) ||
        (e.match?.command && target.command?.command === e.match.command) ||
        (target.fingerprint && e.fingerprints?.includes(target.fingerprint)),
    );

    if (entry) {
      out.push({
        targetId: target.id,
        status: entry.status,
        reason: entry.reason,
        source: entry.source ?? entry.id,
        fingerprintMatch: Boolean(target.fingerprint && entry.fingerprints?.includes(target.fingerprint)),
      });
      continue;
    }

    const indicator = (registry.indicators ?? []).find((i) => {
      try {
        return new RegExp(i.pattern, 'i').test(haystack);
      } catch {
        return false;
      }
    });
    if (indicator) {
      out.push({ targetId: target.id, status: indicator.status, reason: indicator.reason, source: indicator.id });
      continue;
    }

    out.push({
      targetId: target.id,
      status: 'unknown',
      reason: pkg ? `No attestation on record for "${pkg}"` : 'No attestation on record',
    });
  }
  return out;
}
