/**
 * Discovery and parsing of MCP client configuration files.
 *
 * These files are the actual attack surface of a user's machine: whatever is
 * listed here is what the agent will launch and trust. Scanning a repo tells you
 * about one server; scanning the configs tells you what you are already running.
 */
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import type { Artifact, Target } from '../types.js';
import type { ServerConfigEntry } from '../rules/structural.js';
import { lineOf } from '../util/text.js';

export interface DiscoveredConfig {
  path: string;
  client: string;
  raw: string;
  servers: ServerConfigEntry[];
}

/** Well-known config locations, per client. Missing paths are skipped silently. */
export function candidateConfigPaths(): Array<{ path: string; client: string }> {
  const home = homedir();
  const os = platform();
  const appData = process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming');
  const list: Array<{ path: string; client: string }> = [
    { path: join(home, '.claude.json'), client: 'Claude Code' },
    { path: join(home, '.claude', 'settings.json'), client: 'Claude Code' },
    { path: join(home, '.cursor', 'mcp.json'), client: 'Cursor' },
    { path: join(home, '.codeium', 'windsurf', 'mcp_config.json'), client: 'Windsurf' },
    { path: join(home, '.config', 'zed', 'settings.json'), client: 'Zed' },
    { path: join(home, '.gemini', 'settings.json'), client: 'Gemini CLI' },
    { path: join(home, '.vscode', 'mcp.json'), client: 'VS Code' },
  ];
  if (os === 'darwin') {
    list.push(
      { path: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), client: 'Claude Desktop' },
      { path: join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'), client: 'VS Code' },
    );
  } else if (os === 'win32') {
    list.push(
      { path: join(appData, 'Claude', 'claude_desktop_config.json'), client: 'Claude Desktop' },
      { path: join(appData, 'Code', 'User', 'mcp.json'), client: 'VS Code' },
    );
  } else {
    list.push(
      { path: join(home, '.config', 'Claude', 'claude_desktop_config.json'), client: 'Claude Desktop' },
      { path: join(home, '.config', 'Code', 'User', 'mcp.json'), client: 'VS Code' },
    );
  }
  return list;
}

/** Project-local config files found under a scanned directory. */
export function projectConfigPaths(root: string): Array<{ path: string; client: string }> {
  return [
    { path: join(root, '.mcp.json'), client: 'project (.mcp.json)' },
    { path: join(root, '.cursor', 'mcp.json'), client: 'project (Cursor)' },
    { path: join(root, '.vscode', 'mcp.json'), client: 'project (VS Code)' },
    { path: join(root, '.claude', 'settings.json'), client: 'project (Claude Code)' },
    { path: join(root, 'claude_desktop_config.json'), client: 'project (Claude Desktop)' },
  ].filter((c) => existsSync(c.path));
}

function collectServerMaps(node: unknown, out: Array<Record<string, unknown>>, depth = 0): void {
  if (depth > 4 || node === null || typeof node !== 'object') return;
  const obj = node as Record<string, unknown>;
  for (const key of ['mcpServers', 'servers', 'context_servers', 'mcp_servers']) {
    const value = obj[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) out.push(value as Record<string, unknown>);
  }
  for (const value of Object.values(obj)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) collectServerMaps(value, out, depth + 1);
  }
}

export async function parseConfig(path: string, client: string): Promise<DiscoveredConfig | undefined> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripJsonComments(raw));
  } catch {
    return undefined;
  }
  const maps: Array<Record<string, unknown>> = [];
  collectServerMaps(parsed, maps);
  if (!maps.length) return undefined;

  const servers: ServerConfigEntry[] = [];
  const seen = new Set<string>();
  for (const map of maps) {
    for (const [key, value] of Object.entries(map)) {
      if (!value || typeof value !== 'object' || seen.has(key)) continue;
      seen.add(key);
      const v = value as Record<string, unknown>;
      servers.push({
        key,
        command: typeof v['command'] === 'string' ? v['command'] : undefined,
        args: Array.isArray(v['args']) ? (v['args'] as unknown[]).filter((a): a is string => typeof a === 'string') : undefined,
        env: v['env'] && typeof v['env'] === 'object' ? (v['env'] as Record<string, string>) : undefined,
        url: typeof v['url'] === 'string' ? v['url'] : typeof v['serverUrl'] === 'string' ? (v['serverUrl'] as string) : undefined,
        type: typeof v['type'] === 'string' ? v['type'] : undefined,
      });
    }
  }
  if (!servers.length) return undefined;
  return { path, client, raw, servers };
}

/** JSONC tolerance: several clients ship configs with comments. */
export function stripJsonComments(input: string): string {
  let out = '';
  let inString = false;
  let inLine = false;
  let inBlock = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    const next = input[i + 1];
    if (inLine) {
      if (ch === '\n') {
        inLine = false;
        out += ch;
      } else out += ' ';
      continue;
    }
    if (inBlock) {
      if (ch === '*' && next === '/') {
        inBlock = false;
        out += '  ';
        i++;
      } else out += ch === '\n' ? ch : ' ';
      continue;
    }
    if (inString) {
      out += ch;
      if (ch === '\\') {
        out += next ?? '';
        i++;
      } else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === '/' && next === '/') {
      inLine = true;
      out += '  ';
      i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlock = true;
      out += '  ';
      i++;
      continue;
    }
    out += ch;
  }
  return out.replace(/,(\s*[}\]])/g, ' $1');
}

export function configArtifacts(config: DiscoveredConfig): { artifacts: Artifact[]; targets: Target[] } {
  const artifacts: Artifact[] = [];
  const targets: Target[] = [];
  for (const entry of config.servers) {
    const serverId = `${config.client}:${entry.key}`;
    artifacts.push({
      kind: 'config',
      file: config.path,
      text: JSON.stringify(entry, null, 2),
      lineOffset: lineOf(config.raw, `"${entry.key}"`),
      language: 'json',
      serverId,
      data: entry,
    });
    targets.push({
      id: serverId,
      name: entry.key,
      kind: 'client-config',
      path: config.path,
      command: {
        command: entry.command ?? '',
        args: entry.args ?? [],
        env: entry.env,
        url: entry.url,
        type: entry.type,
      },
    });
  }
  return { artifacts, targets };
}
