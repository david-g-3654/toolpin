/**
 * Agent skill parsing (SKILL.md and friends).
 *
 * A skill is prose the agent follows, optionally with a permission grant in its
 * frontmatter -- so it is model-facing text and a capability declaration at once,
 * and both halves need checking.
 */
import { basename, dirname } from 'node:path';
import type { Artifact } from '../types.js';
import type { WalkedFile } from './walk.js';

export interface Frontmatter {
  data: Record<string, unknown>;
  /** Line count of the frontmatter block including delimiters. */
  lines: number;
  raw: string;
}

/**
 * Parse the flat subset of YAML that skill frontmatter actually uses:
 * scalars, inline lists, and block lists. Anything more exotic is left as text.
 */
export function parseFrontmatter(text: string): Frontmatter | undefined {
  if (!text.startsWith('---')) return undefined;
  const end = text.indexOf('\n---', 3);
  if (end === -1) return undefined;
  const raw = text.slice(text.indexOf('\n') + 1, end);
  const data: Record<string, unknown> = {};
  let currentKey: string | undefined;
  for (const line of raw.split('\n')) {
    const listItem = /^\s*-\s+(.*)$/.exec(line);
    if (listItem && currentKey) {
      const existing = data[currentKey];
      const value = unquote(listItem[1] ?? '');
      if (Array.isArray(existing)) existing.push(value);
      else data[currentKey] = [value];
      continue;
    }
    const kv = /^([A-Za-z_][\w.-]*)\s*:\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1] ?? '';
    const value = (kv[2] ?? '').trim();
    currentKey = key;
    if (value === '') {
      data[key] = [];
    } else if (value.startsWith('[') && value.endsWith(']')) {
      data[key] = value
        .slice(1, -1)
        .split(',')
        .map((s) => unquote(s.trim()))
        .filter(Boolean);
    } else {
      data[key] = unquote(value);
    }
  }
  const lines = text.slice(0, end + 4).split('\n').length;
  return { data, lines, raw };
}

function unquote(s: string): string {
  const t = s.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) return t.slice(1, -1);
  return t;
}

/** True when a markdown file should be treated as agent instructions rather than docs. */
export function isSkillFile(file: WalkedFile): boolean {
  const name = basename(file.path).toLowerCase();
  if (name === 'skill.md' || name === 'agents.md' || name === 'claude.md') return true;
  const dir = dirname(file.path).toLowerCase();
  if (/[/\\](?:skills|commands|agents|prompts)([/\\]|$)/.test(dir)) return true;
  // A markdown file with skill-shaped frontmatter is a skill wherever it lives.
  const fm = parseFrontmatter(file.text);
  return Boolean(fm && ('description' in fm.data || 'allowed-tools' in fm.data) && 'name' in fm.data);
}

export function skillArtifacts(file: WalkedFile, serverId: string): Artifact[] {
  const fm = parseFrontmatter(file.text);
  const artifacts: Artifact[] = [];
  const skillName = fm?.data['name'] ? String(fm.data['name']) : basename(dirname(file.path));

  if (fm) {
    artifacts.push({
      kind: 'skill-frontmatter',
      file: file.path,
      text: fm.raw,
      lineOffset: 2,
      language: 'yaml',
      serverId,
      toolName: skillName,
      data: fm.data,
    });
    const description = fm.data['description'];
    if (typeof description === 'string' && description) {
      artifacts.push({
        kind: 'tool-description',
        file: file.path,
        text: description,
        lineOffset: 2,
        language: 'md',
        serverId,
        toolName: skillName,
      });
    }
  }

  artifacts.push({
    kind: 'skill',
    file: file.path,
    text: fm ? file.text.slice(file.text.indexOf('\n---', 3) + 4) : file.text,
    lineOffset: fm ? fm.lines : 1,
    language: 'md',
    serverId,
    toolName: skillName,
  });
  return artifacts;
}
