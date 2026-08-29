/**
 * Path exclusion.
 *
 * Any security scanner needs this: a repository legitimately contains attack
 * samples (test fixtures), documentation of attacks, and -- in this project's
 * case -- the rule definitions themselves, which necessarily contain every
 * pattern they detect. Without exclusion those files make the tool unusable on
 * exactly the codebases that care most about it.
 */
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

export interface Matcher {
  patterns: string[];
  matches(absolutePath: string, root: string): boolean;
}

/**
 * Convert a gitignore-style pattern into a regex.
 * Supports `*` (within a segment), `**` (across segments), a leading `/`
 * (anchored to the root), and a trailing `/` (directory only).
 */
function toRegExp(pattern: string): RegExp {
  let p = pattern.trim();
  const anchored = p.startsWith('/');
  if (anchored) p = p.slice(1);
  const directoryOnly = p.endsWith('/');
  if (directoryOnly) p = p.slice(0, -1);

  let re = '';
  for (let i = 0; i < p.length; i++) {
    const ch = p[i]!;
    if (ch === '*') {
      if (p[i + 1] === '*') {
        // `**/` consumes any number of leading segments, including none.
        if (p[i + 2] === '/') {
          re += '(?:[^/]+/)*';
          i += 2;
        } else {
          re += '.*';
          i++;
        }
      } else {
        re += '[^/]*';
      }
      continue;
    }
    if (ch === '?') {
      re += '[^/]';
      continue;
    }
    re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }

  const body = anchored ? `^${re}` : `(?:^|/)${re}`;
  return new RegExp(`${body}(?:/|$)`);
}

export function buildMatcher(patterns: string[]): Matcher {
  const cleaned = patterns.map((p) => p.trim()).filter((p) => p && !p.startsWith('#'));
  const compiled = cleaned.map(toRegExp);
  return {
    patterns: cleaned,
    matches(absolutePath: string, root: string): boolean {
      const rel = relative(root, absolutePath).split(sep).join('/');
      if (!rel || rel.startsWith('..')) return false;
      return compiled.some((re) => re.test(rel));
    },
  };
}

/** Read `.toolpinignore` from a scan root, if present. */
export async function readIgnoreFile(root: string): Promise<string[]> {
  const path = join(root, '.toolpinignore');
  if (!existsSync(path)) return [];
  try {
    return (await readFile(path, 'utf8')).split('\n');
  } catch {
    return [];
  }
}
