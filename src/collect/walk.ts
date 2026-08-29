import { readdir, readFile, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { extname, join, basename, relative } from 'node:path';
import type { Language } from '../types.js';
import type { Matcher } from '../util/ignore.js';

const DEFAULT_SKIP = new Set([
  '.git', '.hg', '.svn', 'coverage', '.next', '.nuxt',
  '.venv', 'venv', '__pycache__', '.mypy_cache', '.pytest_cache', '.ruff_cache',
  'target', 'vendor', '.cache', '.turbo', '.gradle', 'Pods',
]);

/**
 * Compiled output. Skipping these is only correct when the source they were
 * built from is sitting right next to them -- in a published package or an
 * npx-installed server there is no src/, and dist/ is the only code there is.
 */
const BUILD_OUTPUT = new Set(['dist', 'build', 'out', 'lib']);

function isRedundantBuildOutput(name: string, parent: string): boolean {
  if (!BUILD_OUTPUT.has(name)) return false;
  return existsSync(join(parent, 'src')) || existsSync(join(parent, 'source'));
}

const SOURCE_EXT: Record<string, Language> = {
  '.js': 'js', '.mjs': 'js', '.cjs': 'js', '.jsx': 'js',
  '.ts': 'ts', '.mts': 'ts', '.cts': 'ts', '.tsx': 'ts',
  '.py': 'py', '.pyw': 'py',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
};

export interface WalkedFile {
  path: string;
  relPath: string;
  language: Language;
  text: string;
  size: number;
}

export interface WalkOptions {
  maxFileBytes: number;
  maxFiles: number;
  includeDependencies: boolean;
  exclude?: Matcher;
}

/** Files whose content we can meaningfully analyse. */
export function classify(path: string): Language | undefined {
  const name = basename(path);
  // Declaration files contain types, never behaviour: scanning them produces
  // matches on identifier names with nothing behind them.
  if (name.endsWith('.d.ts') || name.endsWith('.d.mts') || name.endsWith('.d.cts')) return undefined;
  const ext = extname(path).toLowerCase();
  if (SOURCE_EXT[ext]) return SOURCE_EXT[ext];
  if (ext === '.md' || ext === '.markdown' || ext === '.mdx') return 'md';
  if (ext === '.json' || name === '.mcp.json') return 'json';
  if (ext === '.yaml' || ext === '.yml') return 'yaml';
  if (ext === '.toml' && (name === 'pyproject.toml' || name === 'mcp.toml')) return 'other';
  return undefined;
}

function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 1024);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

/** Recursively read every analysable file under `root`. */
export async function walk(root: string, opts: WalkOptions): Promise<WalkedFile[]> {
  const out: WalkedFile[] = [];
  const rootStat = await stat(root);

  if (rootStat.isFile()) {
    const file = await readOne(root, root, opts);
    return file ? [file] : [];
  }

  const queue: string[] = [root];
  while (queue.length && out.length < opts.maxFiles) {
    const dir = queue.shift();
    if (!dir) break;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (opts.exclude?.matches(full, root)) continue;
      if (entry.isDirectory()) {
        if (DEFAULT_SKIP.has(entry.name)) continue;
        if (isRedundantBuildOutput(entry.name, dir)) continue;
        if (entry.name === 'node_modules' && !opts.includeDependencies) continue;
        if (entry.name.startsWith('.') && entry.name !== '.claude' && entry.name !== '.cursor' && entry.name !== '.vscode') continue;
        queue.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (out.length >= opts.maxFiles) break;
      const file = await readOne(full, root, opts);
      if (file) out.push(file);
    }
  }
  return out;
}

async function readOne(full: string, root: string, opts: WalkOptions): Promise<WalkedFile | undefined> {
  const language = classify(full);
  if (!language) return undefined;
  let info;
  try {
    info = await stat(full);
  } catch {
    return undefined;
  }
  if (info.size > opts.maxFileBytes) return undefined;
  let buf: Buffer;
  try {
    buf = await readFile(full);
  } catch {
    return undefined;
  }
  if (looksBinary(buf)) return undefined;
  return {
    path: full,
    relPath: relative(root, full) || basename(full),
    language,
    text: buf.toString('utf8'),
    size: info.size,
  };
}

/**
 * Does this directory look like a repository you build from, rather than an
 * already-published package? Lockfile advice only applies to the former.
 */
export function isSourceCheckout(dir: string): boolean {
  return ['.git', '.github'].some((f) => existsSync(join(dir, f)));
}

export function hasLockfile(dir: string): boolean {
  return ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'bun.lockb', 'uv.lock', 'poetry.lock', 'requirements.txt']
    .some((f) => existsSync(join(dir, f)));
}
