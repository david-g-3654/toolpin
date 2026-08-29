/**
 * Rules that need structure rather than text: package manifests, MCP client
 * configuration entries, skill frontmatter, and cross-artifact analysis such as
 * tool-name collisions between two servers loaded into the same agent.
 */
import type { Artifact, Finding, Rule, RuleContext } from '../types.js';
import { lineOf, locate, makeFinding, truncate } from '../util/text.js';

const SPEC = 'https://modelcontextprotocol.io/specification/draft/basic/security_best_practices';

interface PackageJson {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  bin?: unknown;
  files?: string[];
}

export interface ServerConfigEntry {
  key: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
}

function atLine(file: string, raw: string | undefined, needle: string): { file: string; line: number; column: number } {
  return { file, line: raw ? lineOf(raw, needle) : 1, column: 1 };
}

/** MCP-SUP-001 -- install-time lifecycle scripts. */
const installScripts: Rule = {
  id: 'MCP-SUP-001',
  title: 'Package runs code at install time',
  category: 'supply-chain',
  severity: 'high',
  confidence: 'high',
  kinds: ['manifest'],
  remediation:
    'Install-time scripts run before anyone reviews the package and before the server is ever ' +
    'invoked. Move the work into the server\'s startup path, or install with --ignore-scripts.',
  references: [SPEC],
  check(artifact: Artifact, ctx: RuleContext): Finding[] {
    const pkg = artifact.data as PackageJson | undefined;
    if (!pkg?.scripts) return [];
    const raw = ctx.fileText(artifact.file);
    const out: Finding[] = [];

    // Hooks npm runs on the *consumer's* machine when the package is installed.
    const CONSUMER_INSTALL = ['preinstall', 'install', 'postinstall'];
    // Hooks that only run for the author, or when installing straight from git.
    const AUTHOR_ONLY = ['prepare', 'prepublish', 'prepublishOnly', 'prepack'];

    for (const name of [...CONSUMER_INSTALL, ...AUTHOR_ONLY]) {
      const body = pkg.scripts[name];
      if (!body) continue;
      const fetchesRemote = /\b(?:curl|wget|Invoke-WebRequest|iwr)\b/.test(body) || /https?:\/\//.test(body);
      const pipesToShell = /\|\s*(?:sudo\s+)?(?:ba|z|k|d)?sh\b/.test(body);
      const inlineCode = /\b(?:node|python3?|ruby|perl|deno|bun)\s+-(?:e|c|-eval)\b/.test(body);

      // "prepare": "npm run build" is how every TypeScript package on npm is
      // built. Reporting it teaches users to ignore the rule.
      if (AUTHOR_ONLY.includes(name) && !fetchesRemote && !pipesToShell) continue;

      const severity = fetchesRemote || pipesToShell ? 'critical' : inlineCode ? 'high' : 'medium';
      const when = CONSUMER_INSTALL.includes(name)
        ? 'runs on every machine that installs this package'
        : 'runs when this package is installed directly from git';
      out.push(
        makeFinding(installScripts, {
          message: `"${name}" script ${when}: ${truncate(body, 100)}`,
          location: atLine(artifact.file, raw, `"${name}"`),
          evidence: body,
          severity,
          serverId: artifact.serverId,
        }),
      );
    }
    return out;
  },
};

/** MCP-SUP-002 -- dependencies that are not content-addressed. */
const unpinnedDependency: Rule = {
  id: 'MCP-SUP-002',
  title: 'Dependency resolved from a mutable source',
  category: 'supply-chain',
  severity: 'medium',
  confidence: 'high',
  kinds: ['manifest'],
  remediation:
    'Pin dependencies to exact versions and commit a lockfile. A git URL, a tarball URL, or a ' +
    'floating range means the code you audited is not necessarily the code that runs tomorrow.',
  references: [SPEC],
  check(artifact: Artifact, ctx: RuleContext): Finding[] {
    const pkg = artifact.data as PackageJson | undefined;
    if (!pkg?.dependencies) return [];
    const raw = ctx.fileText(artifact.file);
    const out: Finding[] = [];
    for (const [dep, range] of Object.entries(pkg.dependencies)) {
      if (typeof range !== 'string') continue;
      const isRemote = /^(?:git(?:\+\w+)?:|https?:|file:|github:)/i.test(range) || /^[\w-]+\/[\w.-]+(?:#|$)/.test(range);
      const isWildcard = range === '*' || range === 'latest' || range === '';
      if (!isRemote && !isWildcard) continue;
      out.push(
        makeFinding(unpinnedDependency, {
          message: isRemote
            ? `Dependency "${dep}" is fetched from a mutable remote source (${truncate(range, 60)})`
            : `Dependency "${dep}" has no version constraint ("${range}")`,
          location: atLine(artifact.file, raw, `"${dep}"`),
          evidence: `${dep}: ${range}`,
          severity: isRemote ? 'high' : 'medium',
          serverId: artifact.serverId,
        }),
      );
    }
    return out;
  },
};

/** MCP-SUP-003 -- no lockfile alongside the manifest. */
const missingLockfile: Rule = {
  id: 'MCP-SUP-003',
  title: 'No dependency lockfile',
  category: 'supply-chain',
  severity: 'low',
  confidence: 'high',
  kinds: ['manifest'],
  remediation:
    'Commit a lockfile so installs are reproducible and a compromised transitive release cannot ' +
    'reach users who installed before it was published.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const meta = artifact.data as (PackageJson & { __hasLockfile?: boolean; __isSourceCheckout?: boolean }) | undefined;
    if (!meta || meta.__hasLockfile !== false) return [];
    // A published tarball never ships a lockfile and does not need one; the
    // advice only applies to a repository someone installs from.
    if (!meta.__isSourceCheckout) return [];
    if (!meta.dependencies || Object.keys(meta.dependencies).length === 0) return [];
    return [
      makeFinding(missingLockfile, {
        message: `${Object.keys(meta.dependencies).length} dependencies with no lockfile next to package.json`,
        location: { file: artifact.file, line: 1, column: 1 },
        serverId: artifact.serverId,
      }),
    ];
  },
};

/** MCP-CFG-001 -- server launched by fetching the latest published version. */
const mutableLaunch: Rule = {
  id: 'MCP-CFG-001',
  title: 'Server launched from an unpinned remote package',
  category: 'supply-chain',
  severity: 'high',
  confidence: 'high',
  kinds: ['config'],
  remediation:
    'Pin the version (npx -y pkg@1.2.3, uvx pkg==1.2.3) or install the server locally. As written, ' +
    'every agent start silently pulls whatever the publisher pushed most recently -- the exact ' +
    'mechanism behind MCP "rug pull" attacks.',
  references: [SPEC],
  check(artifact: Artifact, ctx: RuleContext): Finding[] {
    const entry = artifact.data as ServerConfigEntry | undefined;
    if (!entry?.command) return [];
    const runner = /^(?:npx|bunx|pnpm|pnpx|uvx|uv|yarn|dlx|deno)$/i.test(entry.command.split(/[/\\]/).pop() ?? '');
    if (!runner) return [];
    const pkgArg = (entry.args ?? []).find((a) => !a.startsWith('-') && a !== 'dlx' && a !== 'run' && a !== 'tool');
    if (!pkgArg) return [];
    const pinned = /@\d+\.\d+\.\d+|==\d+\.\d+\.\d+|@sha256[:-]/.test(pkgArg);
    if (pinned) return [];
    const raw = ctx.fileText(artifact.file);
    return [
      makeFinding(mutableLaunch, {
        message: `Server "${entry.key}" runs "${entry.command} ${pkgArg}" with no pinned version`,
        location: atLine(artifact.file, raw, `"${entry.key}"`),
        evidence: `${entry.command} ${(entry.args ?? []).join(' ')}`,
        serverId: artifact.serverId,
      }),
    ];
  },
};

/** MCP-CFG-002 -- secrets stored in plaintext in the client config. */
const plaintextSecret: Rule = {
  id: 'MCP-CFG-002',
  title: 'Credential stored in plaintext in an MCP client config',
  category: 'credential-exposure',
  severity: 'high',
  confidence: 'medium',
  kinds: ['config'],
  remediation:
    'Reference an environment variable or a secret manager instead of inlining the value. Client ' +
    'configs are world-readable to every process running as the user, and are frequently shared in ' +
    'bug reports and screen shares.',
  references: [SPEC],
  check(artifact: Artifact, ctx: RuleContext): Finding[] {
    const entry = artifact.data as ServerConfigEntry | undefined;
    if (!entry?.env) return [];
    const raw = ctx.fileText(artifact.file);
    const out: Finding[] = [];
    for (const [key, value] of Object.entries(entry.env)) {
      if (typeof value !== 'string' || value.length < 12) continue;
      if (!/(?:key|token|secret|password|credential|auth|pat)\b/i.test(key)) continue;
      if (/^\$\{?[A-Z_]+\}?$/.test(value) || /^\$\(/.test(value)) continue; // indirection, fine
      out.push(
        makeFinding(plaintextSecret, {
          message: `Server "${entry.key}" stores a literal value for ${key} in its config`,
          location: atLine(artifact.file, raw, `"${key}"`),
          evidence: `${key}=${value}`,
          serverId: artifact.serverId,
        }),
      );
    }
    return out;
  },
};

/** MCP-CFG-003 -- unencrypted or over-broad remote endpoint. */
const insecureRemote: Rule = {
  id: 'MCP-CFG-003',
  title: 'Remote server reached over plaintext HTTP',
  category: 'transport',
  severity: 'high',
  confidence: 'high',
  kinds: ['config'],
  remediation:
    'Use https. Everything the agent sends this server -- including any credential in its env -- ' +
    'crosses the network in the clear.',
  references: [SPEC],
  check(artifact: Artifact, ctx: RuleContext): Finding[] {
    const entry = artifact.data as ServerConfigEntry | undefined;
    const url = entry?.url ?? (entry?.args ?? []).find((a) => /^https?:\/\//i.test(a));
    if (!url || !/^http:\/\//i.test(url)) return [];
    if (/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(url)) return [];
    const raw = ctx.fileText(artifact.file);
    return [
      makeFinding(insecureRemote, {
        message: `Server "${entry?.key}" is configured over plaintext HTTP: ${truncate(url, 80)}`,
        location: atLine(artifact.file, raw, url),
        evidence: url,
        serverId: artifact.serverId,
      }),
    ];
  },
};

/** MCP-CFG-004 -- filesystem-style server pointed at the whole home directory. */
const broadFilesystemScope: Rule = {
  id: 'MCP-CFG-004',
  title: 'Server granted an over-broad filesystem root',
  category: 'configuration',
  severity: 'medium',
  confidence: 'medium',
  kinds: ['config'],
  remediation:
    'Scope the server to the specific project directories it needs. A root of /, ~, or $HOME hands ' +
    'the agent -- and anything that can inject a tool call into it -- every file you own.',
  references: [SPEC],
  check(artifact: Artifact, ctx: RuleContext): Finding[] {
    const entry = artifact.data as ServerConfigEntry | undefined;
    if (!entry?.args?.length) return [];
    const raw = ctx.fileText(artifact.file);
    const out: Finding[] = [];
    for (const arg of entry.args) {
      if (typeof arg !== 'string') continue;
      const normalized = arg === '/' ? '/' : arg.replace(/[/\\]+$/, '');
      const broad =
        normalized === '/' ||
        normalized === '~' ||
        normalized === '$HOME' ||
        /^(?:~|\$HOME|\/Users\/[^/]+|\/home\/[^/]+)$/.test(normalized) ||
        /^(?:\/|~\/)?(?:etc|var|usr|System|Library)$/.test(normalized);
      if (!broad) continue;
      out.push(
        makeFinding(broadFilesystemScope, {
          message: `Server "${entry.key}" is given "${arg}" as a root path`,
          location: atLine(artifact.file, raw, arg),
          evidence: arg,
          severity: normalized === '/' ? 'high' : 'medium',
          serverId: artifact.serverId,
        }),
      );
    }
    return out;
  },
};

/** MCP-CFG-005 -- launch binary sitting in a world-writable location. */
const untrustedBinaryPath: Rule = {
  id: 'MCP-CFG-005',
  title: 'Server launched from a world-writable path',
  category: 'configuration',
  severity: 'high',
  confidence: 'high',
  kinds: ['config'],
  remediation:
    'Move the server into a directory only you can write. Any local process can replace a binary ' +
    'under /tmp or /var/tmp between agent restarts.',
  references: [SPEC],
  check(artifact: Artifact, ctx: RuleContext): Finding[] {
    const entry = artifact.data as ServerConfigEntry | undefined;
    const candidates = [entry?.command, ...(entry?.args ?? [])].filter((x): x is string => typeof x === 'string');
    const bad = candidates.find((c) => /^(?:\/private)?\/(?:tmp|var\/tmp)\//.test(c) || /^\/dev\/shm\//.test(c));
    if (!bad) return [];
    const raw = ctx.fileText(artifact.file);
    return [
      makeFinding(untrustedBinaryPath, {
        message: `Server "${entry?.key}" runs code from ${bad}`,
        location: atLine(artifact.file, raw, bad),
        evidence: bad,
        serverId: artifact.serverId,
      }),
    ];
  },
};

/** MCP-SKL-001 -- skill frontmatter that hands out broad tool access. */
const skillPermissions: Rule = {
  id: 'MCP-SKL-001',
  title: 'Skill requests broad or unconstrained tool access',
  category: 'skill',
  severity: 'medium',
  confidence: 'high',
  kinds: ['skill-frontmatter'],
  remediation:
    'Constrain allowed-tools to the specific commands the skill needs (for example Bash(git status:*)). ' +
    'An unconstrained Bash grant means every instruction in the skill body -- including any injected ' +
    'into it -- can run arbitrary commands.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const fm = artifact.data as Record<string, unknown> | undefined;
    if (!fm) return [];
    const rawTools = fm['allowed-tools'] ?? fm['allowedTools'] ?? fm['tools'];
    if (rawTools === undefined) return [];
    const tools = Array.isArray(rawTools) ? rawTools.map(String) : String(rawTools).split(/[,\s]+/);
    const out: Finding[] = [];
    for (const tool of tools) {
      const t = tool.trim();
      if (!t) continue;
      const unconstrained = /^(?:Bash|Shell|Execute|Terminal)$/i.test(t) || /^Bash\(\s*\*\s*\)$/i.test(t) || t === '*';
      if (!unconstrained) continue;
      out.push(
        makeFinding(skillPermissions, {
          message: `Skill grants "${t}" with no command constraint`,
          location: locate(artifact, Math.max(0, artifact.text.indexOf(t)), t.length),
          evidence: t,
          severity: t === '*' ? 'high' : 'medium',
          serverId: artifact.serverId,
        }),
      );
    }
    return out;
  },
};

/** MCP-SKL-002 -- skill that pulls its real instructions from the network. */
const skillRemoteContent: Rule = {
  id: 'MCP-SKL-002',
  title: 'Skill loads its instructions or code from the network',
  category: 'skill',
  severity: 'high',
  confidence: 'medium',
  kinds: ['skill'],
  remediation:
    'Inline the content or vendor the script into the skill directory. A skill that fetches at run ' +
    'time can be rewritten by whoever controls that URL, after review and after install.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const re = /(?:curl|wget|fetch|https?:\/\/[^\s)"']+)\s*[^\n]{0,80}?(?:\|\s*(?:ba)?sh|\|\s*python3?|>\s*[\w./-]+\.(?:sh|py|js)|\band\s+(?:run|execute))/gi;
    const out: Finding[] = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(artifact.text)) !== null) {
      out.push(
        makeFinding(skillRemoteContent, {
          message: 'Skill body downloads content and runs it',
          location: locate(artifact, m.index, m[0].length),
          evidence: m[0],
          serverId: artifact.serverId,
        }),
      );
      if (out.length >= 3) break;
    }
    return out;
  },
};

/** MCP-SHD-001 -- two servers claiming the same tool name. */
const toolNameCollision: Rule = {
  id: 'MCP-SHD-001',
  title: 'Two servers expose the same tool name',
  category: 'tool-poisoning',
  severity: 'high',
  confidence: 'high',
  kinds: [],
  remediation:
    'Namespace the tools or drop one server. When names collide the agent has no reliable way to ' +
    'tell which server it is calling, which is how a malicious server intercepts a trusted one.',
  references: [SPEC],
  checkAll(ctx: RuleContext): Finding[] {
    const byName = new Map<string, Artifact[]>();
    for (const a of ctx.artifacts) {
      if (a.kind !== 'tool-name') continue;
      const list = byName.get(a.text) ?? [];
      list.push(a);
      byName.set(a.text, list);
    }
    const out: Finding[] = [];
    for (const [name, artifacts] of byName) {
      const servers = [...new Set(artifacts.map((a) => a.serverId ?? a.file))];
      if (servers.length < 2) continue;
      const first = artifacts[0];
      if (!first) continue;
      out.push(
        makeFinding(toolNameCollision, {
          message: `Tool "${name}" is exposed by ${servers.length} servers: ${servers.join(', ')}`,
          location: { file: first.file, line: first.lineOffset, column: 1 },
          evidence: name,
          serverId: first.serverId,
          toolName: name,
        }),
      );
    }
    return out;
  },
};

/** MCP-SHD-002 -- a description that names another configured server. */
const crossServerReference: Rule = {
  id: 'MCP-SHD-002',
  title: 'Tool description references another configured server by name',
  category: 'tool-poisoning',
  severity: 'high',
  confidence: 'medium',
  kinds: [],
  remediation:
    'A server should have no knowledge of its neighbours. A description that names another server\'s ' +
    'tools is positioning itself to intercept or reroute them.',
  references: [SPEC],
  checkAll(ctx: RuleContext): Finding[] {
    const toolNames = new Map<string, string>(); // tool name -> owning server
    for (const a of ctx.artifacts) {
      if (a.kind === 'tool-name' && a.text.length >= 5 && a.serverId) toolNames.set(a.text, a.serverId);
    }
    const out: Finding[] = [];
    for (const a of ctx.artifacts) {
      if (a.kind !== 'tool-description' && a.kind !== 'server-instructions') continue;
      for (const [name, owner] of toolNames) {
        if (owner === a.serverId) continue;
        const idx = a.text.indexOf(name);
        if (idx === -1) continue;
        out.push(
          makeFinding(crossServerReference, {
            message: `Description in "${a.serverId}" names "${name}", a tool belonging to "${owner}"`,
            location: locate(a, idx, name.length),
            evidence: truncate(a.text.slice(Math.max(0, idx - 60), idx + name.length + 60), 180),
            serverId: a.serverId,
            toolName: a.toolName,
          }),
        );
        break;
      }
    }
    return out;
  },
};

export const structuralRules: Rule[] = [
  installScripts,
  unpinnedDependency,
  missingLockfile,
  mutableLaunch,
  plaintextSecret,
  insecureRemote,
  broadFilesystemScope,
  untrustedBinaryPath,
  skillPermissions,
  skillRemoteContent,
  toolNameCollision,
  crossServerReference,
];
