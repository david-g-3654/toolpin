/**
 * Rules for server implementation source (JS/TS/Python/shell).
 *
 * These are deliberately shallow -- regex over source, not a type-aware taint
 * analysis. The goal is to answer "does this server touch credentials, spawn
 * shells, or talk to hosts it never mentioned?" fast enough to run on every
 * install, and to be honest about confidence when it cannot prove a data flow.
 */
import type { Artifact, Finding, Rule } from '../types.js';
import { entropy, isMinified, isTestPath, locate, makeFinding, patternCheck, truncate } from '../util/text.js';

const CODE: Artifact['kind'][] = ['source'];
const SPEC = 'https://modelcontextprotocol.io/specification/draft/basic/security_best_practices';

/** Strip comments so commented-out code does not drive findings. */
function inComment(match: RegExpExecArray, artifact: Artifact): boolean {
  const lineStart = artifact.text.lastIndexOf('\n', Math.max(0, match.index - 1)) + 1;
  const before = artifact.text.slice(lineStart, match.index);
  return /(^|\s)(\/\/|#)/.test(before) || /\*\s*$/.test(before);
}
const notCommented = (m: RegExpExecArray, a: Artifact) => !inComment(m, a);

/** MCP-CRED-001 -- reads of well-known credential locations. */
const credentialRead: Rule = {
  id: 'MCP-CRED-001',
  title: 'Server reads credential material from disk',
  category: 'credential-exposure',
  severity: 'high',
  confidence: 'medium',
  kinds: CODE,
  remediation:
    'Take secrets from the server\'s own environment or a keychain API scoped to what it needs. ' +
    'A server that opens ~/.ssh, ~/.aws/credentials, or .env files reads secrets belonging to every ' +
    'other tool on the machine.',
  references: [SPEC],
};
credentialRead.check = patternCheck(credentialRead, [
  {
    re: /(?:readFile(?:Sync)?|createReadStream|open|read_text|\bopen\s*\(|Path\s*\(|cat\s+)[^\n;]{0,80}(?:\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.aws\/config|\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.docker\/config\.json|\.kube\/config|Keychains?\/|\.gnupg)/i,
    severity: 'critical',
    confidence: 'high',
    note: 'opens a credential store',
    refine: notCommented,
  },
  {
    re: /(?:readFile(?:Sync)?|createReadStream|read_text|\bopen\s*\()[^\n;]{0,80}(?:\/etc\/(?:passwd|shadow)|\.bash_history|\.zsh_history|history\b)/i,
    severity: 'high',
    note: 'reads shell history or system account files',
    refine: notCommented,
  },
  {
    re: /(?:readFile(?:Sync)?|read_text|\bopen\s*\()[^\n;]{0,60}["'`][^"'`\n]*\.env(?:\.[a-z]+)?["'`]/i,
    severity: 'medium',
    note: 'reads a .env file',
    refine: notCommented,
  },
  {
    re: /(?:security\s+find-generic-password|secret-tool\s+lookup|keyring\.get_password|wincred|CredRead)/i,
    severity: 'high',
    note: 'queries the OS credential store',
    refine: notCommented,
  },
]);

/** MCP-CRED-002 -- bulk environment access rather than named variables. */
const envSweep: Rule = {
  id: 'MCP-CRED-002',
  title: 'Server enumerates the entire environment',
  category: 'credential-exposure',
  severity: 'medium',
  confidence: 'medium',
  kinds: CODE,
  remediation:
    'Read the specific variables the server needs by name. Serialising the whole environment sweeps ' +
    'up every other tool\'s API keys, and is the standard first step of a credential-harvesting server.',
  references: [SPEC],
};
envSweep.check = patternCheck(envSweep, [
  { re: /JSON\.stringify\s*\(\s*process\.env\s*\)/, severity: 'high', confidence: 'high', note: 'serialises the whole environment', refine: notCommented },
  { re: /Object\.(keys|entries|values|assign)\s*\(\s*(?:\{\s*\.\.\.\s*)?process\.env/, note: 'iterates every environment variable', refine: notCommented },
  { re: /\{\s*\.\.\.\s*process\.env\s*\}/, note: 'spreads the whole environment', refine: notCommented },
  { re: /(?:json\.dumps|dict|str)\s*\(\s*os\.environ\b/, severity: 'high', confidence: 'high', note: 'serialises the whole environment', refine: notCommented },
  { re: /for\s+\w+\s+in\s+os\.environ\b/, note: 'iterates every environment variable', refine: notCommented },
]);

/** MCP-CRED-003 -- secrets committed into the server itself. */
const hardcodedSecret: Rule = {
  id: 'MCP-CRED-003',
  title: 'Hardcoded credential in server source',
  category: 'credential-exposure',
  severity: 'high',
  confidence: 'high',
  kinds: ['source', 'manifest', 'config'],
  remediation:
    'Move the value to an environment variable and rotate it -- anything committed to a package is ' +
    'published to every machine that installs it.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const out: Finding[] = [];
    const patterns: Array<[RegExp, string, Finding['severity']]> = [
      [/\bAKIA[0-9A-Z]{16}\b/g, 'AWS access key id', 'critical'],
      [/\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, 'GitHub token', 'critical'],
      [/\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b/g, 'API key (OpenAI/Anthropic format)', 'critical'],
      [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, 'Slack token', 'critical'],
      [/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, 'private key', 'critical'],
      [/\bglpat-[A-Za-z0-9_-]{20,}\b/g, 'GitLab token', 'critical'],
      [/\bAIza[0-9A-Za-z_-]{35}\b/g, 'Google API key', 'high'],
      [/\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g, 'Slack webhook', 'high'],
      [/\bhttps:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g, 'Discord webhook', 'high'],
    ];
    for (const [re, label, severity] of patterns) {
      const scan = new RegExp(re.source, re.flags);
      let m: RegExpExecArray | null;
      while ((m = scan.exec(artifact.text)) !== null) {
        out.push(
          makeFinding(hardcodedSecret, {
            message: `Hardcoded ${label} in ${artifact.kind}`,
            location: locate(artifact, m.index, m[0].length),
            evidence: m[0],
            severity,
            serverId: artifact.serverId,
          }),
        );
        break;
      }
    }
    // Generic assignment of a high-entropy literal to a secret-shaped name.
    const generic = /(?:api[_-]?key|secret|token|password|passwd|auth)\s*[:=]\s*["'`]([^"'`\n]{16,80})["'`]/gi;
    let g: RegExpExecArray | null;
    while ((g = generic.exec(artifact.text)) !== null) {
      const value = g[1] ?? '';
      if (/^(?:\$\{|process\.env|os\.environ|<|your|example|placeholder|xxx|changeme|dummy|test|fake|redacted|\.\.\.)/i.test(value)) continue;
      if (entropy(value) < 3.5) continue;
      // Named-format keys above (AKIA…, ghp_…) are leaks wherever they appear.
      // This generic entropy heuristic is not, and test fixtures are full of
      // plausible-looking placeholder tokens.
      const inTest = isTestPath(artifact.file);
      out.push(
        makeFinding(hardcodedSecret, {
          message: inTest
            ? `High-entropy literal assigned to a credential-shaped name in a test file`
            : `High-entropy literal assigned to a credential-shaped name in ${artifact.kind}`,
          location: locate(artifact, g.index, g[0].length),
          evidence: g[0],
          severity: inTest ? 'low' : 'medium',
          confidence: 'low',
          serverId: artifact.serverId,
        }),
      );
      break;
    }
    return out;
  },
};

/** MCP-EXF-001 -- traffic to endpoints associated with drop sites. */
const suspiciousEndpoint: Rule = {
  id: 'MCP-EXF-001',
  title: 'Network call to an exfiltration-friendly endpoint',
  category: 'exfiltration',
  severity: 'critical',
  confidence: 'high',
  kinds: ['source', 'config', 'manifest', 'skill'],
  remediation:
    'These hosts are anonymous, ephemeral drop points. A legitimate MCP server talks to its own ' +
    'documented API, not to a paste site, a request bin, or a chat webhook.',
  references: [SPEC],
};
suspiciousEndpoint.check = patternCheck(suspiciousEndpoint, [
  { re: /https?:\/\/[\w.-]*(?:webhook\.site|requestbin\.\w+|pipedream\.net|beeceptor\.com|interact\.sh|oast\.\w+|burpcollaborator\.net|ngrok(?:-free)?\.(?:io|app|dev)|localtunnel\.me|trycloudflare\.com)[^\s"'`]*/i, note: 'request-capture / tunnel endpoint' },
  { re: /https?:\/\/[\w.-]*(?:pastebin\.com|paste\.ee|hastebin\.com|termbin\.com|transfer\.sh|file\.io|0x0\.st|ix\.io)[^\s"'`]*/i, note: 'anonymous paste / file drop' },
  { re: /https?:\/\/(?:api\.telegram\.org\/bot|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services)[^\s"'`]*/i, note: 'chat webhook used as a data sink' },
  { re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?[^\s"'`]*/i, severity: 'medium', confidence: 'medium', note: 'hardcoded bare IP address', refine: (m) => !/^https?:\/\/(?:127\.|0\.0\.0\.0|localhost)/i.test(m[0]) },
  { re: /\bnc\s+(?:-\w+\s+)*[\w.-]+\s+\d{2,5}\b|\/dev\/tcp\/[\w.-]+\/\d+/i, note: 'raw socket shell' },
]);

/** MCP-EXF-002 -- credential read and network write in the same neighbourhood. */
const exfilFlow: Rule = {
  id: 'MCP-EXF-002',
  title: 'Sensitive read and outbound request in the same function',
  category: 'exfiltration',
  severity: 'high',
  confidence: 'low',
  kinds: CODE,
  remediation:
    'Verify what is being sent. A read of environment, credential, or home-directory data followed ' +
    'closely by an outbound request is the shape of exfiltration; if it is legitimate telemetry, ' +
    'make it opt-in and document the destination.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    // Bulk environment access or named credential material -- not a single
    // `process.env.MY_SETTING`, which is how every server reads its own config.
    const sensitive =
      /JSON\.stringify\s*\(\s*process\.env|\{\s*\.\.\.\s*process\.env|Object\.(?:keys|entries|values|assign)\s*\(\s*(?:\{\s*\.\.\.\s*)?process\.env|json\.dumps\s*\(\s*os\.environ|dict\s*\(\s*os\.environ|for\s+\w+\s+in\s+os\.environ|\.ssh\/|\.aws\/credentials|\.git-credentials|\.netrc|id_rsa|id_ed25519|["'\`][^"'\`\n]*\.env["'\`]/;
    // And a genuine outbound request call. Matching a bare `body:` or `data =`
    // scored every options object and every variable named *Data.
    const network =
      /\bfetch\s*\(|axios\.(?:post|put|patch|request)\s*\(|requests\.(?:post|put|patch)\s*\(|https?\.request\s*\(|urlopen\s*\(|got\.(?:post|put)\s*\(/i;
    // Bundled output has no meaningful line proximity left to measure: in a
    // minified file every statement is within a few lines of every other.
    if (isMinified(artifact.text)) return [];
    const lines = artifact.text.split('\n');
    const out: Finding[] = [];
    const WINDOW = 12;
    // Handing the environment to a child process is how you invoke a CLI, not
    // how you exfiltrate: `spawn(cmd, args, { env: { ...process.env } })`.
    const subprocessEnv = /\benv\s*:/;
    const spawnsProcess = /\b(?:spawn|execFile|exec|fork|subprocess\.)/.test(artifact.text);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (!sensitive.test(line)) continue;
      if (spawnsProcess && subprocessEnv.test(line)) continue;
      const slice = lines.slice(i, Math.min(lines.length, i + WINDOW)).join('\n');
      const netMatch = network.exec(slice);
      if (!netMatch) continue;
      const netLine = i + slice.slice(0, netMatch.index).split('\n').length;
      out.push(
        makeFinding(exfilFlow, {
          message: `Sensitive read on line ${i + artifact.lineOffset} is followed by an outbound request on line ${netLine + artifact.lineOffset - 1}`,
          location: {
            file: artifact.file,
            line: i + artifact.lineOffset,
            column: 1,
            snippet: truncate(lines[i] ?? '', 160),
          },
          evidence: truncate(`${lines[i]} ... ${netMatch[0]}`, 200),
          serverId: artifact.serverId,
        }),
      );
      if (out.length >= 5) break;
    }
    return out;
  },
};

/** MCP-EXE-001 -- shell execution with interpolated input. */
const shellInjection: Rule = {
  id: 'MCP-EXE-001',
  title: 'Shell command built from interpolated input',
  category: 'command-execution',
  severity: 'critical',
  confidence: 'medium',
  kinds: CODE,
  remediation:
    'Use the argument-array form (execFile, spawn without shell, subprocess.run([...]) with ' +
    'shell=False). Every MCP tool argument is attacker-influenced: it arrives from a model that read ' +
    'a web page, an issue, or an email.',
  references: [SPEC],
};
/** Interpolations already passed through a quoting helper. */
const QUOTED = /\$\{\s*(?:JSON\.stringify|shellQuote|quote|escapeShellArg|shlex\.quote|shellescape)\s*\(/;

shellInjection.check = patternCheck(shellInjection, [
  {
    re: /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*`[^`]*\$\{[^`]*`/,
    note: 'template literal interpolated into exec()',
    refine: (m, a) => notCommented(m, a) && !QUOTED.test(m[0]),
  },
  {
    re: /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*`[^`]*\$\{[^`]*`/,
    severity: 'high',
    confidence: 'low',
    note:
      'interpolation is quoted, but JSON/quote helpers do not neutralise `$(...)` or backticks inside double quotes',
    refine: (m, a) => notCommented(m, a) && QUOTED.test(m[0]),
  },
  { re: /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*["'][^"']*["']\s*\+/, note: 'string concatenation into exec()', refine: notCommented },
  { re: /\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true/, severity: 'high', note: 'spawn() with shell:true', refine: notCommented },
  { re: /subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True/, note: 'subprocess with shell=True', refine: notCommented },
  { re: /\bos\.(?:system|popen)\s*\(\s*(?:f["']|["'][^"']*["']\s*[%+]|.*\.format\()/, note: 'os.system() with formatted input', refine: notCommented },
]);

/** MCP-EXE-002 -- dynamic code evaluation. */
const dynamicEval: Rule = {
  id: 'MCP-EXE-002',
  title: 'Dynamic code evaluation',
  category: 'command-execution',
  severity: 'high',
  confidence: 'medium',
  kinds: CODE,
  remediation:
    'Remove the dynamic evaluation, or restrict it to a parser that cannot execute (JSON.parse, ' +
    'yaml.safe_load). Reached with model-supplied input, each of these is remote code execution.',
  references: [SPEC],
};
dynamicEval.check = patternCheck(dynamicEval, [
  { re: /\beval\s*\(/, note: 'eval()', refine: notCommented },
  { re: /new\s+Function\s*\(/, note: 'new Function()', refine: notCommented },
  { re: /\bvm\.run(?:In(?:New|This)Context|InContext)?\s*\(/, severity: 'medium', note: 'vm module execution', refine: notCommented },
  { re: /\bexec\s*\(\s*(?:f["']|["'])/, note: 'Python exec()', refine: notCommented },
  { re: /\bpickle\.loads?\s*\(/, severity: 'critical', confidence: 'high', note: 'pickle deserialisation is arbitrary code execution', refine: notCommented },
  {
    re: /\byaml\.load\s*\((?![^)]*Safe)/,
    note: 'yaml.load() without SafeLoader',
    // js-yaml v4 made load() safe; only PyYAML's load() executes constructors.
    refine: (m, a) => notCommented(m, a) && a.language === 'py',
  },
  { re: /\brequire\s*\(\s*[^)'"`]*(?:\$\{|\+\s*\w)/, severity: 'medium', note: 'require() with a computed path', refine: notCommented },
]);

/** MCP-EXE-003 -- fetch and execute. */
const remoteExecution: Rule = {
  id: 'MCP-EXE-003',
  title: 'Code downloaded and executed at runtime',
  category: 'command-execution',
  severity: 'critical',
  confidence: 'high',
  kinds: ['source', 'manifest', 'config', 'skill'],
  remediation:
    'Vendor the code and pin it. Fetch-and-execute means the audited version and the running version ' +
    'are different artifacts, and the publisher can change behaviour after review.',
  references: [SPEC],
};
remoteExecution.check = patternCheck(remoteExecution, [
  { re: /\b(?:curl|wget)\b[^\n|;]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|k|d)?sh\b/i, note: 'curl | sh' },
  { re: /\b(?:curl|wget)\b[^\n|;]{0,120}\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b/i, note: 'download piped to an interpreter' },
  { re: /\beval\s*\(\s*(?:await\s+)?(?:fetch|requests\.get|urlopen)[^)]*\)/i, note: 'eval of a network response' },
  { re: /(?:exec|eval)\s*\(\s*(?:requests\.get|urllib\.request\.urlopen)\s*\([^)]*\)\s*\.(?:text|read\(\))/i, note: 'exec of a downloaded string' },
  { re: /\bimport\s*\(\s*["']https?:\/\//i, note: 'dynamic import from a URL' },
]);

/** MCP-EXE-004 -- filesystem access without containment. */
const pathTraversal: Rule = {
  id: 'MCP-EXE-004',
  title: 'Filesystem path built from tool input without containment check',
  category: 'command-execution',
  severity: 'high',
  confidence: 'low',
  kinds: CODE,
  remediation:
    'Resolve the joined path and assert it still starts with the allowed root ' +
    '(path.resolve + startsWith, or os.path.commonpath). Joining a caller-supplied segment lets ' +
    '"../../.ssh/id_rsa" escape the sandbox.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const joins = /\b(?:path\.(?:join|resolve)|os\.path\.join|Path\s*\()\s*\([^)]*\b(?:args|params|input|request|req|body|payload|userPath|filePath|filename|file_path|target)\b[^)]*\)/g;
    const hasContainment =
      /\.startsWith\s*\(|commonpath|commonprefix|is_relative_to|relative\s*\(|realpath|resolve\(\)\.startsWith|normalize\s*\(/.test(
        artifact.text,
      );
    if (hasContainment) return [];
    const out: Finding[] = [];
    let m: RegExpExecArray | null;
    while ((m = joins.exec(artifact.text)) !== null) {
      if (inComment(m, artifact)) continue;
      out.push(
        makeFinding(pathTraversal, {
          message: 'Caller-supplied value is joined into a filesystem path and the file contains no containment check',
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

/** MCP-EXE-005 -- persistence and privilege. */
const persistence: Rule = {
  id: 'MCP-EXE-005',
  title: 'Server writes to a persistence or privilege surface',
  category: 'command-execution',
  severity: 'high',
  confidence: 'medium',
  kinds: ['source', 'skill'],
  remediation:
    'An MCP server should not install startup items, edit shell profiles, add SSH keys, or escalate ' +
    'privileges. Remove the code, or if you did not write it, treat the machine as compromised.',
  references: [SPEC],
};
persistence.check = patternCheck(persistence, [
  { re: /(?:writeFile(?:Sync)?|appendFile(?:Sync)?|>>?\s*)[^\n;]{0,80}(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|authorized_keys|crontab|LaunchAgents|LaunchDaemons|systemd\/user|\.config\/autostart)/i, severity: 'critical', note: 'installs persistence', refine: notCommented },
  { re: /\bcrontab\s+-|\bschtasks\s+\/create|\blaunchctl\s+load|\bsystemctl\s+enable\b/i, severity: 'critical', note: 'registers a scheduled task or service', refine: notCommented },
  { re: /\bsudo\s+(?!-n\s+true)|\bchmod\s+(?:\+s|4755|777)\b|\bosascript\b[^\n]{0,60}administrator\s+privileges/i, note: 'privilege escalation', refine: notCommented },
  { re: /\brm\s+-rf\s+(?:\/|~|\$HOME|\*)(?:\s|$)/, severity: 'critical', note: 'destructive recursive delete', refine: notCommented },
  { re: /\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bshred\s+/, severity: 'high', note: 'anti-forensics', refine: notCommented },
]);

/** MCP-NET-001 -- HTTP transport hardening. */
const transportHardening: Rule = {
  id: 'MCP-NET-001',
  title: 'HTTP transport exposed without origin or bind restrictions',
  category: 'transport',
  severity: 'high',
  confidence: 'medium',
  kinds: CODE,
  remediation:
    'Bind local HTTP servers to 127.0.0.1 and validate the Origin header. A locally bound MCP server ' +
    'without Origin validation is reachable from any web page the user visits (DNS rebinding).',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const out: Finding[] = [];
    // Only an actual bind or transport construction counts. Matching the bare
    // identifiers meant every import, type annotation, and re-export scored.
    const LISTEN = /(?:\.listen\s*\(|uvicorn\.run\s*\(|app\.run\s*\([^)]*host|new\s+(?:StreamableHTTPServerTransport|SSEServerTransport)\s*\(|http\.createServer\s*\(|https\.createServer\s*\()/;
    if (!LISTEN.test(artifact.text)) return [];
    if (isTestPath(artifact.file)) return [];
    const validatesOrigin = /\borigin\b/i.test(artifact.text) && /(?:req\.headers|request\.headers|get\s*\(\s*["']origin)/i.test(artifact.text);

    const bindAll = /(?:listen\s*\(\s*[^)]*["']0\.0\.0\.0["']|host\s*=\s*["']0\.0\.0\.0["']|HOST\s*[:=]\s*["']0\.0\.0\.0["'])/g;
    let m: RegExpExecArray | null;
    while ((m = bindAll.exec(artifact.text)) !== null) {
      out.push(
        makeFinding(transportHardening, {
          message: 'HTTP transport binds to 0.0.0.0, exposing the server to the whole network',
          location: locate(artifact, m.index, m[0].length),
          evidence: m[0],
          severity: 'high',
          confidence: 'high',
          serverId: artifact.serverId,
        }),
      );
      break;
    }
    if (!validatesOrigin) {
      const anchor = LISTEN.exec(artifact.text);
      if (anchor) {
        out.push(
          makeFinding(transportHardening, {
            message: 'HTTP transport does not validate the Origin header (DNS-rebinding exposure)',
            location: locate(artifact, anchor.index, anchor[0].length),
            evidence: anchor[0],
            severity: 'medium',
            confidence: 'low',
            serverId: artifact.serverId,
          }),
        );
      }
    }
    return out;
  },
};

/** MCP-NET-002 -- TLS verification switched off. */
const tlsDisabled: Rule = {
  id: 'MCP-NET-002',
  title: 'TLS certificate verification disabled',
  category: 'transport',
  severity: 'high',
  confidence: 'high',
  kinds: ['source', 'config', 'manifest'],
  remediation:
    'Remove the override and fix the certificate chain instead. Disabling verification turns every ' +
    'network hop into a credential-interception point.',
  references: [SPEC],
};
tlsDisabled.check = patternCheck(tlsDisabled, [
  { re: /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0/, refine: notCommented },
  { re: /rejectUnauthorized\s*:\s*false/, refine: notCommented },
  { re: /verify\s*=\s*False/, refine: notCommented },
  { re: /ssl\._create_unverified_context|CERT_NONE/, refine: notCommented },
  { re: /\bcurl\b[^\n]{0,60}(?:\s-k\b|--insecure)/, refine: notCommented },
]);

export const codeRules: Rule[] = [
  credentialRead,
  envSweep,
  hardcodedSecret,
  suspiciousEndpoint,
  exfilFlow,
  shellInjection,
  dynamicEval,
  remoteExecution,
  pathTraversal,
  persistence,
  transportHardening,
  tlsDisabled,
];
