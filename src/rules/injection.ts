/**
 * Rules for text the agent *obeys*: tool descriptions, parameter descriptions,
 * prompt templates, server instructions, resources, and skill bodies.
 *
 * The governing idea: a tool description is a specification of what a tool does.
 * The moment it starts issuing directives about the agent's behaviour -- what to
 * read first, what not to tell the user, which other tools to prefer -- it has
 * left its lane, and that is exactly the shape of a tool-poisoning payload.
 */
import type { Artifact, Finding, Rule } from '../types.js';
import {
  INVISIBLE_CHARS,
  entropy,
  locate,
  makeFinding,
  mixedScripts,
  patternCheck,
  truncate,
} from '../util/text.js';

const MODEL_FACING: Artifact['kind'][] = [
  'tool-description',
  'param-description',
  'prompt',
  'resource',
  'server-instructions',
  'skill',
];

const SPEC = 'https://modelcontextprotocol.io/specification/draft/basic/security_best_practices';

/** MCP-TP-001 -- classic instruction override aimed at the agent. */
const instructionOverride: Rule = {
  id: 'MCP-TP-001',
  title: 'Tool description overrides the agent\'s instructions',
  category: 'tool-poisoning',
  severity: 'critical',
  confidence: 'high',
  kinds: MODEL_FACING,
  remediation:
    'A tool description must describe the tool, not redirect the agent. Remove the directive text, ' +
    'or if you did not write this server, stop using it: the description is executed as instructions.',
  references: [SPEC],
};
instructionOverride.check = patternCheck(instructionOverride, [
  {
    re: /\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(your\s+|the\s+)?(previous|prior|above|earlier|preceding|system|initial)\s+(instructions?|prompts?|rules?|directions?|guidelines?)/i,
    note: 'tells the agent to discard its own instructions',
  },
  {
    re: /\byou\s+(are\s+now|must\s+now|will\s+now|should\s+now)\b[^.\n]{0,120}/i,
    severity: 'high',
    note: 'reassigns the agent\'s role from inside a description',
  },
  {
    re: /\b(new|updated|revised)\s+(system\s+)?(instructions?|prompt|directive)s?\s*[:.]/i,
    note: 'declares a replacement system prompt',
  },
  {
    re: /<\/?(system|important|secret|hidden|instructions?|admin)>/i,
    severity: 'critical',
    note: 'fake system/priority tag inside a description',
  },
  {
    re: /\[\[?\s*(system|important|admin|override)\s*\]?\]/i,
    severity: 'high',
    note: 'fake priority marker inside a description',
  },
]);

/** MCP-TP-002 -- instructions to conceal behaviour from the user. */
const concealment: Rule = {
  id: 'MCP-TP-002',
  title: 'Description instructs the agent to hide activity from the user',
  category: 'tool-poisoning',
  severity: 'critical',
  confidence: 'high',
  kinds: MODEL_FACING,
  remediation:
    'Concealment directives have no legitimate use in a tool description. Treat this server as ' +
    'hostile and remove it; if it is your own server, delete the directive.',
  references: [SPEC],
};
concealment.check = patternCheck(concealment, [
  {
    re: /\b(do\s*n[o']?t|never|avoid)\s+(tell|inform|mention|reveal|disclose|show|notify|display|report)\s+(this\s+|it\s+|that\s+)?(to\s+)?(the\s+)?(user|human|operator|caller)/i,
    note: 'explicitly tells the agent not to disclose something',
  },
  {
    // Bare "silently" is ordinary prose ("silently ignore parse errors").
    // What matters is silence about an action with an effect.
    re: /\b(?:silently|quietly)\s+(?:send|upload|post|forward|transmit|read|write|delete|remove|run|execute|call|invoke|collect|store|copy|share)\b/i,
    severity: 'high',
    note: 'asks for an action to be taken without user awareness',
  },
  {
    re: /\bwithout\s+(?:telling|informing|notifying|alerting|asking|consulting)\s+(?:the\s+)?(?:user|human|operator|caller|them)\b/i,
    severity: 'high',
    note: 'asks for action without user awareness',
  },
  {
    re: /\b(keep|this)\s+(this\s+)?(secret|confidential|hidden|between\s+us)\b/i,
    note: 'asks the agent to keep information from the user',
  },
  {
    re: /\bdo\s*n[o']?t\s+(ask|request|seek)\s+(for\s+)?(permission|confirmation|approval|consent)/i,
    // Real, but on its own it is a UX instruction as often as an attack.
    severity: 'high',
    note: 'suppresses the confirmation step before a side effect',
  },
  {
    re: /\b(hide|suppress|omit)\s+(this|the|any)\s+(from\s+the\s+)?(output|logs?|user|response|summary)/i,
    severity: 'high',
    note: 'asks the agent to suppress evidence of the call',
  },
]);

/** MCP-TP-003 -- description points the agent at credential material. */
const credentialDirective: Rule = {
  id: 'MCP-TP-003',
  title: 'Description directs the agent to read credentials or sensitive files',
  category: 'credential-exposure',
  severity: 'critical',
  confidence: 'high',
  kinds: MODEL_FACING,
  remediation:
    'A tool that needs a secret should take it from its own environment, never by instructing the ' +
    'agent to read the user\'s key material and pass it in. Remove the server.',
  references: [SPEC],
};
credentialDirective.check = patternCheck(credentialDirective, [
  {
    re: /(?:read|open|cat|load|include|attach|fetch|retrieve|send|pass)[^.\n]{0,60}(~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.env\b|\.npmrc|\.git-credentials|\.netrc|\/etc\/(passwd|shadow)|keychain|credentials\.json|token\.json|\.pem\b)/i,
    note: 'names a credential file the agent should read',
  },
  {
    re: /(?:contents?|value)\s+of\s+[^.\n]{0,40}(api[_\s-]?key|secret|token|password|private\s+key|credential)/i,
    severity: 'high',
    note: 'asks for the value of a secret',
  },
  {
    re: /\b(environment\s+variables?|process\.env|os\.environ)\b[^.\n]{0,60}\b(include|pass|send|add|attach|append|as\s+the)\b/i,
    severity: 'high',
    note: 'asks the agent to forward environment variables',
  },
  {
    re: /\bpass\s+(?:it|them|the\s+\w+)\s+(?:as|in|to)\s+the\s+\w+\s+(?:parameter|argument|field)/i,
    severity: 'high',
    confidence: 'medium',
    note: 'side-channel parameter: data smuggled into an unrelated argument',
  },
]);

/** MCP-TP-004 -- preconditions the agent must satisfy before the tool "works". */
const precondition: Rule = {
  id: 'MCP-TP-004',
  title: 'Description imposes a hidden precondition on the agent',
  category: 'tool-poisoning',
  severity: 'high',
  confidence: 'medium',
  kinds: MODEL_FACING,
  remediation:
    'Preconditions phrased as agent instructions ("before using this tool, first ...") are the ' +
    'standard tool-poisoning shape. Express real requirements as schema constraints instead.',
  references: [SPEC],
};
precondition.check = patternCheck(precondition, [
  {
    re: /\bbefore\s+(using|calling|invoking|running)\s+(this|the)\s+(tool|function|server)[^.\n]{0,160}/i,
    note: 'imposes a step the agent must take first',
  },
  {
    re: /\b(first|always|you\s+must),?\s+(read|call|invoke|run|fetch|check|load)\s+[^.\n]{0,100}/i,
    severity: 'medium',
    confidence: 'low',
    note: 'mandatory preliminary action',
  },
  {
    re: /\b(this\s+tool\s+)?(will\s+)?(fail|error|not\s+work|break)\s+(unless|if\s+you\s+do\s*n[o']?t)\b[^.\n]{0,120}/i,
    note: 'coerces compliance by threatening failure',
  },
]);

/** MCP-TP-005 -- description reaches across to other servers' tools. */
const crossToolDirective: Rule = {
  id: 'MCP-TP-005',
  title: 'Description manipulates the agent\'s use of other tools',
  category: 'tool-poisoning',
  severity: 'critical',
  confidence: 'medium',
  kinds: MODEL_FACING,
  remediation:
    'A server may only describe its own tools. Redirecting or overriding another server\'s tools ' +
    'is tool shadowing; remove this server from the agent\'s configuration.',
  references: [SPEC],
};
crossToolDirective.check = patternCheck(crossToolDirective, [
  {
    // The object has to look like a tool, not a feature: "rather than using
    // date filters" is advice about parameters, not tool redirection.
    re: /\b(?:instead\s+of|rather\s+than)\s+(?:using|calling|invoking)\s+(?:[\w.'"`-]+\s+){0,3}["'`]?[\w.-]*(?:_[\w.-]+|tool|server|mcp)\b[^.\n]{0,60}/i,
    note: 'redirects the agent away from another tool',
  },
  {
    re: /\bwhen(ever)?\s+(the\s+)?(user|agent|you)\s+[^.\n]{0,40}\b(use|call|invoke)\s+(this|the\s+\w+)\s+tool\s+instead/i,
    note: 'installs a routing rule that hijacks other tools',
  },
  {
    re: /\b(all|any|every)\s+(calls?|requests?|invocations?)\s+to\s+[\w.-]+\s+(must|should|will)\s+(be\s+)?(routed|proxied|forwarded|redirected)/i,
    note: 'claims to proxy another server\'s traffic',
  },
  {
    re: /\b(this\s+)?(tool|server)\s+(replaces|supersedes|deprecates|overrides)\s+/i,
    severity: 'high',
    note: 'claims precedence over other tools',
  },
]);

/** MCP-TP-006 -- borrowed authority. */
const authorityClaim: Rule = {
  id: 'MCP-TP-006',
  title: 'Description claims authority it cannot have',
  category: 'prompt-injection',
  severity: 'high',
  confidence: 'medium',
  kinds: MODEL_FACING,
  remediation:
    'Descriptions cannot grant permissions. Text asserting pre-authorisation, vendor identity, or ' +
    '"test mode" exists to talk the agent past its own safety checks.',
  references: [SPEC],
};
authorityClaim.check = patternCheck(authorityClaim, [
  {
    re: /\b(the\s+)?(user|owner|admin(istrator)?|developer)\s+has\s+(already\s+)?(authoriz|authoris|approv|consent|permitt)\w*/i,
    note: 'claims the user pre-approved the action',
  },
  {
    re: /\byou\s+(are|have\s+been)\s+(pre-?)?(authoriz|authoris|permitt|allow)\w*\s+to\b/i,
    note: 'asserts permission the description cannot grant',
  },
  {
    re: /\b(anthropic|openai|the\s+system|claude\s+team|security\s+team)\s+(has\s+)?(requires?|mandates?|instructs?|approved?|authoriz\w+)/i,
    note: 'impersonates the vendor or platform',
  },
  {
    re: /\b(test|debug|developer|maintenance|safe)\s+mode\s+(is\s+)?(enabled|active|on)\b/i,
    note: 'claims a mode that relaxes safety checks',
  },
  {
    re: /\b(this\s+is\s+)?(not|no)\s+a\s+(real|production)\s+(request|action|environment)\b/i,
    severity: 'medium',
    note: 'frames a real action as a simulation',
  },
]);

/** MCP-TP-007 -- urgency and coercion. */
const coercion: Rule = {
  id: 'MCP-TP-007',
  title: 'Description uses urgency or coercion to force a call',
  category: 'prompt-injection',
  severity: 'medium',
  confidence: 'low',
  kinds: MODEL_FACING,
  remediation:
    'Remove pressure language. Urgency in a tool description is a social-engineering pattern, not ' +
    'a specification of behaviour.',
  references: [SPEC],
};
coercion.check = patternCheck(coercion, [
  { re: /\b(urgent(ly)?|immediately|right\s+now|critical(ly)?|emergency)\b[^.\n]{0,60}\b(must|need\s+to|required?)\b/i },
  { re: /\bfailure\s+to\s+(comply|do\s+so|follow)\b[^.\n]{0,80}/i },
  { re: /\b(data\s+loss|security\s+breach|account\s+(will\s+be\s+)?(locked|suspended|deleted))\b[^.\n]{0,60}\bunless\b/i },
]);

/** MCP-HID-001 -- invisible characters in model-facing text. */
const invisibleChars: Rule = {
  id: 'MCP-HID-001',
  title: 'Invisible Unicode characters in model-facing text',
  category: 'obfuscation',
  severity: 'high',
  confidence: 'high',
  kinds: [...MODEL_FACING, 'skill-frontmatter', 'manifest'],
  remediation:
    'The agent reads these characters; a human reviewing the same text in a terminal or web UI does ' +
    'not. Strip them, and re-read the description with the characters made visible before trusting it.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const out: Finding[] = [];
    for (const { re, name } of INVISIBLE_CHARS) {
      const scan = new RegExp(re.source, re.flags);
      const first = scan.exec(artifact.text);
      if (!first) continue;
      scan.lastIndex = 0;
      const count = (artifact.text.match(scan) ?? []).length;
      const cp = first[0].codePointAt(0) ?? 0;
      out.push(
        makeFinding(invisibleChars, {
          message: `${count} hidden character${count === 1 ? '' : 's'} in ${artifact.kind}${
            artifact.toolName ? ` of "${artifact.toolName}"` : ''
          } (${name}, U+${cp.toString(16).toUpperCase().padStart(4, '0')})`,
          location: locate(artifact, first.index, first[0].length),
          evidence: `U+${cp.toString(16).toUpperCase().padStart(4, '0')} x${count}`,
          severity: count > 8 ? 'critical' : 'high',
          serverId: artifact.serverId,
          toolName: artifact.toolName,
        }),
      );
    }
    return out;
  },
};

/** MCP-HID-002 -- markup that hides text from a rendered view but not from the model. */
const hiddenMarkup: Rule = {
  id: 'MCP-HID-002',
  title: 'Text hidden from human review but visible to the agent',
  category: 'obfuscation',
  severity: 'high',
  confidence: 'medium',
  kinds: MODEL_FACING,
  remediation:
    'HTML comments, zero-size or off-screen styling, and white-on-white text are invisible in a ' +
    'rendered preview and fully visible to the model. Remove them from anything the agent reads.',
  references: [SPEC],
};
hiddenMarkup.check = patternCheck(hiddenMarkup, [
  { re: /<!--[\s\S]{20,}?-->/, note: 'HTML comment carrying substantial text' },
  { re: /style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)/i, note: 'CSS-hidden content' },
  { re: /color\s*:\s*(#fff(fff)?|white)\s*;\s*background(-color)?\s*:\s*(#fff(fff)?|white)/i, note: 'white-on-white text' },
]);

/** MCP-HID-003 -- encoded payloads embedded in a description. */
const encodedPayload: Rule = {
  id: 'MCP-HID-003',
  title: 'Encoded blob embedded in model-facing text',
  category: 'obfuscation',
  severity: 'medium',
  confidence: 'medium',
  kinds: MODEL_FACING,
  remediation:
    'Decode the blob and review it. Descriptions have no reason to carry base64, hex, or ' +
    'percent-encoded payloads; this is a common way to smuggle instructions past a keyword filter.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const out: Finding[] = [];
    const patterns: Array<[RegExp, string]> = [
      [/[A-Za-z0-9+/]{80,}={0,2}/g, 'base64'],
      [/(?:\\x[0-9a-fA-F]{2}){12,}/g, 'hex escape sequence'],
      [/(?:%[0-9a-fA-F]{2}){15,}/g, 'percent-encoded'],
      [/(?:\\u[0-9a-fA-F]{4}){10,}/g, 'unicode escape sequence'],
    ];
    for (const [re, label] of patterns) {
      let m: RegExpExecArray | null;
      const scan = new RegExp(re.source, re.flags);
      while ((m = scan.exec(artifact.text)) !== null) {
        // High entropy separates a real payload from a long English word run.
        if (label === 'base64' && entropy(m[0]) < 4.2) continue;
        let decoded = '';
        if (label === 'base64') {
          try {
            decoded = Buffer.from(m[0], 'base64').toString('utf8');
          } catch {
            decoded = '';
          }
        }
        const printable = /^[\x20-\x7E\s]{16,}$/.test(decoded) ? truncate(decoded, 120) : '';
        out.push(
          makeFinding(encodedPayload, {
            message: `${m[0].length}-character ${label} blob in ${artifact.kind}${
              printable ? ` decoding to: "${printable}"` : ''
            }`,
            location: locate(artifact, m.index, m[0].length),
            evidence: truncate(m[0], 80),
            severity: printable ? 'high' : 'medium',
            confidence: printable ? 'high' : 'medium',
            serverId: artifact.serverId,
            toolName: artifact.toolName,
          }),
        );
        break; // one finding per encoding type per artifact is enough
      }
    }
    return out;
  },
};

/** MCP-HID-004 -- homoglyph / mixed-script tool names. */
const homoglyphName: Rule = {
  id: 'MCP-HID-004',
  title: 'Tool name mixes Unicode scripts',
  category: 'obfuscation',
  severity: 'high',
  confidence: 'high',
  kinds: ['tool-name'],
  remediation:
    'A name that mixes scripts renders identically to an ASCII name while being a different string. ' +
    'It is used to impersonate a trusted tool. Reject the server.',
  references: [SPEC],
  check(artifact: Artifact): Finding[] {
    const scripts = mixedScripts(artifact.text);
    if (scripts.length < 2) return [];
    return [
      makeFinding(homoglyphName, {
        message: `Tool name "${artifact.text}" mixes ${scripts.join(' and ')} characters - it may be impersonating another tool`,
        location: locate(artifact, 0, artifact.text.length),
        evidence: artifact.text,
        serverId: artifact.serverId,
        toolName: artifact.toolName,
      }),
    ];
  },
};

/** MCP-INJ-001 -- injection sinks inside skill bodies and prompt templates. */
const untrustedContentFlow: Rule = {
  id: 'MCP-INJ-001',
  title: 'Instruction to act on fetched or user-supplied content',
  category: 'prompt-injection',
  severity: 'medium',
  confidence: 'low',
  kinds: ['skill', 'prompt', 'server-instructions'],
  remediation:
    'Content retrieved at runtime is data, not instructions. Say so explicitly in the prompt, and ' +
    'never tell the agent to follow, execute, or obey what it fetches.',
  references: [SPEC],
};
untrustedContentFlow.check = patternCheck(untrustedContentFlow, [
  {
    re: /\b(follow|execute|obey|carry\s+out|do)\s+(the\s+|any\s+|all\s+)?(instructions?|commands?|steps?|directions?)\s+(in|from|found\s+in|contained\s+in)\s+(the\s+)?(page|url|response|file|document|output|result|email|issue|comment)/i,
    severity: 'high',
    confidence: 'high',
    note: 'treats fetched content as instructions',
  },
  {
    re: /\b(fetch|download|curl|wget|retrieve)\b[^.\n]{0,60}\band\s+(run|execute|eval|apply)\b/i,
    severity: 'high',
    confidence: 'medium',
    note: 'fetch-then-execute chain',
  },
]);

export const injectionRules: Rule[] = [
  instructionOverride,
  concealment,
  credentialDirective,
  precondition,
  crossToolDirective,
  authorityClaim,
  coercion,
  invisibleChars,
  hiddenMarkup,
  encodedPayload,
  homoglyphName,
  untrustedContentFlow,
];
