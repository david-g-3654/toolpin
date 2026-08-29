/**
 * Static extraction of tool definitions from server source.
 *
 * The alternative -- launching the server and calling tools/list -- is more
 * accurate but executes untrusted code, so it stays opt-in (`--introspect`).
 * Static extraction is what runs by default and in CI, and it is what makes a
 * poisoned description visible before the server has ever been started.
 */
import type { Artifact, Language, ToolDescriptor } from '../types.js';
import { indexToPosition } from '../util/text.js';

export interface ExtractedTool extends ToolDescriptor {
  /** Character index of the description literal within the file. */
  descriptionIndex?: number;
  nameIndex: number;
}

/**
 * Read a JS/TS/Python string literal that starts at `i` (which must point at a
 * quote character). Returns the decoded value and the index just past the
 * closing quote, or undefined if the literal is unterminated.
 */
function readLiteral(src: string, i: number): { value: string; end: number } | undefined {
  const quote = src[i];
  if (quote !== '"' && quote !== "'" && quote !== '`') return undefined;
  // Python triple-quoted strings.
  const triple = src.slice(i, i + 3);
  if ((triple === '"""' || triple === "'''") && (quote === '"' || quote === "'")) {
    const close = src.indexOf(triple, i + 3);
    if (close === -1) return undefined;
    return { value: src.slice(i + 3, close), end: close + 3 };
  }
  let out = '';
  for (let j = i + 1; j < src.length; j++) {
    const ch = src[j];
    if (ch === '\\') {
      const next = src[j + 1] ?? '';
      out += next === 'n' ? '\n' : next === 't' ? '\t' : next;
      j++;
      continue;
    }
    if (ch === quote) return { value: out, end: j + 1 };
    if (ch === '\n' && quote !== '`') return undefined; // unterminated single-line literal
    out += ch;
  }
  return undefined;
}

/** Skip whitespace, commas, and line comments forward from `i`. */
function skipTrivia(src: string, i: number): number {
  while (i < src.length) {
    const ch = src[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i);
      i = nl === -1 ? src.length : nl + 1;
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      const close = src.indexOf('*/', i);
      i = close === -1 ? src.length : close + 2;
      continue;
    }
    break;
  }
  return i;
}

/** Find `key: "value"` inside the object literal starting at `start`. */
function objectStringField(src: string, start: number, key: string, limit = 4000): { value: string; index: number } | undefined {
  const window = src.slice(start, start + limit);
  const re = new RegExp(`(?:^|[{,\\s])["']?${key}["']?\\s*:\\s*`, 'm');
  const m = re.exec(window);
  if (!m) return undefined;
  const at = start + m.index + m[0].length;
  const lit = readLiteral(src, at);
  if (!lit) return undefined;
  return { value: lit.value, index: at + 1 };
}

function extractJs(src: string): ExtractedTool[] {
  const tools: ExtractedTool[] = [];

  // server.tool("name", "description", schema, handler)
  // server.registerTool("name", { description: "..." }, handler)
  const callRe = /\.\s*(tool|registerTool|addTool|setTool)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = callRe.exec(src)) !== null) {
    let i = skipTrivia(src, m.index + m[0].length);
    const nameLit = readLiteral(src, i);
    if (!nameLit) continue;
    const nameIndex = i + 1;
    i = skipTrivia(src, nameLit.end);
    const tool: ExtractedTool = { name: nameLit.value, origin: 'static', nameIndex };
    const descLit = readLiteral(src, i);
    if (descLit) {
      tool.description = descLit.value;
      tool.descriptionIndex = i + 1;
    } else if (src[i] === '{') {
      const field = objectStringField(src, i, 'description');
      if (field) {
        tool.description = field.value;
        tool.descriptionIndex = field.index;
      }
    }
    tools.push(tool);
  }

  // Plain descriptors: { name: "x", description: "y", inputSchema: {...} }
  const descriptorRe = /\{\s*(?:["']?name["']?\s*:\s*)/g;
  while ((m = descriptorRe.exec(src)) !== null) {
    const at = m.index + m[0].length;
    const nameLit = readLiteral(src, at);
    if (!nameLit || !/^[\w.-]{1,64}$/.test(nameLit.value)) continue;
    const field = objectStringField(src, m.index, 'description');
    if (!field) continue;
    if (tools.some((t) => t.name === nameLit.value && t.description === field.value)) continue;
    tools.push({
      name: nameLit.value,
      description: field.value,
      origin: 'static',
      nameIndex: at + 1,
      descriptionIndex: field.index,
    });
  }
  return tools;
}

/**
 * Given an index just after `def name`, return the index of the ':' that opens the
 * function body, or -1. Handles nested parentheses and quoted defaults.
 */
function signatureEnd(src: string, from: number): number {
  const open = src.indexOf('(', from);
  const nextColon = src.indexOf(':', from);
  if (open === -1 || (nextColon !== -1 && nextColon < open)) return nextColon; // def name: (no params)
  let depth = 0;
  let quote = '';
  for (let i = open; i < src.length; i++) {
    const ch = src[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) return src.indexOf(':', i);
    }
  }
  return -1;
}

function extractPython(src: string): ExtractedTool[] {
  const tools: ExtractedTool[] = [];

  // @mcp.tool(...) / @server.tool(...) followed by def name(...): """docstring"""
  const decoratorRe = /@\s*[\w.]*\btool\s*(\([^)]*\))?\s*\n(?:@[^\n]*\n)*\s*(?:async\s+)?def\s+(\w+)/g;
  let m: RegExpExecArray | null;
  while ((m = decoratorRe.exec(src)) !== null) {
    const args = m[1] ?? '';
    const fnName = m[2] ?? '';
    const nameIndex = m.index + m[0].lastIndexOf(fnName);
    let name = fnName;
    let description: string | undefined;
    let descriptionIndex: number | undefined;

    const nameKw = /name\s*=\s*["']([^"']+)["']/.exec(args);
    if (nameKw?.[1]) name = nameKw[1];
    const descKw = /description\s*=\s*["']/.exec(args);
    if (descKw) {
      const at = m.index + (m[0].indexOf(args) >= 0 ? m[0].indexOf(args) : 0) + descKw.index + descKw[0].length - 1;
      const lit = readLiteral(src, at);
      if (lit) {
        description = lit.value;
        descriptionIndex = at + 1;
      }
    }
    if (!description) {
      // Docstring: first string literal after the signature's closing colon.
      // The signature's own colons (type annotations, defaults) must be skipped,
      // so find the matching close paren before looking for the colon.
      const bodyStart = signatureEnd(src, m.index + m[0].length);
      if (bodyStart !== -1) {
        const at = skipTrivia(src, bodyStart + 1);
        const lit = readLiteral(src, at);
        if (lit) {
          description = lit.value;
          descriptionIndex = at + (src.slice(at, at + 3) === '"""' || src.slice(at, at + 3) === "'''" ? 3 : 1);
        }
      }
    }
    tools.push({ name, description, origin: 'static', nameIndex, descriptionIndex });
  }

  // Tool(name="x", description="y")
  const ctorRe = /\bTool\s*\(\s*name\s*=\s*["']([^"']+)["'][\s\S]{0,400}?description\s*=\s*/g;
  while ((m = ctorRe.exec(src)) !== null) {
    const at = m.index + m[0].length;
    const lit = readLiteral(src, at);
    if (!lit) continue;
    const name = m[1] ?? '';
    if (tools.some((t) => t.name === name)) continue;
    tools.push({
      name,
      description: lit.value,
      origin: 'static',
      nameIndex: m.index + m[0].indexOf(name),
      descriptionIndex: at + 1,
    });
  }
  return tools;
}

export function extractTools(src: string, language: Language): ExtractedTool[] {
  if (language === 'js' || language === 'ts') return extractJs(src);
  if (language === 'py') return extractPython(src);
  return [];
}

/** Turn extracted tools into artifacts with accurate file positions. */
export function toolArtifacts(file: string, src: string, tools: ExtractedTool[], serverId: string, language: Language): Artifact[] {
  const out: Artifact[] = [];
  for (const tool of tools) {
    out.push({
      kind: 'tool-name',
      file,
      text: tool.name,
      lineOffset: indexToPosition(src, tool.nameIndex).line,
      language,
      serverId,
      toolName: tool.name,
    });
    if (tool.description && tool.descriptionIndex !== undefined) {
      out.push({
        kind: 'tool-description',
        file,
        text: tool.description,
        lineOffset: indexToPosition(src, tool.descriptionIndex).line,
        language,
        serverId,
        toolName: tool.name,
      });
    }
  }
  return out;
}
