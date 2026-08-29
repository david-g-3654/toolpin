/**
 * Optional live introspection: launch a server and ask it what it exposes.
 *
 * This runs the server's code, which is exactly what the rest of the scanner
 * avoids -- so it is opt-in, time-boxed, and never enabled by default. Its value
 * is that a server can serve a clean description on disk and a poisoned one over
 * the wire, and only a real handshake catches that.
 */
import { spawn } from 'node:child_process';
import type { Artifact, Target, ToolDescriptor } from '../types.js';
import { sha256 } from '../util/text.js';

interface RpcMessage {
  jsonrpc: '2.0';
  id?: number | string;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string };
}

export interface IntrospectResult {
  tools: ToolDescriptor[];
  instructions?: string;
  serverInfo?: { name?: string; version?: string };
  error?: string;
}

const CLIENT_INFO = { name: 'toolpin', version: '0.1.0' };
const PROTOCOL_VERSION = '2025-06-18';

export async function introspectStdio(
  target: Target,
  timeoutMs: number,
): Promise<IntrospectResult> {
  const cmd = target.command;
  if (!cmd?.command) return { tools: [], error: 'no launch command' };

  return new Promise<IntrospectResult>((resolve) => {
    let settled = false;
    const finish = (result: IntrospectResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
      resolve(result);
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(cmd.command, cmd.args ?? [], {
        stdio: ['pipe', 'pipe', 'pipe'],
        // Deliberately not inheriting the caller's environment: an introspected
        // server should not see the auditor's own secrets.
        env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', ...(cmd.env ?? {}) },
      });
    } catch (err) {
      return resolve({ tools: [], error: `spawn failed: ${(err as Error).message}` });
    }

    const timer = setTimeout(() => finish({ tools: [], error: `timed out after ${timeoutMs}ms` }), timeoutMs);

    let buffer = '';
    let stderr = '';
    const result: IntrospectResult = { tools: [] };

    const send = (msg: RpcMessage) => {
      try {
        child.stdin?.write(`${JSON.stringify(msg)}\n`);
      } catch {
        /* pipe closed */
      }
    };

    child.stdout?.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      let nl: number;
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        let msg: RpcMessage;
        try {
          msg = JSON.parse(line) as RpcMessage;
        } catch {
          continue;
        }
        if (msg.id === 1 && msg.result) {
          const init = msg.result as { instructions?: string; serverInfo?: { name?: string; version?: string } };
          if (init.instructions) result.instructions = init.instructions;
          if (init.serverInfo) result.serverInfo = init.serverInfo;
          send({ jsonrpc: '2.0', method: 'notifications/initialized' });
          send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
        }
        if (msg.id === 2) {
          const listed = (msg.result as { tools?: Array<{ name: string; description?: string; inputSchema?: unknown }> })?.tools ?? [];
          result.tools = listed.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
            origin: 'introspect' as const,
          }));
          finish(result);
        }
      }
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8').slice(0, 2000);
    });
    child.on('error', (err) => finish({ tools: [], error: `launch error: ${err.message}` }));
    child.on('exit', (code) =>
      finish({
        ...result,
        error: result.tools.length ? undefined : `server exited (code ${code})${stderr ? `: ${stderr.slice(0, 200)}` : ''}`,
      }),
    );

    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO },
    });
  });
}

/** Turn a live tool list into artifacts. The "file" is the config that launched it. */
export function introspectArtifacts(target: Target, result: IntrospectResult): Artifact[] {
  const out: Artifact[] = [];
  const file = target.path;
  if (result.instructions) {
    out.push({
      kind: 'server-instructions',
      file,
      text: result.instructions,
      lineOffset: 1,
      language: 'other',
      serverId: target.id,
    });
  }
  for (const tool of result.tools) {
    out.push({ kind: 'tool-name', file, text: tool.name, lineOffset: 1, language: 'other', serverId: target.id, toolName: tool.name });
    if (tool.description) {
      out.push({
        kind: 'tool-description',
        file,
        text: tool.description,
        lineOffset: 1,
        language: 'other',
        serverId: target.id,
        toolName: tool.name,
      });
    }
    const schema = tool.inputSchema as { properties?: Record<string, { description?: string }> } | undefined;
    for (const [param, spec] of Object.entries(schema?.properties ?? {})) {
      if (!spec?.description) continue;
      out.push({
        kind: 'param-description',
        file,
        text: spec.description,
        lineOffset: 1,
        language: 'other',
        serverId: target.id,
        toolName: `${tool.name}.${param}`,
      });
    }
  }
  return out;
}

/**
 * Stable hash of a server's entire tool surface. Two servers with the same
 * fingerprint present the agent with byte-identical instructions.
 */
export function toolsetFingerprint(tools: ToolDescriptor[]): string {
  const normalized = tools
    .map((t) => ({ name: t.name, description: t.description ?? '', schema: t.inputSchema ? JSON.stringify(t.inputSchema) : '' }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return sha256(JSON.stringify(normalized));
}
