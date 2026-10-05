import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { transportOf } from "./config.js";
import { VERSION } from "./version.js";
import type { ServerConfig, ToolDefinition } from "./types.js";

/** Expand `${VAR}` and `${VAR:-default}` the way Claude Code does for .mcp.json. */
function expand(value: string): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_, name, def) => process.env[name] ?? def ?? "");
}

const expandRecord = (r?: Record<string, string>) => (r ? Object.fromEntries(Object.entries(r).map(([k, v]) => [k, expand(v)])) : undefined);

/**
 * Connects to a configured server, runs `fn` with the client, and always closes it. This *launches*
 * stdio servers, so callers must have explicit user consent.
 */
export async function withClient<T>(s: ServerConfig, timeoutMs: number, fn: (client: Client) => Promise<T>): Promise<T> {
  const client = new Client({ name: "mcp-security-scanner", version: VERSION });
  const kind = transportOf(s);
  const transport =
    kind === "stdio"
      ? new StdioClientTransport({ command: expand(s.command!), args: (s.args ?? []).map(expand), env: { ...getDefaultEnvironment(), ...expandRecord(s.env) }, stderr: "ignore" })
      : kind === "sse"
        ? new SSEClientTransport(new URL(expand(s.url!)), { requestInit: { headers: expandRecord(s.headers) } })
        : kind === "http"
          ? new StreamableHTTPClientTransport(new URL(expand(s.url!)), { requestInit: { headers: expandRecord(s.headers) } })
          : undefined;
  if (!transport) throw new Error("no command or url configured");

  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs / 1000}s`)), timeoutMs);
  });
  try {
    return await Promise.race([
      (async () => {
        await client.connect(transport);
        return fn(client);
      })(),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
    await client.close().catch(() => {});
  }
}

export async function listAllTools(client: Client): Promise<ToolDefinition[]> {
  const tools: ToolDefinition[] = [];
  let cursor: string | undefined;
  do {
    const page = await client.listTools(cursor ? { cursor } : undefined);
    tools.push(...(page.tools as ToolDefinition[]));
    cursor = page.nextCursor;
  } while (cursor && tools.length < 2000);
  return tools;
}

/** Lists a server's tools. Only `initialize` and `tools/list` are sent; no tool is ever called. */
export async function fetchTools(s: ServerConfig, timeoutMs = 20_000): Promise<ToolDefinition[]> {
  return withClient(s, timeoutMs, listAllTools);
}

/** Everything a server puts in the model's context, not only tools. */
export interface ServerSurface {
  tools: ToolDefinition[];
  /** `instructions` from the initialize result; clients add it to the system prompt. */
  instructions?: string;
  prompts: { name: string; title?: string; description?: string; arguments?: { name: string; description?: string; required?: boolean }[] }[];
  resources: { uri: string; name: string; title?: string; description?: string; mimeType?: string }[];
  resourceTemplates: { uriTemplate: string; name: string; title?: string; description?: string }[];
}

async function paginate<T>(fetchPage: (cursor?: string) => Promise<{ items: T[]; nextCursor?: string }>, max = 2000): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  do {
    const page = await fetchPage(cursor);
    out.push(...page.items);
    cursor = page.nextCursor;
  } while (cursor && out.length < max);
  return out;
}

/**
 * Lists tools, prompts, resources and resource templates, and reads the server instructions. Only
 * list requests are sent: no tool is called, no prompt is rendered, no resource is read. A server that
 * does not support prompts or resources simply yields empty lists.
 */
export async function fetchSurface(s: ServerConfig, timeoutMs = 20_000): Promise<ServerSurface> {
  return withClient(s, timeoutMs, async (client) => {
    const caps = client.getServerCapabilities() ?? {};
    const safe = async <T>(enabled: unknown, fn: () => Promise<T[]>): Promise<T[]> => (enabled ? fn().catch(() => []) : []);
    const [tools, prompts, resources, resourceTemplates] = await Promise.all([
      // Some servers omit the tools capability but still answer tools/list.
      listAllTools(client).catch((e) => (caps.tools ? Promise.reject(e) : ([] as ToolDefinition[]))),
      safe(caps.prompts, () => paginate(async (cursor) => { const r = await client.listPrompts(cursor ? { cursor } : undefined); return { items: r.prompts as ServerSurface["prompts"], nextCursor: r.nextCursor }; })),
      safe(caps.resources, () => paginate(async (cursor) => { const r = await client.listResources(cursor ? { cursor } : undefined); return { items: r.resources as ServerSurface["resources"], nextCursor: r.nextCursor }; })),
      safe(caps.resources, () => paginate(async (cursor) => { const r = await client.listResourceTemplates(cursor ? { cursor } : undefined); return { items: r.resourceTemplates as ServerSurface["resourceTemplates"], nextCursor: r.nextCursor }; })),
    ]);
    return { tools, instructions: client.getInstructions() || undefined, prompts, resources, resourceTemplates };
  });
}

/**
 * The non-tool parts of a surface as tool-shaped definitions, so the same poisoning rules and pins
 * apply. Names are prefixed (`#instructions`, `prompt:`, `resource:`, `template:`) and never collide with tools.
 */
export function surfaceDefinitions(surface: ServerSurface): { kind: "instructions" | "prompt" | "resource" | "template"; def: ToolDefinition }[] {
  return [
    ...(surface.instructions ? [{ kind: "instructions" as const, def: { name: "#instructions", description: surface.instructions } }] : []),
    ...surface.prompts.map((p) => ({
      kind: "prompt" as const,
      def: { name: `prompt:${p.name}`, title: p.title, description: p.description, inputSchema: { type: "object", properties: Object.fromEntries((p.arguments ?? []).map((a) => [a.name, { type: "string", ...(a.description ? { description: a.description } : {}) }])) } },
    })),
    ...surface.resources.map((r) => ({ kind: "resource" as const, def: { name: `resource:${r.uri}`, title: r.title ?? r.name, description: r.description } })),
    ...surface.resourceTemplates.map((t) => ({ kind: "template" as const, def: { name: `template:${t.uriTemplate}`, title: t.title ?? t.name, description: t.description } })),
  ];
}
