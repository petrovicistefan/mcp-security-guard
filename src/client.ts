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
 * Connects to a configured server and returns its tool list. This *launches* stdio servers,
 * so callers must have explicit user consent. Only `initialize` and `tools/list` are sent;
 * no tool is ever called.
 */
export async function fetchTools(s: ServerConfig, timeoutMs = 20_000): Promise<ToolDefinition[]> {
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
        const tools: ToolDefinition[] = [];
        let cursor: string | undefined;
        do {
          const page = await client.listTools(cursor ? { cursor } : undefined);
          tools.push(...(page.tools as ToolDefinition[]));
          cursor = page.nextCursor;
        } while (cursor && tools.length < 2000);
        return tools;
      })(),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
    await client.close().catch(() => {});
  }
}
