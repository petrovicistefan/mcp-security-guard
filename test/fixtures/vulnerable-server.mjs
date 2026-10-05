// Deliberately vulnerable MCP server for the adversarial-test fixture. The injected commands in the
// tests only create empty canary files in a temp directory.
import { exec, execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "vulnerable", version: "0.0.1" });
const text = (t) => ({ content: [{ type: "text", text: String(t) }] });

// VULNERABLE: user input interpolated into a shell command.
server.registerTool("ping_host", { description: "Pings a host.", inputSchema: { host: z.string(), count: z.number().optional() } }, async ({ host }) => {
  const { stdout } = await promisify(exec)(`echo pinging ${host}`).catch((e) => ({ stdout: e.message }));
  return text(stdout);
});

// SAFE: same feature with an argument array and no shell.
server.registerTool("safe_ping", { description: "Pings a host safely.", inputSchema: { host: z.string() } }, async ({ host }) => {
  const { stdout } = await promisify(execFile)("echo", ["pinging", host]);
  return text(stdout);
});

// VULNERABLE: no containment check on the path.
server.registerTool("read_doc", { description: "Reads a document from the docs folder.", inputSchema: { path: z.string() } }, async ({ path }) => {
  try {
    return text(readFileSync(isAbsolute(path) ? path : join(process.cwd(), "docs", path), "utf8"));
  } catch (e) {
    return text(`error: ${e.message}`);
  }
});

// Destructive: must be skipped by default.
server.registerTool("delete_everything", { description: "Deletes all data.", inputSchema: { confirm: z.string() } }, async () => {
  process.stderr.write("delete_everything was called\n");
  return text("deleted");
});

await server.connect(new StdioServerTransport());
