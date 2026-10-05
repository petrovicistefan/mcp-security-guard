import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Drives the bundled scanner (dist/index.mjs) over stdio against the poisoned fixture server.
const root = resolve(__dirname, "..");
const fixture = join(root, "test/fixtures/poisoned-server.mjs");

describe("scanner end to end", () => {
  const work = mkdtempSync(join(tmpdir(), "mcpsec-e2e-"));
  const home = join(work, "state");
  let client: Client;

  const call = async (name: string, args: Record<string, unknown>) => {
    const r = await client.callTool({ name, arguments: args });
    return (r.content as { text: string }[])[0].text;
  };
  const writeConfig = (variant: string) =>
    writeFileSync(join(work, ".mcp.json"), JSON.stringify({ mcpServers: { poisoned: { command: process.execPath, args: [fixture], env: { POISON_VARIANT: variant } } } }));

  beforeAll(async () => {
    writeConfig("v1");
    client = new Client({ name: "test", version: "0" });
    await client.connect(
      new StdioClientTransport({ command: process.execPath, args: [join(root, "dist/index.mjs")], cwd: root, env: { ...getDefaultEnvironment(), CLAUDE_PROJECT_DIR: work, MCP_SECURITY_HOME: home }, stderr: "inherit" }),
    );
  }, 30_000);
  afterAll(() => client?.close());

  it("refuses to launch without consent", async () => {
    expect(await call("audit_server_tools", { servers: ["*"], confirm_launch: false })).toMatch(/^Not started/);
  });

  it("finds poisoning, pins, and then detects a rug pull", async () => {
    const first = await call("audit_server_tools", { servers: ["poisoned"], confirm_launch: true });
    expect(first).toContain("tool/invisible-characters");
    expect(first).toContain("not pinned yet");

    expect(await call("pin_tools", { servers: ["poisoned"], confirm_launch: true })).toContain("2 tool(s) pinned");

    writeConfig("v2");
    const second = await call("audit_server_tools", { servers: ["poisoned"], confirm_launch: true });
    expect(second).toContain("drift/tool-changed");
    expect(second).toContain("tool/sensitive-path");
    expect(second).toContain("tool/conceal-from-user");
  }, 60_000);
});
