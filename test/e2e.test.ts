import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
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
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, "welcomed"), "test\n");
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

    expect(first).toContain("1** prompt(s)");
    expect(first).toContain("instructions from **1** server(s)");
    expect(await call("pin_tools", { servers: ["poisoned"], confirm_launch: true })).toContain("2 tool(s) and 3 instruction/prompt/resource definition(s) pinned");

    expect(runHook()).toBe("");

    writeConfig("v2");
    const second = await call("audit_server_tools", { servers: ["poisoned"], confirm_launch: true });
    expect(second).toContain("drift/tool-changed");
    expect(second).toContain("tool/sensitive-path");
    expect(second).toContain("tool/conceal-from-user");
    // The rug pull also rewrote the server instructions and a prompt, not only tools.
    expect(second).toMatch(/server "poisoned" › server instructions/);
    expect(second).toMatch(/server "poisoned" › prompt "summarize"/);
    expect(second).toMatch(/3 tool definition\(s\) changed since pinning/);

    const hook = JSON.parse(runHook());
    expect(hook.systemMessage).toContain('"poisoned" (project): 3 definition(s) changed');
    expect(hook.systemMessage).toContain("critical/high poisoning finding");
    expect(hook.hookSpecificOutput.hookEventName).toBe("SessionStart");
  }, 60_000);

  // The SessionStart hook reads the project dir from stdin and must stay silent when nothing changed.
  const runHook = () =>
    execFileSync(process.execPath, [join(root, "dist/cli.mjs"), "session-check"], {
      input: JSON.stringify({ hook_event_name: "SessionStart", cwd: work }),
      env: { ...getDefaultEnvironment(), MCP_SECURITY_HOME: home },
      encoding: "utf8",
    });
});

describe("first run", () => {
  it("greets once with a config summary, then stays silent", () => {
    const work = mkdtempSync(join(tmpdir(), "mcpsec-welcome-"));
    const home = join(work, "state");
    writeFileSync(join(work, ".mcp.json"), JSON.stringify({ mcpServers: { leaky: { command: "x", env: { GITHUB_TOKEN: "ghp_" + "e".repeat(36) } } } }));
    const hook = () => execFileSync(process.execPath, [join(root, "dist/cli.mjs"), "session-check"], { input: JSON.stringify({ cwd: work }), env: { ...getDefaultEnvironment(), MCP_SECURITY_HOME: home, HOME: work }, encoding: "utf8" });
    const first = JSON.parse(hook());
    expect(first.systemMessage).toContain("mcp-security is active");
    expect(first.systemMessage).toMatch(/found \d+ critical\/high issue/);
    expect(hook()).toBe("");
  });
});
