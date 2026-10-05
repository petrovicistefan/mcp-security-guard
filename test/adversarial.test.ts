import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { adversarialTest } from "../src/adversarial.js";
import type { ServerConfig } from "../src/types.js";

const fixture = resolve(__dirname, "fixtures/vulnerable-server.mjs");

describe("adversarial testing", () => {
  it("finds command injection and path traversal, spares safe and destructive tools", async () => {
    const canary = mkdtempSync(join(tmpdir(), "mcpsec-canary-"));
    const server: ServerConfig = { name: "vulnerable", scope: "project", source: "/x/.mcp.json", command: process.execPath, args: [fixture] };
    const r = await adversarialTest(server, { canaryDir: canary });

    expect(r.findings.map((f) => `${f.severity} ${f.rule} ${f.location.split("›")[1].trim()}`).sort()).toEqual([
      'critical adversarial/command-injection tool "ping_host"',
      'high adversarial/path-traversal tool "read_doc"',
    ]);
    expect(r.skippedTools).toEqual([{ tool: "delete_everything", reason: expect.stringContaining("destructive") }]);
    expect(r.testedTools.sort()).toEqual(["ping_host", "read_doc", "safe_ping"]);
    expect(readdirSync(canary)).toEqual([]); // canaries are cleaned up
  }, 60_000);
});
