import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { auditTools } from "../src/tool-audit.js";
import type { ServerConfig } from "../src/types.js";

// End-to-end wiring of the opt-in threat feed into the full audit, against a local fake backend.
const fixture = resolve(__dirname, "fixtures/poisoned-server.mjs");
const server: ServerConfig = { name: "poisoned", scope: "project", source: "/x/.mcp.json", command: process.execPath, args: [fixture], env: { POISON_VARIANT: "v1" } };

describe("threat feed wiring", () => {
  let backend: Server;
  let url: string;
  const requests: { auth?: string; body: any }[] = [];

  beforeAll(async () => {
    backend = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c)).on("end", () => {
        const parsed = JSON.parse(body);
        requests.push({ auth: req.headers.authorization, body: parsed });
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ feedUpdatedAt: "2026-10-06", findings: [{ match: { kind: "tool", hash: parsed.toolHashes[0] }, severity: "critical", title: "Tool definition seen in a known attack" }] }));
      });
    });
    await new Promise<void>((r) => backend.listen(0, "127.0.0.1", r));
    url = `http://127.0.0.1:${(backend.address() as AddressInfo).port}`;
  });
  afterAll(() => backend.close());

  it("sends nothing without an API key", async () => {
    delete process.env.MCP_SECURITY_API_KEY;
    process.env.MCP_SECURITY_API_URL = url;
    const a = await auditTools([server], 20);
    expect(requests).toEqual([]);
    expect(a.cloudNote).toBeUndefined();
  }, 30_000);

  it("reports feed matches with the key set, sending only hashes", async () => {
    process.env.MCP_SECURITY_API_KEY = "test-key";
    process.env.MCP_SECURITY_API_URL = url;
    try {
      const a = await auditTools([server], 20);
      expect(requests).toHaveLength(1);
      expect(requests[0].auth).toBe("Bearer test-key");
      expect(requests[0].body.toolHashes.every((h: string) => /^[0-9a-f]{64}$/.test(h))).toBe(true);
      expect(JSON.stringify(requests[0].body)).not.toContain("Adds two numbers");
      const feed = a.findings.filter((f) => f.rule === "feed/tool");
      expect(feed).toHaveLength(1);
      expect(feed[0]).toMatchObject({ severity: "critical", server: "poisoned" });
      expect(a.cloudNote).toContain("Threat feed checked");
    } finally {
      delete process.env.MCP_SECURITY_API_KEY;
      delete process.env.MCP_SECURITY_API_URL;
    }
  }, 30_000);
});
