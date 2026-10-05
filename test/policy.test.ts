import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { auditConfig } from "../src/audit.js";
import { applyPolicy, auditPolicy, matchesHost, matchesServer, policyFromServers } from "../src/policy.js";
import type { ServerConfig } from "../src/types.js";

const s = (name: string, scope: ServerConfig["scope"] = "project", extra: Partial<ServerConfig> = {}): ServerConfig => ({ name, scope, source: "/p/.mcp.json", ...extra });
const rules = (fs: { rule: string }[]) => fs.map((f) => f.rule);
const pol = (policy: object) => ({ policy, sources: ["/p/.mcp-security.json"] });

describe("policy", () => {
  it("matches names, scopes and globs", () => {
    expect(matchesServer(s("github"), "github")).toBe(true);
    expect(matchesServer(s("github"), "user:github")).toBe(false);
    expect(matchesServer(s("cloudflare:docs", "plugin"), "plugin:cloudflare:*")).toBe(true);
    expect(matchesHost("https://docs.mcp.cloudflare.com/mcp", ["*.cloudflare.com"])).toBe(true);
    expect(matchesHost("https://evil.example/cloudflare.com", ["*.cloudflare.com"])).toBe(false);
  });

  it("flags unapproved, blocked and disallowed-host servers", () => {
    const servers = [s("github"), s("random"), s("bad"), s("remote", "project", { url: "https://evil.example/mcp" })];
    const fs = auditPolicy(servers, pol({ allowedServers: ["github", "remote"], blockedServers: ["bad"], allowedRemoteHosts: ["mcp.vercel.com"] }));
    expect(fs.map((f) => [f.server, f.rule])).toEqual([
      ["random", "policy/unapproved-server"],
      ["bad", "policy/blocked-server"],
      ["remote", "policy/remote-host-not-allowed"],
    ]);
  });

  it("raises unpinned packages to high when required", () => {
    const f = { severity: "medium" as const, rule: "config/unpinned-package", title: "x", location: "", remediation: "" };
    expect(applyPolicy([f], pol({ requirePinnedVersions: true }))[0].severity).toBe("high");
    expect(applyPolicy([f], undefined)[0].severity).toBe("medium");
  });

  it("is picked up from the project by auditConfig, and a generated policy approves the current state", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpsec-pol-"));
    writeFileSync(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { ok: { command: "x" }, sneaky: { command: "y" } } }));
    writeFileSync(join(dir, ".mcp-security.json"), JSON.stringify({ allowedServers: ["ok"] }));
    const { findings, servers } = auditConfig(dir, { projectOnly: true });
    expect(rules(findings)).toEqual(["policy/unapproved-server"]);
    expect(auditPolicy(servers, pol(policyFromServers(servers)))).toEqual([]);
  });

  it("reports an unreadable policy instead of silently allowing everything", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpsec-pol-"));
    writeFileSync(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: {} }));
    writeFileSync(join(dir, ".mcp-security.json"), "{ not json");
    expect(rules(auditConfig(dir, { projectOnly: true }).findings)).toEqual(["policy/unreadable"]);
  });
});
