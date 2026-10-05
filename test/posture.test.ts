import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { capabilityFindings, classifyTool, inventory, permissionName, recommendPermissions } from "../src/capabilities.js";
import { owaspFor } from "../src/owasp.js";
import { scoreServer } from "../src/score.js";
import type { Finding, ServerConfig } from "../src/types.js";

const srv = (over: Partial<ServerConfig> = {}): ServerConfig => ({ name: "s", scope: "project", source: "/p/.mcp.json", ...over });

describe("capability classification", () => {
  it.each([
    [{ name: "run_command", inputSchema: { properties: { command: {} } } }, ["command-execution"]],
    [{ name: "execute_sql" }, ["command-execution"]],
    [{ name: "delete_repository" }, ["destructive"]],
    [{ name: "write_file", inputSchema: { properties: { path: {}, content: {} } } }, ["filesystem-write"]],
    [{ name: "fetch", inputSchema: { properties: { url: {} } } }, ["network-egress"]],
    [{ name: "list_issues" }, ["read-only"]],
    [{ name: "svelte-autofixer", description: "Analyzes Svelte code and suggests fixes.", inputSchema: { properties: { code: {} } } }, []],
    [{ name: "run_python", description: "Executes Python code in a sandbox.", inputSchema: { properties: { code: {} } } }, ["command-execution"]],
    [{ name: "terminal_helper", description: "Runs shell commands in the project." }, ["command-execution"]],
    [{ name: "format", description: "Runs the code formatter on a file." }, []],
    [{ name: "remove_label", annotations: { readOnlyHint: true } }, ["read-only"]],
    [{ name: "archive", annotations: { destructiveHint: true } }, ["destructive"]],
  ])("%o", (tool, expected) => expect(classifyTool(tool as any).sort()).toEqual(expected.sort()));

  it("summarises per server and flags unauthenticated remote write access", () => {
    const inv = inventory(srv({ url: "https://x.example/mcp" }), [{ name: "delete_item" }, { name: "list_items" }]);
    const rules = capabilityFindings(inv).map((f) => [f.rule, f.severity]);
    expect(rules).toEqual([["capability/destructive", "low"], ["auth/unauthenticated-write-access", "high"]]);
    const withToken = inventory(srv({ url: "https://x.example/mcp", headers: { Authorization: "Bearer ${T}" } }), [{ name: "delete_item" }]);
    expect(capabilityFindings(withToken).map((f) => f.rule)).not.toContain("auth/unauthenticated-write-access");
  });

  it("builds Claude Code permission names, including plugin namespacing", () => {
    expect(permissionName(srv({ name: "github" }), "create_issue")).toBe("mcp__github__create_issue");
    expect(permissionName(srv({ name: "cloudflare:cloudflare-api", scope: "plugin" }), "deploy")).toBe("mcp__plugin_cloudflare_cloudflare-api__deploy");
    expect(permissionName(srv({ scope: "claude-desktop" }), "x")).toBeUndefined();
    const invs = [inventory(srv({ name: "fs" }), [{ name: "write_file", inputSchema: { properties: { path: {} } } }, { name: "read_file" }])];
    expect(recommendPermissions(invs)).toEqual({ ask: ["mcp__fs__write_file"] });
  });
});

describe("score", () => {
  const s = srv();
  const f = (severity: Finding["severity"], rule = `r/${severity}`): Finding => ({ severity, rule, title: "", location: "", remediation: "", server: s.name, file: s.source });
  it("is 100 without findings and caps by worst severity", () => {
    expect(scoreServer(s, [], "config").score).toBe(100);
    expect(scoreServer(s, [f("medium")], "config")).toMatchObject({ score: 90, grade: "A" });
    expect(scoreServer(s, [f("high")], "config").grade).toBe("D");
    expect(scoreServer(s, [f("critical")], "config").grade).toBe("F");
  });
  it("caps repeated findings of one rule", () => {
    expect(scoreServer(s, Array(10).fill(f("medium", "same")), "config").score).toBe(50);
  });
  it("ignores other servers' findings", () => {
    expect(scoreServer(s, [{ ...f("critical"), server: "other" }], "config").score).toBe(100);
  });
});

describe("OWASP mapping", () => {
  it("maps every rule id used in the sources", () => {
    const src = ["rules/config-rules.ts", "rules/tool-rules.ts", "tool-audit.ts", "capabilities.ts"].map((p) => readFileSync(resolve(__dirname, "../src", p), "utf8")).join("\n");
    const ruleIds = [...new Set([...src.matchAll(/rule: "([a-z-]+\/[a-z-]+)"/g)].map((m) => m[1]))];
    expect(ruleIds.length).toBeGreaterThan(30);
    expect(ruleIds.filter((r) => owaspFor(r).length === 0)).toEqual([]);
  });
});
