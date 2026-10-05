import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { discoverServers } from "../src/config.js";
import { applyPlan, describePlan, planEnvRefs, planPermissions, planPinVersions } from "../src/fixes.js";
import type { Fetcher } from "../src/supply-chain.js";

const KEY = "ghp_" + "d".repeat(36);

process.env.MCP_SECURITY_HOME = mkdtempSync(join(tmpdir(), "mcpsec-fix-home-"));

function project(mcp: object, settings?: object): string {
  const dir = mkdtempSync(join(tmpdir(), "mcpsec-fix-"));
  writeFileSync(join(dir, ".mcp.json"), JSON.stringify(mcp, null, 2));
  if (settings) {
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude/settings.json"), JSON.stringify(settings, null, 2));
  }
  return dir;
}
const read = (p: string) => JSON.parse(readFileSync(p, "utf8"));

describe("fixes", () => {
  it("dry run writes nothing; write merges ask rules and keeps existing settings", () => {
    const dir = project({ mcpServers: {} }, { model: "x", permissions: { allow: ["Bash(ls)"], ask: ["mcp__a__old"], deny: ["mcp__fs__rm"] } });
    const plan = planPermissions(dir, ["mcp__a__old", "mcp__fs__rm", "mcp__fs__write_file"]);
    expect(plan.changes[0].edits).toEqual(['permissions.ask += "mcp__fs__write_file"']);
    expect(read(join(dir, ".claude/settings.json")).permissions.ask).toEqual(["mcp__a__old"]);
    const r = applyPlan(plan);
    const s = read(join(dir, ".claude/settings.json"));
    expect(s).toEqual({ model: "x", permissions: { allow: ["Bash(ls)"], ask: ["mcp__a__old", "mcp__fs__write_file"], deny: ["mcp__fs__rm"] } });
    expect(existsSync(r.backups[0])).toBe(true);
    // Backups never land inside the project, where they could be committed.
    expect(r.backups[0].startsWith(dir)).toBe(false);
    expect(readdirSync(dir).filter((n) => n.includes("backup"))).toEqual([]);
  });

  it("creates .claude/settings.json when missing", () => {
    const dir = project({ mcpServers: {} });
    applyPlan(planPermissions(dir, ["mcp__x__exec"]));
    expect(read(join(dir, ".claude/settings.json"))).toEqual({ permissions: { ask: ["mcp__x__exec"] } });
  });

  it("pins npx and uvx packages to the registry version", async () => {
    const dir = project({ mcpServers: { a: { command: "npx", args: ["-y", "@s/pkg@latest"] }, b: { command: "uvx", args: ["tool"] }, c: { command: "npx", args: ["done@1.0.0"] } } });
    const fetcher: Fetcher = async (url) => ({ ok: true, status: 200, json: async () => (url.includes("npmjs") ? { "dist-tags": { latest: "2.3.4" } } : { info: { version: "1.2.0" } }) });
    const plan = await planPinVersions(dir, discoverServers(dir, dir).servers, fetcher);
    applyPlan(plan);
    const m = read(join(dir, ".mcp.json")).mcpServers;
    expect([m.a.args, m.b.args, m.c.args]).toEqual([["-y", "@s/pkg@2.3.4"], ["tool==1.2.0"], ["done@1.0.0"]]);
  });

  it("replaces literal secrets with references and never prints them", () => {
    const dir = project({ mcpServers: { gh: { command: "x", env: { GITHUB_TOKEN: KEY, OTHER: "${OK}" }, headers: { Authorization: `Bearer ${KEY}` } } } });
    const plan = planEnvRefs(dir);
    expect(describePlan(plan)).not.toContain(KEY);
    const r = applyPlan(plan);
    const s = read(join(dir, ".mcp.json")).mcpServers.gh;
    expect(s.env).toEqual({ GITHUB_TOKEN: "${GH_GITHUB_TOKEN}", OTHER: "${OK}" });
    expect(s.headers.Authorization).toBe("Bearer ${GH_AUTHORIZATION}");
    // The backup keeps the secret so nothing is lost, readable by the owner only.
    expect(readFileSync(r.backups[0], "utf8")).toContain(KEY);
    if (process.platform !== "win32") expect(statSync(r.backups[0]).mode & 0o777).toBe(0o600);
    expect(describePlan(plan, r)).toContain("still contains the secret");
  });
});
