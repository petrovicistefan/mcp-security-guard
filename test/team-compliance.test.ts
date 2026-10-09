import { describe, expect, it } from "vitest";
import { runTeam } from "../src/team-cli.js";
import { complianceReport, type ComplianceInput } from "../src/team-compliance.js";
import type { TeamFetcher } from "../src/team.js";

const now = new Date("2026-10-09T00:00:00Z");
const input = (over: Partial<ComplianceInput> = {}): ComplianceInput => ({
  org: "Acme",
  policy: { org: { name: "Acme" }, role: "admin", version: 3, updatedAt: "2026-10-01T00:00:00Z", fleetVisibility: true, policy: { allowedServers: ["github"], allowedRemoteHosts: ["mcp.github.com"], blockedPlugins: ["evil"], requirePinnedVersions: true } },
  members: [
    { label: "ana", reportedAt: "2026-10-08T00:00:00Z", servers: [{ name: "github", scope: "user", transport: "stdio", package: { ecosystem: "npm", name: "gh-mcp", version: "1.2.3" }, pinned: true }], plugins: [{ name: "vercel", version: "1" }], violations: [] },
    { label: "bob|x", reportedAt: "2026-08-01T00:00:00Z", servers: [{ name: "scraper", scope: "user", transport: "stdio", package: { ecosystem: "npm", name: "scr" }, pinned: false }], plugins: [], violations: [{ kind: "server", name: "user:scraper", reason: "not-approved" }] },
  ],
  approvals: [{ id: "a1", kind: "server", identity: "user:scraper", status: "pending", requestedBy: "bob", note: null, createdAt: "2026-10-02T00:00:00Z", decidedAt: null, decisionNote: null }],
  now,
  ...over,
});

describe("team compliance report", () => {
  it("states controls from the policy, the fleet and the approval log", () => {
    const md = complianceReport(input());
    expect(md).toContain("# MCP security compliance evidence: Acme");
    expect(md).toContain("| MCP09 | Shadow MCP servers | gap |");
    expect(md).toContain("1 unapproved server(s) in use");
    expect(md).toContain("| MCP04 | Pinned package versions | gap | 1 of 2");
    expect(md).toContain("| MCP03 | Rug-pull detection (tool pinning) | gap | 1 of 2 server entries pinned (50%)");
    expect(md).toContain("1 report(s) older than 30 days");
    expect(md).toContain("## Pending approvals");
    expect(md).toContain("bob/x");
    expect(md).not.toContain("bob|x");
  });

  it("marks controls met when the fleet is clean", () => {
    const md = complianceReport(input({ members: [input().members[0]], approvals: [] }));
    expect(md).toMatch(/\| MCP09 \| Shadow MCP servers \| met \|/);
    expect(md).toMatch(/\| MCP04 \| Pinned package versions \| met \|/);
    expect(md).not.toContain("## Violations");
  });

  it("says so when there is no allow list or fleet data", () => {
    const md = complianceReport(input({ members: [], policy: { ...input().policy, policy: null, fleetVisibility: false } }));
    expect(md).toContain("No allow list in the central policy");
    expect(md).toContain("no member reports are accepted");
  });

  it("is built by `team compliance` from the service's answers", async () => {
    const i = input();
    const answers: Record<string, unknown> = {
      "/v1/team/inventory": { members: i.members, servers: [], violationCount: 1 },
      "/v1/team/approvals": { approvals: i.approvals },
      "/v1/team/policy": i.policy,
      "/v1/team/keys": { seats: 5, used: 2, keys: [] },
      "/v1/team/settings": { name: "Acme", fleetVisibility: true, webhookConfigured: false },
    };
    const seen: string[] = [];
    const fetcher: TeamFetcher = async (url) => {
      const path = new URL(url).pathname;
      seen.push(path);
      return path in answers ? { ok: true, status: 200, json: async () => answers[path] } : { ok: false, status: 404, json: async () => ({}) };
    };
    const r = await runTeam({ sub: "compliance", rest: [], project: ".", dryRun: false }, { apiKey: "mcps_test", endpoint: "https://api.example.test", fetcher });
    expect(r.code).toBe(0);
    expect(r.text).toContain("Members reporting: **2** of 2 active key(s), 5 seat(s)");
    expect(new Set(seen).size).toBe(5);
    const denied = await runTeam({ sub: "compliance", rest: [], project: "." , dryRun: false}, { apiKey: "mcps_test", endpoint: "https://api.example.test", fetcher: async () => ({ ok: false, status: 403, json: async () => ({ error: "admin key required" }) }) });
    expect(denied).toEqual({ text: "team: admin key required", code: 1 });
  });
});
