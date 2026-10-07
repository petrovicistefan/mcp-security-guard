import { spawnSync, spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { auditContext } from "../src/context-audit.js";
import { auditPluginPolicy, auditPolicy, loadPolicy } from "../src/policy.js";
import { sessionCheck } from "../src/session-check.js";
import { buildInventory, reportInventory, syncTeamPolicy, teamSessionStart, type TeamFetcher } from "../src/team.js";
import { readTeamCache, teamCachePath, writeTeamCache } from "../src/team-cache.js";
import type { ServerConfig } from "../src/types.js";

let root: string;
let home: string;
let project: string;
const saved = { MCP_SECURITY_HOME: process.env.MCP_SECURITY_HOME, HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "mcpsec-team-"));
  home = join(root, "home");
  project = join(root, "project");
  mkdirSync(join(home, ".claude", "plugins"), { recursive: true });
  mkdirSync(project, { recursive: true });
  process.env.MCP_SECURITY_HOME = join(root, "state");
  process.env.HOME = home;
  process.env.USERPROFILE = home;
});
afterEach(() => {
  for (const [k, v] of Object.entries(saved)) v === undefined ? delete process.env[k] : (process.env[k] = v);
});

const write = (path: string, content: string) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
};
const srv = (name: string, over: Partial<ServerConfig> = {}): ServerConfig => ({ name, scope: "project", source: join(project, ".mcp.json"), command: "node", ...over });

/** A fake backend answering GET /v1/team/policy, and counting the calls it gets. */
function backend(answer: { status?: number; body: unknown }) {
  const calls: { method: string; url: string; body?: string; auth?: string }[] = [];
  const fetcher: TeamFetcher = async (url, init) => {
    calls.push({ method: init.method, url, body: init.body, auth: init.headers.authorization });
    return { ok: (answer.status ?? 200) < 300, status: answer.status ?? 200, json: async () => answer.body };
  };
  return { calls, fetcher };
}
const policyAnswer = (policy: object | null, version = 3) => ({ org: { name: "Acme" }, role: "member", policy, version, updatedAt: "2026-10-07T10:00:00Z", fleetVisibility: true });
const opts = (fetcher: TeamFetcher, extra = {}) => ({ apiKey: "mcps_test", endpoint: "https://api.example.test", fetcher, ...extra });

describe("team policy sync", () => {
  it("caches the policy, sends only the key, and enforces it next to the user's own policy", async () => {
    const b = backend({ body: policyAnswer({ allowedServers: ["github"], allowedPlugins: ["vercel"], blockedPlugins: ["bad"] }) });
    const r = await syncTeamPolicy(opts(b.fetcher), true);
    expect(r.status).toBe("synced");
    expect(b.calls).toHaveLength(1);
    expect(b.calls[0]).toMatchObject({ method: "GET", url: "https://api.example.test/v1/team/policy", auth: "Bearer mcps_test" });
    expect(b.calls[0].body).toBeUndefined();
    expect(JSON.stringify(readTeamCache())).not.toContain("mcps_test");

    const loaded = loadPolicy(project)!;
    expect(loaded.team).toMatchObject({ version: 3, org: "Acme" });
    const f = auditPolicy([srv("github"), srv("scraper")], loaded);
    expect(f.map((x) => `${x.rule}:${x.server}`)).toEqual(["policy/unapproved-server:scraper"]);
    expect(f[0].remediation).toContain("team policy of Acme (version 3)");

    const plugins = auditPluginPolicy([{ name: "vercel" }, { name: "bad" }, { name: "other" }], loaded);
    expect(plugins.map((x) => [x.rule, x.severity])).toEqual([["policy/blocked-plugin", "critical"], ["policy/unapproved-plugin", "high"]]);
  });

  it("is not loosened by a project policy that approves more", async () => {
    await syncTeamPolicy(opts(backend({ body: policyAnswer({ allowedServers: ["github"] }) }).fetcher), true);
    write(join(project, ".mcp-security.json"), JSON.stringify({ allowedServers: ["github", "scraper"] }));
    const f = auditPolicy([srv("scraper")], loadPolicy(project));
    expect(f.map((x) => x.rule)).toEqual(["policy/unapproved-server"]);
    expect(f[0].remediation).toContain("team policy");
  });

  it("reports the same finding once when both policies reject a server", async () => {
    await syncTeamPolicy(opts(backend({ body: policyAnswer({ allowedServers: ["github"] }) }).fetcher), true);
    write(join(project, ".mcp-security.json"), JSON.stringify({ allowedServers: ["github"] }));
    expect(auditPolicy([srv("scraper")], loadPolicy(project))).toHaveLength(1);
  });

  it("stays fresh for an hour and then refreshes", async () => {
    const b = backend({ body: policyAnswer({ allowedServers: ["a"] }) });
    let now = new Date("2026-10-07T10:00:00Z");
    const o = opts(b.fetcher, { now: () => now });
    expect((await syncTeamPolicy(o)).status).toBe("synced");
    now = new Date("2026-10-07T10:30:00Z");
    expect((await syncTeamPolicy(o)).status).toBe("fresh");
    now = new Date("2026-10-07T11:01:00Z");
    expect((await syncTeamPolicy(o)).status).toBe("synced");
    expect(b.calls).toHaveLength(2);
  });

  it("remembers that a key is not a team key for a day", async () => {
    const b = backend({ status: 403, body: { error: "this key does not belong to a team" } });
    let now = new Date("2026-10-07T10:00:00Z");
    const o = opts(b.fetcher, { now: () => now });
    expect((await syncTeamPolicy(o)).status).toBe("not-team");
    expect((await syncTeamPolicy(o)).status).toBe("not-team");
    expect(b.calls).toHaveLength(1);
    expect(loadPolicy(project)).toBeUndefined();
    now = new Date("2026-10-08T10:01:00Z");
    await syncTeamPolicy(o);
    expect(b.calls).toHaveLength(2);
  });

  it("keeps enforcing the last policy when the backend is unreachable, and does not hammer it", async () => {
    await syncTeamPolicy(opts(backend({ body: policyAnswer({ allowedServers: ["github"] }) }).fetcher), true);
    const down: TeamFetcher = async () => {
      throw new Error("offline");
    };
    const calls: number[] = [];
    const counting: TeamFetcher = async (u, i) => (calls.push(1), down(u, i));
    let now = new Date(Date.now() + 2 * 3600_000);
    const o = opts(counting, { now: () => now });
    const first = await syncTeamPolicy(o);
    expect(first.status).toBe("skipped");
    expect(first.note).toContain("last synced policy stays in force");
    expect(auditPolicy([srv("scraper")], loadPolicy(project))).toHaveLength(1);
    now = new Date(now.getTime() + 5 * 60_000);
    expect((await syncTeamPolicy(o)).note).toBe("");
    expect(calls).toHaveLength(1);
    now = new Date(now.getTime() + 20 * 60_000);
    await syncTeamPolicy(o);
    expect(calls).toHaveLength(2);
  });

  it("clears the cached policy when the admin removes it", async () => {
    await syncTeamPolicy(opts(backend({ body: policyAnswer({ allowedServers: ["a"] }) }).fetcher), true);
    expect(loadPolicy(project)).toBeDefined();
    await syncTeamPolicy(opts(backend({ body: policyAnswer(null, 0) }).fetcher), true);
    expect(loadPolicy(project)).toBeUndefined();
  });

  it("ignores a damaged cache instead of failing", () => {
    writeTeamCache({ version: 1, fetchedAt: "now", policy: { allowedServers: "nope" as never }, policyVersion: 1 });
    expect(loadPolicy(project)?.team?.policy.allowedServers).toBeUndefined();
    write(teamCachePath(), "{not json");
    expect(loadPolicy(project)).toBeUndefined();
  });

  it("does nothing without a key and never calls the network", async () => {
    const b = backend({ body: {} });
    expect((await syncTeamPolicy({ fetcher: b.fetcher })).status).toBe("skipped");
    expect(await teamSessionStart(project, {}, { fetcher: b.fetcher })).toEqual([]);
    expect(b.calls).toHaveLength(0);
  });

  it("can be switched off for session start", async () => {
    const b = backend({ body: policyAnswer(null) });
    expect(await teamSessionStart(project, { MCP_SECURITY_TEAM_SYNC: "off" }, opts(b.fetcher))).toEqual([]);
    expect(b.calls).toHaveLength(0);
  });
});

describe("team policy in audits and at session start", () => {
  it("flags blocked and unapproved plugins in audit-context and in the session check, without launching anything", async () => {
    const dir = join(root, "cache", "bad", "1.0.0");
    write(join(dir, "skills", "s", "SKILL.md"), "fine\n");
    write(join(home, ".claude", "plugins", "installed_plugins.json"), JSON.stringify({ plugins: { "bad@mk": [{ scope: "user", installPath: dir, version: "1.0.0" }] } }));
    await syncTeamPolicy(opts(backend({ body: policyAnswer({ blockedPlugins: ["bad"] }) }).fetcher), true);
    const a = auditContext(project, { home });
    expect(a.findings.map((f) => f.rule)).toContain("policy/blocked-plugin");
    const { problems } = await sessionCheck(project, "config");
    expect(problems.some((p) => p.includes("block list"))).toBe(true);
  });

  it("counts an MCP-only plugin (no skills) as installed", () => {
    const dir = join(root, "cache", "mcponly", "2.0.0");
    write(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { x: { command: "node" } } }));
    write(join(home, ".claude", "plugins", "installed_plugins.json"), JSON.stringify({ plugins: { "mcponly@mk": [{ scope: "user", installPath: dir, version: "2.0.0" }] } }));
    expect(auditContext(project, { home }).plugins).toEqual([{ name: "mcponly", version: "2.0.0" }]);
  });
});

describe("fleet report", () => {
  it("holds names and versions only, never paths, arguments, environment, headers or query strings", () => {
    write(
      join(project, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          github: { command: "npx", args: ["-y", "@acme/gh@1.2.3", "--token", "ghp_secretsecretsecret", "/home/me/private"], env: { API_KEY: "sk-live-123" } },
          remote: { url: "https://mcp.example.com/path/secret?token=abc", headers: { Authorization: "Bearer xyz" } },
        },
      }),
    );
    const dir = join(root, "cache", "vercel", "0.45.1");
    write(join(dir, "skills", "s", "SKILL.md"), "x\n");
    write(join(home, ".claude", "plugins", "installed_plugins.json"), JSON.stringify({ plugins: { "vercel@mk": [{ scope: "user", installPath: dir, version: "0.45.1" }] } }));
    const report = buildInventory(project, home);
    expect(report.servers.find((s) => s.name === "github")).toMatchObject({ scope: "project", transport: "stdio", package: { ecosystem: "npm", name: "@acme/gh", version: "1.2.3" }, pinned: false });
    expect(report.servers.find((s) => s.name === "remote")).toMatchObject({ transport: "http", host: "mcp.example.com" });
    expect(report.plugins).toEqual([{ name: "vercel", version: "0.45.1" }]);
    const wire = JSON.stringify(report);
    for (const leak of ["ghp_secret", "sk-live", "Bearer xyz", "token=abc", "/path/secret", "/home/me", project, "API_KEY", "Authorization"]) expect(wire).not.toContain(leak);
  });

  it("is refused cleanly while fleet visibility is off", async () => {
    const b = backend({ status: 403, body: { error: "fleet reporting is off for this organization", fleetVisibility: false } });
    const r = await reportInventory(opts(b.fetcher), buildInventory(project, home));
    expect(r).toEqual({ ok: false, status: 403, reason: "fleet reporting is off for this organization" });
  });

  it("is sent at session start only when the user turned it on and the admin allows it", async () => {
    const answers = { body: policyAnswer({ allowedServers: ["x"] }) };
    const a = backend(answers);
    await teamSessionStart(project, {}, opts(a.fetcher));
    expect(a.calls.map((c) => c.method + " " + c.url.split("/v1")[1])).toEqual(["GET /team/policy"]);

    writeTeamCache({ version: 1, fetchedAt: new Date(0).toISOString() });
    const b = backend(answers);
    await teamSessionStart(project, { MCP_SECURITY_TEAM_REPORT: "on" }, opts(b.fetcher));
    expect(b.calls.map((c) => c.method + " " + c.url.split("/v1")[1])).toEqual(["GET /team/policy", "POST /team/inventory"]);
  });
});

describe("team CLI against a stand-in backend", () => {
  let server: Server;
  let base: string;
  const seen: { method: string; url: string; body: string }[] = [];

  beforeEach(async () => {
    seen.length = 0;
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen.push({ method: req.method!, url: req.url!, body });
        const path = req.url!.split("?")[0];
        const send = (status: number, data: unknown) => (res.writeHead(status, { "content-type": "application/json" }), res.end(JSON.stringify(data)));
        if (req.url === "/v1/team/policy" && req.method === "GET") return send(200, { org: { name: "Acme" }, role: "admin", policy: { allowedServers: ["github"] }, version: 4, updatedAt: "x", fleetVisibility: true });
        if (req.url === "/v1/team/approvals" && req.method === "POST") return send(201, { id: "apr_000000000001", status: "pending", alreadyRequested: false });
        if (path === "/v1/team/approvals" && req.method === "GET") return send(200, { approvals: [{ id: "apr_000000000001", kind: "server", identity: "project:linear", status: "pending", requestedBy: "ana", note: "board", createdAt: "x", decidedAt: null, decisionNote: null }] });
        if (req.url === "/v1/team/approvals/apr_000000000001/decision") return send(200, { id: "apr_000000000001", status: "approved", policyVersion: 5 });
        if (req.url === "/v1/team/inventory" && req.method === "POST") return send(200, { policyVersion: 4, violations: [{ kind: "server", name: "user:scraper", reason: "not-approved" }] });
        if (req.url === "/v1/team/policy" && req.method === "PUT") return send(200, { version: 5, updatedAt: "x" });
        return send(404, { error: "not found" });
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterEach(() => new Promise<void>((r) => server.close(() => r())));

  const cli = resolve(__dirname, "../plugin/dist/cli.mjs");
  // The CLI runs in a child process, so the stand-in backend must be served from this one: run it asynchronously.
  const run = (args: string[]) =>
    new Promise<{ status: number | null; stdout: string; stderr: string }>((done) => {
      const c = spawn(process.execPath, [cli, ...args, "--project", project], { env: { ...process.env, HOME: home, USERPROFILE: home, MCP_SECURITY_HOME: join(root, "state"), MCP_SECURITY_API_KEY: "mcps_cli", MCP_SECURITY_API_URL: base } });
      let stdout = "";
      let stderr = "";
      c.stdout.on("data", (d) => (stdout += d));
      c.stderr.on("data", (d) => (stderr += d));
      c.on("close", (status) => done({ status, stdout, stderr }));
    });

  it("status, request, approvals, approve, report and policy-push talk to the right routes", async () => {
    const status = await run(["team", "status"]);
    expect(status.status).toBe(0);
    expect(status.stdout).toContain("Team policy of Acme: version 4");
    expect(status.stdout).toContain("Role: admin");

    expect((await run(["team", "request", "server", "project:linear", "--note", "for the board"])).stdout).toContain("Requested (apr_000000000001)");
    expect(JSON.parse(seen.find((s) => s.method === "POST" && s.url === "/v1/team/approvals")!.body)).toEqual({ kind: "server", identity: "project:linear", note: "for the board" });

    expect((await run(["team", "approvals", "--status", "pending"])).stdout).toContain("apr_000000000001  pending  server project:linear (by ana)");
    expect(seen.some((s) => s.url === "/v1/team/approvals?status=pending")).toBe(true);

    expect((await run(["team", "approve", "apr_000000000001", "--note", "ok"])).stdout).toContain("approved. The policy is now version 5");

    const dry = await run(["team", "report", "--dry-run"]);
    expect(dry.stdout).toContain("Would send");
    expect(seen.some((s) => s.url === "/v1/team/inventory")).toBe(false);
    const rep = await run(["team", "report"]);
    expect(rep.stdout).toContain("1 violation(s)");
    expect(rep.stdout).toContain("server user:scraper: not-approved");

    const file = join(root, "policy.json");
    writeFileSync(file, JSON.stringify({ allowedServers: ["github"] }));
    expect((await run(["team", "policy-push", file])).stdout).toContain("Policy pushed: version 5");
    expect(JSON.parse(seen.find((s) => s.method === "PUT")!.body)).toEqual({ allowedServers: ["github"] });
  });

  it("explains a missing key and a bad command", async () => {
    const c = spawnSync(process.execPath, [cli, "team", "status", "--project", project], { encoding: "utf8", env: { ...process.env, HOME: home, USERPROFILE: home, MCP_SECURITY_HOME: join(root, "state"), MCP_SECURITY_API_KEY: "", MCP_SECURITY_GUARD_FEED_KEY: "" } });
    expect(c.status).toBe(1);
    expect(c.stderr).toContain("no API key");
    expect((await run(["team", "nonsense"])).status).toBe(2);
  });
});
