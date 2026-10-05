import { describe, expect, it } from "vitest";
import { checkSupplyChain, packagesOf, typosquatOf, type Fetcher } from "../src/supply-chain.js";
import type { ServerConfig } from "../src/types.js";

const NOW = Date.parse("2026-10-05T00:00:00Z");
const days = (n: number) => new Date(NOW - n * 86_400_000).toISOString();
const srv = (name: string, command: string, args: string[]): ServerConfig => ({ name, scope: "project", source: "/p/.mcp.json", command, args });

/** Fake registries + OSV keyed by URL. */
function fakeFetch(routes: Record<string, unknown>, osv: Record<string, { id: string; [k: string]: unknown }[]> = {}): Fetcher {
  return async (url, init) => {
    if (url === "https://api.osv.dev/v1/querybatch") {
      const queries = JSON.parse(init!.body!).queries as { package: { name: string }; version: string }[];
      return { ok: true, status: 200, json: async () => ({ results: queries.map((q) => ({ vulns: (osv[`${q.package.name}@${q.version}`] ?? []).map((v) => ({ id: v.id })) })) }) };
    }
    const vuln = /\/v1\/vulns\/(.+)$/.exec(url);
    if (vuln) {
      const v = Object.values(osv).flat().find((x) => x.id === decodeURIComponent(vuln[1]));
      return { ok: true, status: 200, json: async () => v };
    }
    const body = routes[url];
    return body ? { ok: true, status: 200, json: async () => body } : { ok: false, status: 404, json: async () => ({}) };
  };
}

const npmDoc = (name: string, versions: Record<string, { at: string; by: string; scripts?: Record<string, string> }>, created: string) => ({
  name,
  "dist-tags": { latest: Object.keys(versions).at(-1) },
  time: { created, ...Object.fromEntries(Object.entries(versions).map(([v, x]) => [v, x.at])) },
  versions: Object.fromEntries(Object.entries(versions).map(([v, x]) => [v, { _npmUser: { name: x.by }, scripts: x.scripts ?? {} }])),
});

describe("package extraction", () => {
  it("reads npm and PyPI specs and skips git/local sources", () => {
    expect(packagesOf(srv("a", "npx", ["-y", "@scope/pkg@1.2.3"]))).toMatchObject([{ ecosystem: "npm", name: "@scope/pkg", version: "1.2.3" }]);
    expect(packagesOf(srv("b", "npx", ["pkg@latest"]))).toMatchObject([{ ecosystem: "npm", name: "pkg", version: undefined }]);
    expect(packagesOf(srv("c", "uvx", ["mcp-server-git==2026.8.18"]))).toMatchObject([{ ecosystem: "PyPI", name: "mcp-server-git", version: "2026.8.18" }]);
    expect(packagesOf(srv("d", "uvx", ["--from", "git+https://github.com/x/y", "y"]))).toEqual([]);
    expect(packagesOf(srv("e", "node", ["server.js"]))).toEqual([]);
  });

  it("detects typosquats of popular MCP packages", () => {
    const ref = (name: string) => ({ ...packagesOf(srv("x", "npx", [name]))[0] });
    expect(typosquatOf(ref("@modelcontextprotocol/server-githbu"))).toBe("@modelcontextprotocol/server-github");
    expect(typosquatOf(ref("@modelcontext/server-github"))).toBe("@modelcontextprotocol/server-github");
    expect(typosquatOf(ref("@modelcontextprotocol/server-github"))).toBeUndefined();
    expect(typosquatOf(ref("some-unrelated-package"))).toBeUndefined();
  });
});

describe("registry and OSV checks", () => {
  it("reports new packages, install scripts, publisher changes, vulnerabilities and malicious versions", async () => {
    const fetcher = fakeFetch(
      {
        "https://registry.npmjs.org/fresh-mcp": npmDoc("fresh-mcp", { "1.0.0": { at: days(5), by: "alice" } }, days(5)),
        "https://registry.npmjs.org/old-mcp": npmDoc("old-mcp", { "1.0.0": { at: days(400), by: "alice" }, "1.1.0": { at: days(10), by: "mallory", scripts: { postinstall: "node x.js" } } }, days(400)),
      },
      { "old-mcp@1.1.0": [{ id: "GHSA-aaaa", summary: "RCE", database_specific: { severity: "HIGH" } }, { id: "MAL-2026-1" }] },
    );
    const r = await checkSupplyChain([srv("fresh", "npx", ["fresh-mcp@1.0.0"]), srv("old", "npx", ["old-mcp"])], fetcher, NOW);
    const by = (server: string) => r.findings.filter((f) => f.server === server).map((f) => `${f.severity} ${f.rule}`).sort();
    expect(by("fresh")).toEqual(["medium supply-chain/new-package"]);
    expect(by("old")).toEqual([
      "critical supply-chain/malicious-package",
      "high supply-chain/known-vulnerability",
      "medium supply-chain/install-scripts",
      "medium supply-chain/publisher-changed",
    ]);
    expect(r.errors).toEqual([]);
  });

  it("flags names that do not exist and keeps going when a lookup fails", async () => {
    const failing: Fetcher = async (url) => (url.includes("pypi.org") ? Promise.reject(new Error("offline")) : fakeFetch({})(url));
    const r = await checkSupplyChain([srv("ghost", "npx", ["ghost-mcp-zzz"]), srv("py", "uvx", ["mcp-server-time"])], failing, NOW);
    expect(r.findings.map((f) => f.rule)).toEqual(["supply-chain/package-not-found"]);
    expect(r.errors.join()).toContain("offline");
  });
});
