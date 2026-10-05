// Supply-chain checks for MCP servers launched from npm or PyPI (OWASP MCP04). This is the only
// module that talks to the network: it sends package names and versions to registry.npmjs.org,
// pypi.org and api.osv.dev, and nothing else.
import { NODE_RUNNERS, PY_RUNNERS, baseCommand, packageSpec } from "./rules/config-rules.js";
import { excerpt } from "./sanitize.js";
import type { Finding, ServerConfig, Severity } from "./types.js";

export type Ecosystem = "npm" | "PyPI";

export interface PackageRef {
  server: ServerConfig;
  ecosystem: Ecosystem;
  name: string;
  /** Exact version when pinned, otherwise undefined (the registry's latest is checked). */
  version?: string;
}

export type Fetcher = (url: string, init?: { method?: string; body?: string; headers?: Record<string, string> }) => Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

const DAY = 86_400_000;

/** Well-known MCP packages: a name one or two edits away from one of these is a typosquat candidate. */
export const POPULAR_PACKAGES: Record<Ecosystem, string[]> = {
  npm: [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-google-maps",
    "@playwright/mcp",
    "@upstash/context7-mcp",
    "@notionhq/notion-mcp-server",
    "@supabase/mcp-server-supabase",
    "@stripe/mcp",
    "@sentry/mcp-server",
    "@browsermcp/mcp",
    "mcp-remote",
    "firebase-tools",
    "figma-developer-mcp",
    "exa-mcp-server",
    "tavily-mcp",
  ],
  PyPI: ["mcp-server-git", "mcp-server-fetch", "mcp-server-time", "mcp-server-sqlite", "mcp", "fastmcp"],
};

/** Packages launched by npx/bunx/pnpx/npm exec or uvx/pipx. Git and local paths are skipped. */
export function packagesOf(s: ServerConfig): PackageRef[] {
  if (!s.command) return [];
  const cmd = baseCommand(s.command);
  const args = s.args ?? [];
  const isNode = NODE_RUNNERS.has(cmd) || ((cmd === "npm" || cmd === "pnpm") && (args[0] === "exec" || args[0] === "dlx"));
  const isPy = PY_RUNNERS.has(cmd);
  const spec = (isNode || isPy) && packageSpec(args);
  if (!spec || /^(git\+|https?:|ssh:|github:|file:|\.|\/)/.test(spec)) return [];
  if (isNode) {
    const m = /^(@[^/@]+\/[^@]+|[^@]+)(?:@(.+))?$/.exec(spec);
    if (!m) return [];
    const v = m[2];
    return [{ server: s, ecosystem: "npm", name: m[1], version: v && /^\d+\.\d+\.\d+/.test(v) ? v : undefined }];
  }
  const m = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:(?:==|@)([0-9][^\s;]*))?$/.exec(spec);
  return m ? [{ server: s, ecosystem: "PyPI", name: m[1], version: m[2] }] : [];
}

function editDistance(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

export function typosquatOf(p: PackageRef): string | undefined {
  const name = p.name.toLowerCase();
  const popular = POPULAR_PACKAGES[p.ecosystem];
  if (popular.includes(name)) return undefined;
  // Same unscoped name under a different scope (e.g. @modelcontext/server-github) is also suspicious.
  const unscoped = name.replace(/^@[^/]+\//, "");
  return popular.find((q) => {
    const dist = editDistance(name, q);
    const qUnscoped = q.replace(/^@[^/]+\//, "");
    return (dist > 0 && dist <= (q.length > 12 ? 2 : 1)) || (q.startsWith("@") && name !== q && unscoped === qUnscoped);
  });
}

function osvSeverity(vuln: any): Severity {
  if (String(vuln?.id ?? "").startsWith("MAL-")) return "critical";
  const s = String(vuln?.database_specific?.severity ?? "").toUpperCase();
  return s === "CRITICAL" ? "critical" : s === "HIGH" ? "high" : s === "LOW" ? "low" : "medium";
}

interface RegistryInfo {
  exists: boolean;
  version?: string;
  created?: number;
  versionPublished?: number;
  installScripts?: string[];
  deprecated?: string;
  publisherChanged?: { from: string; to: string };
}

async function npmInfo(name: string, version: string | undefined, fetcher: Fetcher): Promise<RegistryInfo> {
  const r = await fetcher(`https://registry.npmjs.org/${name.replace("/", "%2f")}`);
  if (r.status === 404) return { exists: false };
  if (!r.ok) throw new Error(`npm registry HTTP ${r.status}`);
  const d = await r.json();
  const v = version ?? d["dist-tags"]?.latest;
  const meta = d.versions?.[v] ?? {};
  const scripts = Object.keys(meta.scripts ?? {}).filter((k) => ["preinstall", "install", "postinstall"].includes(k));
  const ordered = Object.keys(d.time ?? {})
    .filter((k) => d.versions?.[k] && !/-/.test(k))
    .sort((a, b) => Date.parse(d.time[a]) - Date.parse(d.time[b]));
  const prev = ordered[ordered.indexOf(v) - 1];
  const who = (x?: string) => (x ? d.versions?.[x]?._npmUser?.name : undefined);
  const from = who(prev);
  const to = who(v);
  return {
    exists: true,
    version: v,
    created: Date.parse(d.time?.created),
    versionPublished: Date.parse(d.time?.[v]),
    installScripts: scripts,
    deprecated: typeof meta.deprecated === "string" ? meta.deprecated : undefined,
    publisherChanged: from && to && from !== to ? { from, to } : undefined,
  };
}

async function pypiInfo(name: string, version: string | undefined, fetcher: Fetcher): Promise<RegistryInfo> {
  const r = await fetcher(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (r.status === 404) return { exists: false };
  if (!r.ok) throw new Error(`PyPI HTTP ${r.status}`);
  const d = await r.json();
  const v = version ?? d.info?.version;
  const uploads = Object.values<any[]>(d.releases ?? {}).flat().map((f) => Date.parse(f.upload_time_iso_8601));
  const files: any[] = d.releases?.[v] ?? [];
  return {
    exists: true,
    version: v,
    created: uploads.length ? Math.min(...uploads) : undefined,
    versionPublished: files.length ? Math.min(...files.map((f) => Date.parse(f.upload_time_iso_8601))) : undefined,
    deprecated: files.some((f) => f.yanked) ? "yanked" : undefined,
  };
}

/** Query OSV for every package version at once, then fetch details for the hits (capped). */
async function osvVulns(pkgs: { ecosystem: Ecosystem; name: string; version: string }[], fetcher: Fetcher): Promise<any[][]> {
  if (!pkgs.length) return [];
  const r = await fetcher("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ queries: pkgs.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
  });
  if (!r.ok) throw new Error(`OSV HTTP ${r.status}`);
  const results: { vulns?: { id: string }[] }[] = (await r.json()).results ?? [];
  return Promise.all(
    results.map(async (res) =>
      Promise.all(
        (res.vulns ?? []).slice(0, 10).map(async (v) => {
          const d = await fetcher(`https://api.osv.dev/v1/vulns/${encodeURIComponent(v.id)}`);
          return d.ok ? d.json() : { id: v.id };
        }),
      ),
    ),
  );
}

export async function checkSupplyChain(servers: ServerConfig[], fetcher: Fetcher = fetch as unknown as Fetcher, now = Date.now()): Promise<{ findings: Finding[]; checked: PackageRef[]; errors: string[] }> {
  const pkgs = servers.flatMap(packagesOf);
  const findings: Finding[] = [];
  const errors: string[] = [];
  const add = (p: PackageRef, severity: Severity, rule: string, title: string, remediation: string, evidence?: string) =>
    findings.push({ severity, rule, title, location: `server "${p.server.name}" (${p.server.scope}) › ${p.ecosystem} ${excerpt(p.name, 80)}`, evidence, remediation, file: p.server.source, server: p.server.name });

  const infos = await Promise.all(
    pkgs.map(async (p) => {
      try {
        return await (p.ecosystem === "npm" ? npmInfo(p.name, p.version, fetcher) : pypiInfo(p.name, p.version, fetcher));
      } catch (e) {
        errors.push(`${p.ecosystem} ${p.name}: ${excerpt(e instanceof Error ? e.message : String(e), 100)}`);
        return undefined;
      }
    }),
  );

  pkgs.forEach((p, i) => {
    const squat = typosquatOf(p);
    if (squat) add(p, "high", "supply-chain/typosquat", `Package name is suspiciously close to the popular "${squat}"`, `Check the name character by character. If you meant "${squat}", fix the config.`);
    const info = infos[i];
    if (!info) return;
    if (!info.exists) {
      add(p, "high", "supply-chain/package-not-found", "Package does not exist on the registry", "Anyone can register this name and get code execution on your machine at the next launch (name squatting / dependency confusion). Fix the name or remove the server.");
      return;
    }
    if (info.created && now - info.created < 30 * DAY) add(p, "medium", "supply-chain/new-package", `Package was first published ${Math.max(1, Math.round((now - info.created) / DAY))} day(s) ago`, "Very new packages have no track record. Prefer established servers, or review the source first.");
    if (info.versionPublished && now - info.versionPublished < 3 * DAY) add(p, "low", "supply-chain/fresh-release", `Version ${excerpt(info.version ?? "?", 30)} was published less than 3 days ago`, "Compromised releases are usually caught within days. Pin the previous version until this one has aged.");
    if (info.installScripts?.length) add(p, "medium", "supply-chain/install-scripts", `Package runs install scripts (${info.installScripts.join(", ")})`, "Install scripts execute before any MCP check can run. Review them, or launch with --ignore-scripts.");
    if (info.deprecated) add(p, "medium", "supply-chain/deprecated", `Version is ${info.deprecated === "yanked" ? "yanked" : "deprecated"}`, "Move to a maintained version or server.", info.deprecated === "yanked" ? undefined : excerpt(info.deprecated, 120));
    if (info.publisherChanged) add(p, "medium", "supply-chain/publisher-changed", `Published by a different npm account than the previous version ("${excerpt(info.publisherChanged.from, 40)}" → "${excerpt(info.publisherChanged.to, 40)}")`, "A new publisher is how account takeovers show up. Confirm the change with the project before upgrading.");
  });

  try {
    const versioned = pkgs.map((p, i) => ({ p, version: p.version ?? infos[i]?.version })).filter((x): x is { p: PackageRef; version: string } => !!x.version && infos[pkgs.indexOf(x.p)]?.exists !== false);
    const vulns = await osvVulns(versioned.map((x) => ({ ecosystem: x.p.ecosystem, name: x.p.name, version: x.version })), fetcher);
    versioned.forEach(({ p, version }, i) => {
      for (const v of vulns[i] ?? []) {
        const malicious = String(v.id).startsWith("MAL-");
        add(p, osvSeverity(v), malicious ? "supply-chain/malicious-package" : "supply-chain/known-vulnerability", malicious ? `Version ${excerpt(version, 30)} is a known MALICIOUS package (${v.id})` : `Version ${excerpt(version, 30)} has a known vulnerability: ${excerpt(v.id, 40)}${v.summary ? ` (${excerpt(v.summary, 100)})` : ""}`, malicious ? "Remove the server immediately and rotate every credential it could reach." : `Upgrade to a fixed version. Details: https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`);
      }
    });
  } catch (e) {
    errors.push(`OSV: ${excerpt(e instanceof Error ? e.message : String(e), 100)}`);
  }
  return { findings, checked: pkgs, errors };
}
