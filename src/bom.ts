// Agent bill of materials (AI-BOM): a CycloneDX 1.6 inventory of what the agent can run and read here:
// MCP servers, plugins, skills, commands, subagents, CLAUDE.md and hook configs, with hashes, pin status,
// scores and finding counts. Static and local: nothing is launched, nothing is sent.
// Privacy: names, scopes, package coordinates, remote hostnames and file hashes only. Never paths outside
// the origin's own root, arguments, environment, headers, URL paths or query strings, file contents.
import { randomUUID } from "node:crypto";
import { auditConfig } from "./audit.js";
import { transportOf } from "./config.js";
import { auditContext } from "./context-audit.js";
import { contextDrift, loadContextPins } from "./context-pins.js";
import { owaspFor, OWASP_MCP } from "./owasp.js";
import { loadPins, pinKey } from "./pins.js";
import { scoreServer } from "./score.js";
import { packagesOf } from "./supply-chain.js";
import { SEVERITY_ORDER, type Finding, type Severity } from "./types.js";
import { VERSION } from "./version.js";

type Prop = { name: string; value: string };
export interface BomComponent {
  "bom-ref": string;
  type: "application" | "service" | "file";
  name: string;
  version?: string;
  purl?: string;
  hashes?: { alg: "SHA-256"; content: string }[];
  endpoints?: string[];
  properties: Prop[];
}
export interface Bom {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  serialNumber: string;
  version: 1;
  metadata: { timestamp: string; tools: { components: { type: "application"; name: string; version: string }[] }; properties: Prop[] };
  components: BomComponent[];
}

const prop = (name: string, value: string | number | boolean): Prop => ({ name: `mcp-security-guard:${name}`, value: String(value) });
const clean = (s: string) => s.replace(/[^A-Za-z0-9_.:@/ -]/g, "_").slice(0, 200);

function counts(findings: Finding[]): Record<Severity, number> {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}
const countProps = (findings: Finding[]): Prop[] => {
  const c = counts(findings);
  const owasp = [...new Set(findings.flatMap((f) => owaspFor(f.rule)))].sort();
  return [...SEVERITY_ORDER.map((s) => prop(`findings.${s}`, c[s])), ...(owasp.length ? [prop("owasp", owasp.join(","))] : [])];
};
const purl = (eco: "npm" | "PyPI", name: string, version?: string) => {
  const n = eco === "npm" ? name.replace(/^@/, "%40") : name.toLowerCase().replace(/_/g, "-");
  return `pkg:${eco === "npm" ? "npm" : "pypi"}/${n}${version ? `@${version}` : ""}`;
};
const hostOf = (url?: string) => {
  try {
    const h = url ? new URL(url.replace(/\$\{[^}]+\}/g, "x")).hostname.toLowerCase() : "";
    return /^[a-z0-9.-]{1,253}$/.test(h) ? h : undefined;
  } catch {
    return undefined;
  }
};

export function buildBom(projectDir: string, opts: { home?: string; projectOnly?: boolean; now?: Date; serial?: string } = {}): { bom: Bom; findings: Finding[] } {
  const cfg = auditConfig(projectDir, { projectOnly: opts.projectOnly });
  const ctx = auditContext(projectDir, { projectOnly: opts.projectOnly, home: opts.home });
  const pins = loadPins();
  const ctxPins = loadContextPins();
  const drift = Object.keys(ctxPins.origins).length ? contextDrift(ctx, projectDir, ctxPins) : undefined;
  const components: BomComponent[] = [];
  const used = new Set<string>();
  const ref = (base: string) => {
    let r = base, i = 2;
    while (used.has(r)) r = `${base}#${i++}`;
    used.add(r);
    return r;
  };

  for (const s of cfg.servers) {
    const transport = transportOf(s);
    const own = cfg.findings.filter((f) => f.server === s.name && f.file === s.source);
    const sc = scoreServer(s, cfg.findings, "config");
    const pkg = packagesOf(s)[0];
    const host = hostOf(s.url);
    components.push({
      "bom-ref": ref(`mcp-server:${clean(s.scope)}:${clean(s.name)}`),
      type: transport === "stdio" ? "application" : "service",
      name: clean(s.name),
      ...(pkg?.version ? { version: pkg.version } : {}),
      ...(pkg ? { purl: purl(pkg.ecosystem, pkg.name, pkg.version) } : {}),
      ...(host && transport !== "stdio" ? { endpoints: [`https://${host}`] } : {}),
      properties: [
        prop("kind", "mcp-server"),
        prop("scope", s.scope),
        prop("transport", transport),
        prop("pinned", !!pins.servers[pinKey(s.scope, s.name)]),
        ...(pkg && !pkg.version ? [prop("version-pinned", false)] : []),
        prop("score", sc.score),
        prop("grade", sc.grade),
        prop("score-basis", "config"),
        ...countProps(own),
      ],
    });
  }

  for (const p of ctx.plugins) {
    const origin = `plugin:${p.name}`;
    const own = ctx.findings.filter((f) => ctx.files.some((c) => c.path === f.file && c.origin === origin));
    components.push({
      "bom-ref": ref(`plugin:${clean(p.name)}`),
      type: "application",
      name: clean(p.name),
      ...(p.version ? { version: clean(p.version) } : {}),
      properties: [prop("kind", "claude-plugin"), prop("files", ctx.files.filter((c) => c.origin === origin).length), ...countProps(own)],
    });
  }

  for (const f of ctx.files) {
    const own = ctx.findings.filter((x) => x.file === f.path);
    components.push({
      "bom-ref": ref(`file:${clean(f.origin)}:${clean(f.rel)}`),
      type: "file",
      name: clean(f.rel),
      hashes: [{ alg: "SHA-256", content: f.hash }],
      properties: [prop("kind", f.kind), prop("origin", f.origin.startsWith("project") ? "project" : f.origin), ...countProps(own)],
    });
  }

  const all = [...cfg.findings, ...ctx.findings];
  const c = counts(all);
  const unpinned = components.filter((x) => x.properties.some((p) => p.name.endsWith(":kind") && p.value === "mcp-server") && x.properties.some((p) => p.name.endsWith(":pinned") && p.value === "false") && !x.properties.some((p) => p.name.endsWith(":scope") && p.value === "claude-ai")).length;
  const bom: Bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${opts.serial ?? randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: (opts.now ?? new Date()).toISOString(),
      tools: { components: [{ type: "application", name: "mcp-security-guard", version: VERSION }] },
      properties: [
        prop("scope", opts.projectOnly ? "project-only" : "machine"),
        prop("servers", cfg.servers.length),
        prop("plugins", ctx.plugins.length),
        prop("context-files", ctx.files.length),
        prop("servers-unpinned", unpinned),
        prop("context-drift", drift ? drift.findings.length : "not-pinned"),
        ...SEVERITY_ORDER.map((s) => prop(`findings.${s}`, c[s])),
      ],
    },
    components,
  };
  return { bom, findings: all };
}

/** Evidence summary for audits: inventory counts, posture and OWASP MCP Top 10 findings. Markdown. */
export function bomSummary(bom: Bom, findings: Finding[]): string {
  const meta = Object.fromEntries(bom.metadata.properties.map((p) => [p.name.replace("mcp-security-guard:", ""), p.value]));
  const servers = bom.components.filter((c) => c.properties.some((p) => p.name.endsWith(":kind") && p.value === "mcp-server"));
  const get = (c: BomComponent, k: string) => c.properties.find((p) => p.name === `mcp-security-guard:${k}`)?.value ?? "";
  const rows = (Object.keys(OWASP_MCP) as string[]).sort().map((id) => {
    const n = findings.filter((f) => owaspFor(f.rule).includes(id));
    const worst = SEVERITY_ORDER.find((s) => n.some((f) => f.severity === s));
    return `| ${id} | ${OWASP_MCP[id]} | ${n.length} | ${worst ?? "none"} |`;
  });
  return [
    "# Agent bill of materials",
    "",
    `Generated ${bom.metadata.timestamp} by mcp-security-guard ${VERSION} (${meta.scope}). Static scan; nothing was launched or sent.`,
    "",
    `- MCP servers: **${meta.servers}** (${meta["servers-unpinned"]} not pinned)`,
    `- Plugins: **${meta.plugins}**`,
    `- Skills, commands, subagents, CLAUDE.md, hook configs and scripts: **${meta["context-files"]}** (SHA-256 each)`,
    `- Findings: ${SEVERITY_ORDER.map((s) => `${meta[`findings.${s}`]} ${s}`).join(", ")}`,
    "",
    "## MCP servers",
    "",
    "| Server | Scope | Transport | Package | Pinned | Grade |",
    "|---|---|---|---|---|---|",
    ...servers.map((c) => `| ${c.name} | ${get(c, "scope")} | ${get(c, "transport")} | ${c.purl ?? c.endpoints?.[0] ?? "-"} | ${get(c, "pinned") === "true" ? "yes" : "no"} | ${get(c, "grade")} (${get(c, "score")}) |`),
    "",
    "## OWASP MCP Top 10 evidence",
    "",
    "| ID | Risk | Findings | Worst |",
    "|---|---|---|---|",
    ...rows,
    "",
  ].join("\n");
}
