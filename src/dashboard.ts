// Data for the interactive dashboard (MCP App). Built from the same audits as the text reports, so the
// board and the reports can never disagree.
import { auditConfig } from "./audit.js";
import { recommendPermissions } from "./capabilities.js";
import { transportOf } from "./config.js";
import { OWASP_MCP, owaspFor } from "./owasp.js";
import { loadPins, pinKey } from "./pins.js";
import { scoreServer } from "./score.js";
import { auditTools, surfaceCounts } from "./tool-audit.js";
import { SEVERITY_ORDER, type Finding, type Severity } from "./types.js";
import { excerpt } from "./sanitize.js";
import { VERSION } from "./version.js";

export const DASHBOARD_URI = "ui://mcp-security-guard/dashboard.html";
export const DASHBOARD_MIME = "text/html;profile=mcp-app";

export interface DashboardServer {
  /** `scope:name`, the selector the other tools accept. */
  key: string;
  name: string;
  scope: string;
  transport: string;
  score: number | null;
  grade: string | null;
  basis: "config" | "config+tools";
  counts: Record<Severity, number>;
  pinned: boolean;
  /** Set when a full scan could not connect. */
  error?: string;
}

export interface DashboardFinding {
  severity: Severity;
  rule: string;
  title: string;
  location: string;
  evidence?: string;
  remediation: string;
  server?: string;
  owasp: string[];
}

export interface DashboardData {
  version: string;
  generatedAt: string;
  mode: "config" | "full";
  summary: Record<Severity, number>;
  servers: DashboardServer[];
  findings: DashboardFinding[];
  owasp: { id: string; name: string; count: number }[];
  /** Recommended permissions.ask rules (full scans only). */
  permissions: string[];
  notes: string[];
}

const zero = (): Record<Severity, number> => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

function countBy(findings: Finding[]): Record<Severity, number> {
  const c = zero();
  for (const f of findings) c[f.severity]++;
  return c;
}

/**
 * `config` reads files only. `full` also starts every launchable server to list its tools, prompts and
 * resources (the caller must have the user's consent).
 */
export async function buildDashboard(projectDir: string, mode: "config" | "full"): Promise<DashboardData> {
  const config = auditConfig(projectDir);
  const pins = loadPins();
  let findings = config.findings;
  const notes: string[] = [];
  let permissions: string[] = [];
  const errors = new Map<string, string>();
  const scanned = new Set<string>();

  if (mode === "full") {
    const launchable = config.servers.filter((s) => s.scope !== "claude-ai");
    const audit = await auditTools(launchable, 20, pins, config.policy);
    // auditTools re-runs the config rules for the servers it scans; keep the config findings of the rest.
    const covered = new Set(launchable.map((s) => `${s.scope}:${s.name}`));
    findings = [...config.findings.filter((f) => !config.servers.some((s) => s.name === f.server && s.source === f.file && covered.has(`${s.scope}:${s.name}`))), ...audit.findings];
    for (const r of audit.ok) scanned.add(`${r.server.scope}:${r.server.name}`);
    for (const e of audit.errors) errors.set(`${e.server.scope}:${e.server.name}`, e.error);
    permissions = recommendPermissions(audit.inventories).ask;
    notes.push(`Scanned ${audit.ok.length} server(s): ${surfaceCounts(audit.ok).replace(/\*\*/g, "")}.`);
    if (audit.cloudNote) notes.push(audit.cloudNote);
  } else {
    notes.push("Configuration only: tool definitions were not checked. Run a full scan to include tool poisoning, capabilities and drift.");
  }

  const servers: DashboardServer[] = config.servers.map((s) => {
    const key = `${s.scope}:${s.name}`;
    const own = findings.filter((f) => f.server === s.name && f.file === s.source);
    const scored = s.scope === "claude-ai" ? undefined : scoreServer(s, findings, scanned.has(key) ? "config+tools" : "config");
    return {
      key,
      name: s.name,
      scope: s.scope,
      transport: transportOf(s),
      score: scored?.score ?? null,
      grade: scored?.grade ?? null,
      basis: scanned.has(key) ? "config+tools" : "config",
      counts: countBy(own),
      pinned: !!pins.servers[pinKey(s.scope, s.name)],
      ...(errors.has(key) ? { error: errors.get(key) } : {}),
    };
  });

  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    mode,
    summary: countBy(findings),
    servers: servers.sort((a, b) => (a.score ?? 101) - (b.score ?? 101)),
    findings: sorted.map((f) => ({ severity: f.severity, rule: f.rule, title: f.title, location: f.location, evidence: f.evidence, remediation: f.remediation, server: f.server, owasp: owaspFor(f.rule) })),
    owasp: Object.entries(OWASP_MCP).map(([id, name]) => ({ id, name, count: findings.filter((f) => owaspFor(f.rule).includes(id)).length })),
    permissions,
    notes,
  };
}

/** Short text version for hosts that do not render MCP Apps (e.g. Claude Code in a terminal), and for the model. */
export function dashboardText(d: DashboardData): string {
  const s = d.summary;
  const worst = d.servers.filter((x) => x.score !== null).slice(0, 5).map((x) => `${excerpt(x.name, 50)} (${x.scope}) ${x.score}/${x.grade}`);
  return [
    `mcp-security-guard dashboard (${d.mode === "full" ? "full scan" : "configuration only"}): ${d.servers.length} server(s), ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low.`,
    worst.length ? `Lowest scores: ${worst.join(", ")}.` : "",
    ...d.notes,
    "Hosts that support MCP Apps (Claude Desktop, claude.ai) show the interactive dashboard; elsewhere use audit_mcp_config / audit_server_tools for the full report.",
  ]
    .filter(Boolean)
    .join("\n");
}
