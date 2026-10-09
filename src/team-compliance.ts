// `team compliance`: an evidence report for the organisation, built from what the service already holds
// (the central policy, the latest fleet report of every member, the approval log). Nothing new is collected,
// and the report is written locally by the admin's CLI; the service stores no report.
import { excerpt } from "./sanitize.js";
import type { ApprovalView, InventoryPlugin, InventoryServer, TeamPolicyAnswer, Violation } from "./team.js";

export interface FleetMember {
  label: string | null;
  reportedAt: string;
  servers: InventoryServer[];
  plugins: InventoryPlugin[];
  violations: Violation[];
}
export interface ComplianceInput {
  org: string;
  policy: TeamPolicyAnswer;
  members: FleetMember[];
  approvals: ApprovalView[];
  seatsUsed?: number;
  seats?: number | null;
  now: Date;
}

const DAY = 86_400_000;
const pct = (n: number, d: number) => (d ? `${Math.round((n / d) * 100)}%` : "n/a");
const cell = (s: string, n = 60) => excerpt(s, n).replace(/\|/g, "/");

export function complianceReport(i: ComplianceInput): string {
  const { policy: pa, members, approvals, now } = i;
  const p = pa.policy;
  const age = (m: FleetMember) => Math.floor((now.getTime() - Date.parse(m.reportedAt)) / DAY);
  const stale = members.filter((m) => age(m) > 30);
  const servers = members.flatMap((m) => m.servers);
  const pinned = servers.filter((s) => s.pinned).length;
  const pkgs = servers.filter((s) => s.package);
  const unpinnedPkgs = pkgs.filter((s) => !s.package!.version);
  const violations = members.flatMap((m) => m.violations.map((v) => ({ ...v, who: m.label ?? "unnamed" })));
  const byReason = (r: Violation["reason"]) => violations.filter((v) => v.reason === r).length;
  const status = (s: ApprovalView["status"]) => approvals.filter((a) => a.status === s);
  const pending = status("pending");
  const state = (ok: boolean) => (ok ? "met" : "gap");

  const controls: [string, string, string, string][] = [
    ["MCP09", "Shadow MCP servers", p?.allowedServers?.length ? state(byReason("not-approved") === 0) : "gap", p?.allowedServers?.length ? `${p.allowedServers.length} allowed pattern(s); ${byReason("not-approved")} unapproved server(s) in use` : "No allow list in the central policy"],
    ["MCP09", "Blocked servers and plugins", p?.blockedServers?.length || p?.blockedPlugins?.length ? state(byReason("blocked") === 0) : "info", `${p?.blockedServers?.length ?? 0} blocked server pattern(s), ${p?.blockedPlugins?.length ?? 0} blocked plugin(s); ${byReason("blocked")} in use`],
    ["MCP07", "Approved remote hosts", p?.allowedRemoteHosts?.length ? state(byReason("host-not-allowed") === 0) : "gap", p?.allowedRemoteHosts?.length ? `${p.allowedRemoteHosts.length} allowed host(s); ${byReason("host-not-allowed")} server(s) on other hosts` : "No host allow list"],
    ["MCP04", "Pinned package versions", state(unpinnedPkgs.length === 0 && pkgs.length > 0), `${pkgs.length - unpinnedPkgs.length} of ${pkgs.length} npm/PyPI server(s) pinned to a version${p?.requirePinnedVersions ? "; required by policy" : "; not required by policy"}`],
    ["MCP03", "Rug-pull detection (tool pinning)", state(servers.length > 0 && pinned === servers.length), `${pinned} of ${servers.length} server entries pinned (${pct(pinned, servers.length)})`],
    ["-", "Fleet reporting is current", state(members.length > 0 && stale.length === 0), `${members.length} member(s) reported; ${stale.length} report(s) older than 30 days`],
    ["-", "Approval requests decided", state(pending.length === 0), `${pending.length} pending, ${status("approved").length} approved, ${status("rejected").length} rejected`],
  ];

  const lines = [
    `# MCP security compliance evidence: ${cell(i.org, 80)}`,
    "",
    `Generated ${now.toISOString()} by mcp-security-guard from the organisation's policy (version ${pa.version}, updated ${pa.updatedAt ?? "never"}), the latest report of each member and the approval log. Fleet data is what members reported with their consent: server and plugin names and versions only. This is evidence of configuration, not a certification.`,
    "",
    "## Summary",
    "",
    `- Fleet visibility: **${pa.fleetVisibility ? "on" : "off"}**${pa.fleetVisibility ? "" : " (no member reports are accepted, so the sections below are empty)"}`,
    `- Members reporting: **${members.length}**${i.seatsUsed !== undefined ? ` of ${i.seatsUsed} active key(s)${i.seats ? `, ${i.seats} seat(s)` : ""}` : ""}`,
    `- Distinct servers in use: **${new Set(servers.map((s) => `${s.scope}:${s.name}`)).size}**, plugins: **${new Set(members.flatMap((m) => m.plugins.map((x) => x.name))).size}**`,
    `- Policy violations: **${violations.length}**`,
    "",
    "## Controls",
    "",
    "| OWASP | Control | Status | Evidence |",
    "|---|---|---|---|",
    ...controls.map(([id, name, st, ev]) => `| ${id} | ${name} | ${st} | ${cell(ev, 160)} |`),
  ];
  if (violations.length) {
    lines.push("", "## Violations", "", "| Member | Kind | Name | Reason |", "|---|---|---|---|", ...violations.slice(0, 100).map((v) => `| ${cell(v.who, 40)} | ${v.kind} | ${cell(v.name, 60)} | ${v.reason} |`));
    if (violations.length > 100) lines.push("", `… and ${violations.length - 100} more.`);
  }
  if (stale.length) lines.push("", "## Members that have not reported in 30 days", "", ...stale.map((m) => `- ${cell(m.label ?? "unnamed", 40)}: ${age(m)} days ago`));
  if (pending.length) lines.push("", "## Pending approvals", "", ...pending.map((a) => `- ${a.kind} ${cell(a.identity, 80)}, requested ${a.createdAt.slice(0, 10)}${a.requestedBy ? ` by ${cell(a.requestedBy, 40)}` : ""}`));
  lines.push("");
  return lines.join("\n");
}
