// `mcp-security-guard team ...`: the Team plan from the command line. Admin actions (approve, reject, policy,
// settings, fleet) exist here only, not as MCP tools, so an injected instruction cannot trigger them.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { excerpt } from "./sanitize.js";
import {
  buildInventory,
  decideApproval,
  fleetInventory,
  getSettings,
  listApprovals,
  pushPolicy,
  putSettings,
  reportInventory,
  requestApproval,
  syncTeamPolicy,
  teamOptionsFromEnv,
  type TeamOptions,
  type TeamResult,
  type Violation,
} from "./team.js";
import { readTeamCache } from "./team-cache.js";

export interface TeamArgs {
  sub: string | undefined;
  rest: string[];
  project: string;
  status?: string;
  note?: string;
  dryRun: boolean;
  fleet?: string;
  webhook?: string;
}

export const TEAM_USAGE = `Team plan (needs a team API key; MCP_SECURITY_API_KEY or the plugin's settings):
  team status                         sync and show your organisation, role and policy version
  team sync                           fetch the organisation's policy now (otherwise hourly, at session start)
  team report [--dry-run]             send your servers and plugins (names and versions only; the admin must have turned fleet visibility on). --dry-run prints what would be sent
  team request server|plugin NAME [--note TEXT]   ask the admin to approve a server (e.g. project:linear) or plugin
  team approvals [--status pending|approved|rejected]
  admin: team approve ID [--note TEXT] | team reject ID [--note TEXT]
  admin: team inventory               the latest report of every member, with policy violations
  admin: team policy-push FILE        replace the central policy (a .mcp-security.json-style file)
  admin: team settings [--fleet on|off] [--webhook URL|none]
Environment: MCP_SECURITY_TEAM_SYNC=off stops the session-start sync; MCP_SECURITY_TEAM_REPORT=on also reports at session start (default off).
`;

const violationLine = (v: Violation) => `  - ${v.kind} ${excerpt(v.name, 80)}: ${v.reason}`;

function out(r: TeamResult<unknown>, ok: (data: any) => string[]): { text: string; code: number } {
  return r.ok ? { text: ok(r.data).join("\n"), code: 0 } : { text: `team: ${r.reason}`, code: 1 };
}

export async function runTeam(a: TeamArgs, opts: TeamOptions = teamOptionsFromEnv()): Promise<{ text: string; code: number }> {
  const sub = a.sub;
  if (!sub || sub === "help") return { text: TEAM_USAGE, code: sub ? 0 : 2 };
  if (!opts.apiKey) return { text: "team: no API key. Set MCP_SECURITY_API_KEY (or the plugin's API key setting) to a team key.", code: 1 };

  if (sub === "sync" || sub === "status") {
    const s = await syncTeamPolicy(opts, true);
    if (s.status === "not-team") return { text: "This key does not belong to a team.", code: 1 };
    if (s.status === "skipped") return { text: s.note, code: 1 };
    const c = s.cache ?? readTeamCache();
    const p = c?.policy;
    const lines = [s.note, `Role: ${c?.role ?? "member"}. Fleet visibility: ${c?.fleetVisibility ? "on (your reports are accepted)" : "off (reports are refused until an admin turns it on)"}.`];
    if (p) lines.push(`Policy: ${p.allowedServers?.length ?? 0} allowed server pattern(s), ${p.blockedServers?.length ?? 0} blocked, ${p.allowedRemoteHosts?.length ?? 0} allowed host(s), ${p.allowedPlugins?.length ?? 0} allowed plugin(s), ${p.blockedPlugins?.length ?? 0} blocked${p.requirePinnedVersions ? ", pinned versions required" : ""}. Enforced next to your own policy.`);
    return { text: lines.join("\n"), code: 0 };
  }

  if (sub === "report") {
    const report = buildInventory(a.project);
    if (a.dryRun) return { text: `Would send (nothing else leaves your machine):\n${JSON.stringify(report, null, 2)}`, code: 0 };
    return out(await reportInventory(opts, report), (d) => [`Reported ${report.servers.length} server(s) and ${report.plugins.length} plugin(s). Policy version ${d.policyVersion}.`, d.violations.length ? `${d.violations.length} violation(s):` : "No policy violations.", ...(d.violations as Violation[]).map(violationLine)]);
  }

  if (sub === "request") {
    const [kind, ...name] = a.rest;
    const identity = name.join(" ").trim();
    if ((kind !== "server" && kind !== "plugin") || !identity) return { text: "usage: team request server|plugin NAME [--note TEXT]", code: 2 };
    return out(await requestApproval(opts, kind, identity, a.note), (d) => [d.alreadyRequested ? `Already requested (${d.id}); your admin has not decided yet.` : `Requested (${d.id}). Your admin has been notified if an alert webhook is set.`]);
  }

  if (sub === "approvals") {
    return out(await listApprovals(opts, a.status), (d) => (d.approvals.length ? d.approvals.map((x: any) => `${x.id}  ${x.status.padEnd(8)} ${x.kind} ${excerpt(x.identity, 80)}${x.requestedBy ? ` (by ${excerpt(x.requestedBy, 40)})` : ""}${x.note ? ` - ${excerpt(x.note, 120)}` : ""}`) : ["No approval requests."]));
  }

  if (sub === "approve" || sub === "reject") {
    const id = a.rest[0];
    if (!id) return { text: `usage: team ${sub} ID [--note TEXT]`, code: 2 };
    return out(await decideApproval(opts, id, sub, a.note), (d) => [`${id}: ${d.status}${d.policyVersion ? `. The policy is now version ${d.policyVersion}; members get it at their next sync.` : "."}`]);
  }

  if (sub === "inventory") {
    return out(await fleetInventory(opts), (d) => [
      `${d.members.length} member(s) reported, ${d.violationCount} violation(s).`,
      ...d.members.flatMap((m: any) => [`- ${excerpt(m.label ?? "unnamed", 40)} (${m.reportedAt}): ${m.servers.length} server(s), ${m.plugins.length} plugin(s)`, ...(m.violations as Violation[]).map(violationLine)]),
      d.servers.length ? "Servers by number of members using them:" : "",
      ...d.servers.slice(0, 20).map((s: any) => `  ${s.members}  ${excerpt(s.name, 80)}`),
    ].filter(Boolean));
  }

  if (sub === "policy-push") {
    const file = a.rest[0];
    if (!file) return { text: "usage: team policy-push FILE", code: 2 };
    let policy: unknown;
    try {
      policy = JSON.parse(readFileSync(resolve(file), "utf8"));
    } catch {
      return { text: `team: ${file} is not readable JSON`, code: 2 };
    }
    return out(await pushPolicy(opts, policy as never), (d) => [`Policy pushed: version ${d.version}. Members get it within the hour or at \`team sync\`.`]);
  }

  if (sub === "settings") {
    const patch: { fleetVisibility?: boolean; webhookUrl?: string | null } = {};
    if (a.fleet !== undefined) {
      if (!["on", "off"].includes(a.fleet)) return { text: "--fleet must be on or off", code: 2 };
      patch.fleetVisibility = a.fleet === "on";
    }
    if (a.webhook !== undefined) patch.webhookUrl = a.webhook === "none" ? null : a.webhook;
    const r = Object.keys(patch).length ? await putSettings(opts, patch) : await getSettings(opts);
    return out(r, (d) => [`Organisation: ${excerpt(d.name, 60)}`, `Fleet visibility: ${d.fleetVisibility ? "on" : "off"}`, `Alert webhook: ${d.webhookConfigured ? "set" : "not set"}`]);
  }

  return { text: `team: unknown command "${excerpt(sub, 40)}"\n${TEAM_USAGE}`, code: 2 };
}
