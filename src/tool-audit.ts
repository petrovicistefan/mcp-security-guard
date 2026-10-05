import { capabilityFindings, inventory, recommendPermissions, type ServerInventory } from "./capabilities.js";
import { fetchTools } from "./client.js";
import { applyPolicy, auditPolicy, type LoadedPolicy } from "./policy.js";
import { computeDrift, hasDrift, hashConfig, pinKey, type PinFile } from "./pins.js";
import { auditServerConfig } from "./rules/config-rules.js";
import { analyzeTools } from "./rules/tool-rules.js";
import { scoreServer, scoreTable } from "./score.js";
import { excerpt } from "./sanitize.js";
import type { Finding, ServerConfig, ToolDefinition } from "./types.js";

export function selectServers(all: ServerConfig[], names: string[]): { picked: ServerConfig[]; unknown: string[] } {
  if (names.includes("*")) return { picked: all, unknown: [] };
  const picked: ServerConfig[] = [];
  const unknown: string[] = [];
  for (const n of names) {
    const [scope, name] = n.includes(":") ? n.split(/:(.*)/s) : [undefined, n];
    const hits = all.filter((s) => s.name === name && (!scope || s.scope === scope));
    if (hits.length) picked.push(...hits.filter((h) => !picked.includes(h)));
    else unknown.push(n);
  }
  return { picked, unknown };
}

export type FetchResult = { server: ServerConfig; tools: ToolDefinition[] } | { server: ServerConfig; error: string };

export async function fetchAll(servers: ServerConfig[], timeoutSeconds: number): Promise<FetchResult[]> {
  return Promise.all(
    servers.map(async (s) => {
      try {
        return { server: s, tools: await fetchTools(s, timeoutSeconds * 1000) };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        // StreamableHTTPError carries the HTTP status in `code`; some servers send an empty 401 body.
        const status = (e as { code?: unknown })?.code;
        const needsAuth = s.url && (status === 401 || status === 403 || /\b40[13]\b|unauthori[sz]ed|authoriz|authenticat|invalid_token|www-authenticate/i.test(msg));
        return {
          server: s,
          error: needsAuth ? "requires OAuth sign-in. The scanner cannot reuse Claude Code's tokens; its config can still be audited statically" : excerpt(msg, 200),
        };
      }
    }),
  );
}

export interface ToolAudit {
  findings: Finding[];
  ok: { server: ServerConfig; tools: ToolDefinition[] }[];
  errors: { server: ServerConfig; error: string }[];
  /** Per-server pin status lines; empty when no pin file was given. */
  driftLines: string[];
  inventories: ServerInventory[];
}

/**
 * Full audit of the given servers: configuration rules, then tools/list for poisoning, shadowing,
 * capability and authentication checks across all of them, and a comparison with pins if given.
 */
export async function auditTools(servers: ServerConfig[], timeoutSeconds: number, pins?: PinFile, policy?: LoadedPolicy): Promise<ToolAudit> {
  const results = await fetchAll(servers, timeoutSeconds);
  const ok = results.filter((r): r is { server: ServerConfig; tools: ToolDefinition[] } => "tools" in r);
  const errors = results.filter((r): r is { server: ServerConfig; error: string } => "error" in r);
  const findings: Finding[] = servers.flatMap(auditServerConfig);
  const driftLines: string[] = [];
  const inventories = ok.map((r) => inventory(r.server, r.tools));
  findings.push(...inventories.flatMap(capabilityFindings));

  for (const r of ok) {
    const own: Finding[] = [];
    const others = Object.fromEntries(ok.filter((o) => o !== r).map((o) => [o.server.name, o.tools.map((t) => t.name)]));
    own.push(...analyzeTools(r.server.name, r.tools, others));

    const label = `**${excerpt(r.server.name, 50)}** (${r.server.scope})`;
    const where = `server "${r.server.name}" (${r.server.scope})`;
    const pinned = pins?.servers[pinKey(r.server.scope, r.server.name)];
    if (pins && !pinned) driftLines.push(`- ${label}: not pinned yet`);
    if (pinned) {
      if (pinned.config && pinned.config !== hashConfig(r.server)) {
        own.push({ severity: "medium", rule: "drift/config-changed", title: "Launch command, package version or URL changed since pinning", location: `${where} in ${r.server.source}`, remediation: "Check who changed the config and why (e.g. a pulled .mcp.json or a version bump), then re-pin." });
      }
      const d = computeDrift(pinned, r.tools);
      driftLines.push(hasDrift(d) ? `- ${label}: ⚠️ changed since ${pinned.pinnedAt}` : `- ${label}: unchanged since ${pinned.pinnedAt}`);
      const list = (xs: string[]) => xs.map((x) => `"${excerpt(x, 50)}"`).join(", ");
      if (d.changed.length) own.push({ severity: "high", rule: "drift/tool-changed", title: `${d.changed.length} tool definition(s) changed since pinning: ${list(d.changed)}`, location: where, remediation: "A server that rewrites tool descriptions after approval is the rug-pull pattern. Review the findings for these tools, and re-pin only once you trust the new wording." });
      if (d.added.length) own.push({ severity: "medium", rule: "drift/tool-added", title: `${d.added.length} new tool(s) since pinning: ${list(d.added)}`, location: where, remediation: "Check that the new tools match a release you expected, then re-pin." });
      if (d.removed.length) own.push({ severity: "low", rule: "drift/tool-removed", title: `${d.removed.length} tool(s) removed since pinning: ${list(d.removed)}`, location: where, remediation: "Usually a normal upgrade. Re-pin after reviewing." });
    }
    findings.push(...own.map((f) => ({ ...f, file: r.server.source, server: r.server.name })));
  }
  findings.push(...auditPolicy(servers, policy));
  return { findings: applyPolicy(findings, policy), ok, errors, driftLines, inventories };
}

export function toolAuditSections(a: ToolAudit, unknown: string[] = [], pinsLocation?: string): string[] {
  return [
    `Scanned **${a.ok.length}** server(s), **${a.ok.reduce((n, r) => n + r.tools.length, 0)}** tool(s).`,
    unknown.length ? `**Unknown server names:** ${unknown.map((u) => excerpt(u, 50)).join(", ")}` : "",
    a.errors.length ? `**Could not connect:**\n${a.errors.map((e) => `- **${excerpt(e.server.name, 50)}** (${e.server.scope}): ${e.error}`).join("\n")}` : "",
    a.driftLines.length ? `**Pinning status**${pinsLocation ? ` (${pinsLocation})` : ""}:\n${a.driftLines.join("\n")}` : "",
    scoreTable([...a.ok.map((r) => scoreServer(r.server, a.findings, "config+tools")), ...a.errors.map((e) => scoreServer(e.server, a.findings, "config"))]),
    permissionsSection(a.inventories),
  ];
}

function permissionsSection(invs: ServerInventory[]): string {
  const { ask } = recommendPermissions(invs);
  if (!ask.length) return "";
  return [
    `**Recommended permission rules:** ${ask.length} tool(s) can execute code, delete data or write files. Add them to \`.claude/settings.json\` so Claude asks before each call:`,
    "```json",
    JSON.stringify({ permissions: { ask } }, null, 2),
    "```",
  ].join("\n");
}
