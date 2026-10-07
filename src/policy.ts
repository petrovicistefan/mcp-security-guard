// Approved-server policy (OWASP MCP09, shadow MCP servers). A team commits `.mcp-security.json`;
// an individual can also keep one at ~/.claude/mcp-security/policy.json. Project rules take precedence.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { excerpt } from "./sanitize.js";
import { loadTeamPolicy } from "./team-cache.js";
import type { Finding, ServerConfig } from "./types.js";

export interface Policy {
  /** Server patterns that may be configured: "github", "project:github", "plugin:cloudflare:*", "*". */
  allowedServers?: string[];
  /** Server patterns that must never be configured. Wins over allowedServers. */
  blockedServers?: string[];
  /** Host patterns remote servers may use, e.g. "mcp.vercel.com", "*.cloudflare.com". */
  allowedRemoteHosts?: string[];
  /** Plugin name patterns that may be installed. */
  allowedPlugins?: string[];
  /** Plugin name patterns that must never be installed. Wins over allowedPlugins. */
  blockedPlugins?: string[];
  /** Raise unpinned packages/images from medium to high. */
  requirePinnedVersions?: boolean;
}

export interface LoadedPolicy {
  /** The user's and the project's policy, merged (project wins field by field). */
  policy: Policy;
  sources: string[];
  /**
   * The organisation's policy, synced from the team backend. It is checked in addition to `policy`, never
   * replaced by it: a project file cannot loosen what the organisation requires.
   */
  team?: { policy: Policy; version: number; org: string };
}

export function policyPaths(projectDir: string): string[] {
  return [join(process.env.MCP_SECURITY_HOME ?? join(homedir(), ".claude", "mcp-security"), "policy.json"), join(projectDir, ".mcp-security.json")];
}

/** Merge user and project policies; project values replace user values field by field. */
export function loadPolicy(projectDir: string): LoadedPolicy | undefined {
  const merged: Policy = {};
  const sources: string[] = [];
  for (const p of policyPaths(projectDir)) {
    if (!existsSync(p)) continue;
    try {
      Object.assign(merged, JSON.parse(readFileSync(p, "utf8")));
      sources.push(p);
    } catch {
      // An unreadable policy must not silently allow everything: surface it as a finding instead.
      sources.push(`${p} (unreadable)`);
    }
  }
  const team = loadTeamPolicy();
  return sources.length || team ? { policy: merged, sources, ...(team ? { team: { policy: team.policy, version: team.version, org: team.org } } : {}) } : undefined;
}

function globToRegExp(pattern: string): RegExp {
  return new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");
}

/** A pattern matches "<scope>:<name>" or, without a scope prefix, the bare name in any scope. */
export function matchesServer(s: ServerConfig, pattern: string): boolean {
  const re = globToRegExp(pattern);
  return re.test(`${s.scope}:${s.name}`) || re.test(s.name);
}

export function matchesHost(url: string, patterns: string[]): boolean {
  let host: string;
  try {
    host = new URL(url.replace(/\$\{[^}]+\}/g, "x")).hostname;
  } catch {
    return false;
  }
  return patterns.some((p) => globToRegExp(p).test(host));
}

function checkServers(servers: ServerConfig[], policy: Policy, ref: string): Finding[] {
  const out: Finding[] = [];
  for (const s of servers) {
    const where = `server "${s.name}" (${s.scope})`;
    const tag = { file: s.source, server: s.name };
    const blocked = policy.blockedServers?.find((p) => matchesServer(s, p));
    if (blocked) {
      out.push({ severity: "critical", rule: "policy/blocked-server", title: `Server is on the block list ("${excerpt(blocked, 60)}")`, location: where, remediation: `Remove it. Blocked by ${ref}.`, ...tag });
      continue;
    }
    if (policy.allowedServers && !policy.allowedServers.some((p) => matchesServer(s, p))) {
      out.push({ severity: "high", rule: "policy/unapproved-server", title: "Server is not on the approved list (shadow MCP server)", location: where, remediation: `Get it reviewed and add "${s.scope}:${s.name}" to allowedServers, or remove it. Enforced by ${ref}.`, ...tag });
    }
    if (s.url && policy.allowedRemoteHosts && !matchesHost(s.url, policy.allowedRemoteHosts)) {
      out.push({ severity: "high", rule: "policy/remote-host-not-allowed", title: "Remote server host is not on the allowed hosts list", location: `${where} › url`, evidence: excerpt(s.url.replace(/\?.*$/, ""), 100), remediation: `Use an approved host or extend allowedRemoteHosts in ${ref}.`, ...tag });
    }
  }
  return out;
}

export function auditPolicy(servers: ServerConfig[], loaded: LoadedPolicy | undefined): Finding[] {
  if (!loaded) return [];
  const { policy, sources } = loaded;
  const out: Finding[] = sources
    .filter((s) => s.endsWith("(unreadable)"))
    .map((s) => ({ severity: "high" as const, rule: "policy/unreadable", title: "Policy file could not be parsed", location: s, remediation: "Fix the JSON. Until then the policy is not enforced." }));
  if (sources.some((s) => !s.endsWith("(unreadable)"))) out.push(...checkServers(servers, policy, `policy (${sources.join(", ")})`));
  if (loaded.team) {
    // The same finding from both policies is reported once; the team's wording wins because it cannot be overridden locally.
    const own = new Set(out.map((f) => `${f.rule}|${f.location}`));
    out.push(...checkServers(servers, loaded.team.policy, `the team policy of ${excerpt(loaded.team.org, 60)} (version ${loaded.team.version})`).filter((f) => !own.has(`${f.rule}|${f.location}`)));
  }
  return out;
}

/** Plugins the policy (local or the team's) blocks or does not list. `plugins` are installed plugin names. */
export function auditPluginPolicy(plugins: { name: string; version?: string }[], loaded: LoadedPolicy | undefined): Finding[] {
  if (!loaded) return [];
  const layers: { policy: Policy; ref: string; active: boolean }[] = [
    { policy: loaded.policy, ref: `policy (${loaded.sources.join(", ")})`, active: loaded.sources.some((s) => !s.endsWith("(unreadable)")) },
    ...(loaded.team ? [{ policy: loaded.team.policy, ref: `the team policy of ${excerpt(loaded.team.org, 60)} (version ${loaded.team.version})`, active: true }] : []),
  ];
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const { policy, ref, active } of layers) {
    if (!active) continue;
    for (const p of plugins) {
      const where = `plugin "${excerpt(p.name, 60)}"${p.version ? ` ${excerpt(p.version, 30)}` : ""}`;
      const blocked = policy.blockedPlugins?.find((x) => globToRegExp(x).test(p.name));
      const key = (rule: string) => `${rule}|${p.name}`;
      if (blocked && !seen.has(key("policy/blocked-plugin"))) {
        seen.add(key("policy/blocked-plugin"));
        out.push({ severity: "critical", rule: "policy/blocked-plugin", title: `Plugin is on the block list ("${excerpt(blocked, 60)}")`, location: where, remediation: `Uninstall it. Blocked by ${ref}.` });
      } else if (!blocked && policy.allowedPlugins && !policy.allowedPlugins.some((x) => globToRegExp(x).test(p.name)) && !seen.has(key("policy/unapproved-plugin"))) {
        seen.add(key("policy/unapproved-plugin"));
        out.push({ severity: "high", rule: "policy/unapproved-plugin", title: "Plugin is not on the approved list", location: where, remediation: `Get it reviewed and ask for approval ("team request plugin ${excerpt(p.name, 60)}"), or uninstall it. Enforced by ${ref}.` });
      }
    }
  }
  return out;
}

/** Applies policy-driven severity changes to other findings (e.g. requirePinnedVersions). */
export function applyPolicy(findings: Finding[], loaded: LoadedPolicy | undefined): Finding[] {
  if (!loaded?.policy.requirePinnedVersions && !loaded?.team?.policy.requirePinnedVersions) return findings;
  return findings.map((f) => (f.rule === "config/unpinned-package" || f.rule === "config/docker-unpinned-image" ? { ...f, severity: "high", title: `${f.title} (policy requires pinned versions)` } : f));
}

/** A policy that approves exactly what is configured now, as a starting point for a team. */
export function policyFromServers(servers: ServerConfig[]): Policy {
  const hosts = servers.flatMap((s) => {
    try {
      return s.url ? [new URL(s.url.replace(/\$\{[^}]+\}/g, "x")).hostname] : [];
    } catch {
      return [];
    }
  });
  return {
    allowedServers: [...new Set(servers.filter((s) => s.scope !== "claude-desktop").map((s) => `${s.scope}:${s.name}`))].sort(),
    blockedServers: [],
    allowedRemoteHosts: [...new Set(hosts)].sort(),
    requirePinnedVersions: true,
  };
}
