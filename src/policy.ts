// Approved-server policy (OWASP MCP09, shadow MCP servers). A team commits `.mcp-security.json`;
// an individual can also keep one at ~/.claude/mcp-security/policy.json. Project rules take precedence.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { excerpt } from "./sanitize.js";
import type { Finding, ServerConfig } from "./types.js";

export interface Policy {
  /** Server patterns that may be configured: "github", "project:github", "plugin:cloudflare:*", "*". */
  allowedServers?: string[];
  /** Server patterns that must never be configured. Wins over allowedServers. */
  blockedServers?: string[];
  /** Host patterns remote servers may use, e.g. "mcp.vercel.com", "*.cloudflare.com". */
  allowedRemoteHosts?: string[];
  /** Raise unpinned packages/images from medium to high. */
  requirePinnedVersions?: boolean;
}

export interface LoadedPolicy {
  policy: Policy;
  sources: string[];
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
  return sources.length ? { policy: merged, sources } : undefined;
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

export function auditPolicy(servers: ServerConfig[], loaded: LoadedPolicy | undefined): Finding[] {
  if (!loaded) return [];
  const { policy, sources } = loaded;
  const out: Finding[] = sources
    .filter((s) => s.endsWith("(unreadable)"))
    .map((s) => ({ severity: "high" as const, rule: "policy/unreadable", title: "Policy file could not be parsed", location: s, remediation: "Fix the JSON. Until then the policy is not enforced." }));
  const ref = `policy (${sources.join(", ")})`;

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

/** Applies policy-driven severity changes to other findings (e.g. requirePinnedVersions). */
export function applyPolicy(findings: Finding[], loaded: LoadedPolicy | undefined): Finding[] {
  if (!loaded?.policy.requirePinnedVersions) return findings;
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
