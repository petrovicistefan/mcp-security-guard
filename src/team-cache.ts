// The organisation's policy as last synced from the team backend, kept next to the other state files.
// It is read by the policy loader on every audit and at session start, so it keeps being enforced when the
// backend is unreachable. It holds the policy and its version only, never the API key.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Policy } from "./policy.js";

export interface TeamCache {
  version: 1;
  /** When the backend was last asked, even if it answered "not a team". */
  fetchedAt: string;
  /** The last failed attempt to reach the backend, so a session start offline does not wait on it every time. */
  lastFailedAt?: string;
  /** The key is not a team key: skip the backend for a day. */
  notTeam?: boolean;
  org?: string;
  role?: "member" | "admin";
  policyVersion?: number;
  fleetVisibility?: boolean;
  policy?: Policy | null;
}

export function teamCachePath(): string {
  return join(process.env.MCP_SECURITY_HOME ?? join(homedir(), ".claude", "mcp-security"), "team-policy.json");
}

export function readTeamCache(path = teamCachePath()): TeamCache | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const data = JSON.parse(readFileSync(path, "utf8"));
    return data?.version === 1 && typeof data.fetchedAt === "string" ? (data as TeamCache) : undefined;
  } catch {
    return undefined;
  }
}

export function writeTeamCache(cache: TeamCache, path = teamCachePath()): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(cache, null, 2), { mode: 0o600 });
  renameSync(tmp, path);
}

const STRING_LISTS = ["allowedServers", "blockedServers", "allowedRemoteHosts", "allowedPlugins", "blockedPlugins"] as const;

/** The cached organisation policy, if there is one. Anything that does not look like a policy is ignored field by field. */
export function loadTeamPolicy(path = teamCachePath()): { policy: Policy; version: number; org: string } | undefined {
  const c = readTeamCache(path);
  if (!c?.policy || typeof c.policy !== "object" || c.notTeam) return undefined;
  const policy: Policy = {};
  for (const f of STRING_LISTS) {
    const v = (c.policy as Record<string, unknown>)[f];
    if (Array.isArray(v) && v.every((x) => typeof x === "string")) policy[f] = v as string[];
  }
  if (typeof c.policy.requirePinnedVersions === "boolean") policy.requirePinnedVersions = c.policy.requirePinnedVersions;
  return { policy, version: typeof c.policyVersion === "number" ? c.policyVersion : 0, org: typeof c.org === "string" ? c.org : "your organisation" };
}
