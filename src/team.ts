// Client for the Team plan of mcp-security-cloud (opt-in: needs an API key that belongs to a team).
// This file is the public contract of what leaves the machine for team features; the backend mirrors the
// types in its team-contract.ts.
//   sync      the organisation's policy comes down and is enforced next to your own (fail open, cached)
//   report    servers and plugins go up, by name and version only, and only if the admin turned fleet visibility on
//   request   ask the admin to approve a server or plugin
// Reports never hold paths, arguments, environment, headers, URLs with query strings, tool definitions or secrets.
import { homedir } from "node:os";
import { resolve } from "node:path";
import { discoverServers, pluginRoots, transportOf } from "./config.js";
import { cloudOptionsFromEnv, endpointAllowed } from "./cloud.js";
import { loadPins, pinKey } from "./pins.js";
import type { Policy } from "./policy.js";
import { excerpt } from "./sanitize.js";
import { packagesOf } from "./supply-chain.js";
import { readTeamCache, writeTeamCache, type TeamCache } from "./team-cache.js";
import type { ServerConfig } from "./types.js";
import { VERSION } from "./version.js";

export interface InventoryServer {
  name: string;
  scope: string;
  transport: "stdio" | "http" | "sse" | "claude-ai" | "unknown";
  package?: { ecosystem: "npm" | "PyPI"; name: string; version?: string };
  host?: string;
  pinned?: boolean;
}
export interface InventoryPlugin {
  name: string;
  version?: string;
}
export interface InventoryReport {
  client: { name: "mcp-security-guard"; version: string };
  servers: InventoryServer[];
  plugins: InventoryPlugin[];
}
export interface Violation {
  kind: "server" | "plugin" | "host";
  name: string;
  reason: "blocked" | "not-approved" | "host-not-allowed";
}
export interface ApprovalView {
  id: string;
  kind: "server" | "plugin";
  identity: string;
  status: "pending" | "approved" | "rejected";
  requestedBy: string | null;
  note: string | null;
  createdAt: string;
  decidedAt: string | null;
  decisionNote: string | null;
}

const SYNC_TTL_MS = 60 * 60 * 1000;
const RETRY_AFTER_FAILURE_MS = 15 * 60 * 1000;
const NOT_TEAM_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 5000;

export type TeamFetcher = (url: string, init: { method: string; body?: string; headers: Record<string, string>; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;
export interface TeamOptions {
  apiKey?: string;
  endpoint?: string;
  timeoutMs?: number;
  fetcher?: TeamFetcher;
  now?: () => Date;
}

/** The same key and backend as the threat feed. */
export function teamOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): TeamOptions {
  const { apiKey, endpoint } = cloudOptionsFromEnv(env);
  return { apiKey, endpoint };
}

export type TeamResult<T> = { ok: true; data: T } | { ok: false; status?: number; reason: string };

const safeLabel = (text: string) => text.replace(/[^A-Za-z0-9_.:@/ -]/g, "_").slice(0, 200);

/** Sends one request to the team backend. Errors become a reason; nothing throws. */
export async function teamRequest<T>(opts: TeamOptions, method: string, path: string, body?: unknown): Promise<TeamResult<T>> {
  if (!opts.apiKey) return { ok: false, reason: "no API key: set MCP_SECURITY_API_KEY or enter the key in the plugin's settings" };
  if (!opts.endpoint || !endpointAllowed(opts.endpoint)) return { ok: false, reason: "MCP_SECURITY_API_URL must be an https URL" };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const res = await (opts.fetcher ?? ((u, i) => fetch(u, i)))(new URL(path, opts.endpoint).href, {
      method,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { authorization: `Bearer ${opts.apiKey}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
      signal: controller.signal,
    });
    let data: unknown;
    try {
      data = await res.json();
    } catch {
      data = undefined;
    }
    if (res.ok) return { ok: true, data: data as T };
    const message = typeof (data as { error?: unknown })?.error === "string" ? excerpt((data as { error: string }).error, 160) : undefined;
    const why = res.status === 401 ? "the API key was rejected" : res.status === 402 ? "the subscription has expired" : res.status === 429 ? "too many requests, try again in a minute" : (message ?? `the service answered ${res.status}`);
    return { ok: false, status: res.status, reason: why };
  } catch (e) {
    return { ok: false, reason: (e as Error)?.name === "AbortError" ? "no answer from the service" : "the service could not be reached" };
  } finally {
    clearTimeout(timer);
  }
}

export interface TeamPolicyAnswer {
  org: { name: string };
  role: "member" | "admin";
  policy: Policy | null;
  version: number;
  updatedAt: string | null;
  fleetVisibility: boolean;
}

export interface SyncResult {
  status: "synced" | "not-team" | "fresh" | "skipped";
  note: string;
  cache?: TeamCache;
}

/**
 * Fetches the organisation's policy into the local cache. `force` ignores the hourly freshness window.
 * Without a key it does nothing; on any failure the cached policy keeps being enforced.
 */
export async function syncTeamPolicy(opts: TeamOptions = teamOptionsFromEnv(), force = false): Promise<SyncResult> {
  if (!opts.apiKey) return { status: "skipped", note: "No API key." };
  const now = (opts.now ?? (() => new Date()))();
  const cached = readTeamCache();
  if (!force && cached) {
    const age = now.getTime() - Date.parse(cached.fetchedAt);
    if (age >= 0 && age < (cached.notTeam ? NOT_TEAM_TTL_MS : SYNC_TTL_MS)) return { status: cached.notTeam ? "not-team" : "fresh", note: cached.notTeam ? "This key does not belong to a team." : "Team policy is up to date.", cache: cached };
  }
  if (!force && cached?.lastFailedAt && now.getTime() - Date.parse(cached.lastFailedAt) < RETRY_AFTER_FAILURE_MS) return { status: "skipped", note: "", cache: cached };
  const r = await teamRequest<TeamPolicyAnswer>(opts, "GET", "/v1/team/policy");
  if (!r.ok) {
    if (r.status === 403) {
      const cache: TeamCache = { version: 1, fetchedAt: now.toISOString(), notTeam: true };
      writeTeamCache(cache);
      return { status: "not-team", note: "This key does not belong to a team.", cache };
    }
    const failed: TeamCache = { ...(cached ?? { version: 1, fetchedAt: new Date(0).toISOString() }), lastFailedAt: now.toISOString() };
    writeTeamCache(failed);
    return { status: "skipped", note: `Team policy not synced: ${r.reason}.${cached?.policy ? " The last synced policy stays in force." : ""}`, cache: failed };
  }
  const a = r.data;
  const cache: TeamCache = {
    version: 1,
    fetchedAt: now.toISOString(),
    org: typeof a.org?.name === "string" ? excerpt(a.org.name, 80) : undefined,
    role: a.role === "admin" ? "admin" : "member",
    policyVersion: typeof a.version === "number" ? a.version : 0,
    fleetVisibility: a.fleetVisibility === true,
    policy: a.policy && typeof a.policy === "object" ? a.policy : null,
  };
  writeTeamCache(cache);
  return { status: "synced", note: `Team policy of ${cache.org ?? "your organisation"}: version ${cache.policyVersion}${cache.policy ? "" : " (no policy set)"}.`, cache };
}

/** What a report would send, built from the machine's configuration. Names, scopes, package coordinates, hosts and versions only. */
export function buildInventory(projectDir: string, home?: string): InventoryReport {
  const { servers } = discoverServers(projectDir, home);
  const pins = loadPins();
  const packages = servers.flatMap(packagesOf);
  const pkgOf = (s: ServerConfig) => packages.find((p) => p.server === s);
  const host = (s: ServerConfig) => {
    try {
      return s.url ? new URL(s.url.replace(/\$\{[^}]+\}/g, "x")).hostname.toLowerCase() : undefined;
    } catch {
      return undefined;
    }
  };
  const out: InventoryServer[] = servers.map((s) => {
    const p = pkgOf(s);
    const h = host(s);
    return {
      name: safeLabel(s.name),
      scope: safeLabel(s.scope),
      transport: transportOf(s),
      ...(p ? { package: { ecosystem: p.ecosystem, name: safeLabel(p.name), ...(p.version ? { version: p.version } : {}) } } : {}),
      ...(h && /^[a-z0-9.-]{1,253}$/.test(h) ? { host: h } : {}),
      pinned: !!pins.servers[pinKey(s.scope, s.name)],
    };
  });
  const plugins = pluginRoots(resolve(projectDir), home ?? homedir(), []).map((p) => ({ name: safeLabel(p.name), ...(p.version ? { version: p.version } : {}) }));
  return { client: { name: "mcp-security-guard", version: VERSION }, servers: out.slice(0, 500), plugins: plugins.slice(0, 500) };
}

export async function reportInventory(opts: TeamOptions, report: InventoryReport): Promise<TeamResult<{ policyVersion: number; violations: Violation[] }>> {
  return teamRequest(opts, "POST", "/v1/team/inventory", report);
}

export async function requestApproval(opts: TeamOptions, kind: "server" | "plugin", identity: string, note?: string): Promise<TeamResult<{ id: string; status: "pending"; alreadyRequested: boolean }>> {
  return teamRequest(opts, "POST", "/v1/team/approvals", { kind, identity, ...(note ? { note } : {}) });
}

export const listApprovals = (opts: TeamOptions, status?: string) => teamRequest<{ approvals: ApprovalView[] }>(opts, "GET", `/v1/team/approvals${status ? `?status=${encodeURIComponent(status)}` : ""}`);
export const decideApproval = (opts: TeamOptions, id: string, decision: "approve" | "reject", note?: string) => teamRequest<{ id: string; status: string; policyVersion?: number }>(opts, "POST", `/v1/team/approvals/${encodeURIComponent(id)}/decision`, { decision, ...(note ? { note } : {}) });
export const fleetInventory = (opts: TeamOptions) =>
  teamRequest<{ members: { label: string | null; reportedAt: string; servers: InventoryServer[]; plugins: InventoryPlugin[]; violations: Violation[] }[]; servers: { name: string; members: number }[]; violationCount: number }>(opts, "GET", "/v1/team/inventory");
export const pushPolicy = (opts: TeamOptions, policy: Policy) => teamRequest<{ version: number; updatedAt: string }>(opts, "PUT", "/v1/team/policy", policy);
export const getSettings = (opts: TeamOptions) => teamRequest<SettingsView>(opts, "GET", "/v1/team/settings");
export const putSettings = (opts: TeamOptions, patch: { fleetVisibility?: boolean; webhookUrl?: string | null; alertEmail?: string | null }) => teamRequest<SettingsView>(opts, "PUT", "/v1/team/settings", patch);
export const listKeys = (opts: TeamOptions) => teamRequest<{ seats: number | null; used: number; keys: { id: string; role: string; label: string | null; status: string; expiresAt: string | null }[] }>(opts, "GET", "/v1/team/keys");
/** The new key is in the answer and is shown once; the service keeps only its hash. */
export const createKey = (opts: TeamOptions, label: string, role: "member" | "admin" = "member") => teamRequest<{ key: string; id: string; label: string; role: string }>(opts, "POST", "/v1/team/keys", { label, role });
export const revokeKey = (opts: TeamOptions, id: string) => teamRequest<{ id: string; status: string }>(opts, "POST", `/v1/team/keys/${encodeURIComponent(id)}/revoke`);

export interface SettingsView {
  name: string;
  fleetVisibility: boolean;
  webhookConfigured: boolean;
  alertEmailConfigured?: boolean;
  emailAvailable?: boolean;
  seats?: number | null;
}

/** Session start: refreshes the policy at most hourly, and reports the inventory only if the user turned that on. Never throws. */
export async function teamSessionStart(projectDir: string, env: NodeJS.ProcessEnv = process.env, opts: TeamOptions = teamOptionsFromEnv(env)): Promise<string[]> {
  if (!opts.apiKey || (env.MCP_SECURITY_TEAM_SYNC ?? "on").toLowerCase() === "off") return [];
  const notes: string[] = [];
  const quick = { ...opts, timeoutMs: opts.timeoutMs ?? 3000 };
  try {
    const sync = await syncTeamPolicy(quick);
    if (sync.status === "skipped" && sync.note) notes.push(sync.note);
    const reportOn = (env.MCP_SECURITY_TEAM_REPORT ?? "off").toLowerCase() === "on";
    if (reportOn && sync.cache?.fleetVisibility && !sync.cache.notTeam) {
      const r = await reportInventory(quick, buildInventory(projectDir));
      if (!r.ok) notes.push(`Team report not sent: ${r.reason}.`);
    }
  } catch {
    // Team features never get in the way of a session.
  }
  return notes;
}
