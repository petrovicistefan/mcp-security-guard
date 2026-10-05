// Opt-in client for the paid threat feed (mcp-security-cloud). Off unless MCP_SECURITY_API_KEY is set.
// This file is the public API contract: the request below is everything that leaves the machine.
// It holds SHA-256 hashes of tool definitions and npm/PyPI package names and versions, never server
// names, paths, descriptions, arguments or secrets. Matches are mapped back to servers locally.
// The client fails open: any error, timeout or malformed answer skips the check and the local audit
// goes on unchanged.
import { hashTool } from "./pins.js";
import { excerpt } from "./sanitize.js";
import type { Ecosystem, PackageRef } from "./supply-chain.js";
import { SEVERITY_ORDER, type Finding, type ServerConfig, type Severity, type ToolDefinition } from "./types.js";
import { VERSION } from "./version.js";

/** The hosted backend. MCP_SECURITY_API_URL overrides it, e.g. for a self-hosted or local backend. */
const DEFAULT_ENDPOINT: string | undefined = "https://mcp-security-cloud.petrovicistefan.workers.dev";

export const MAX_PACKAGES = 500;
export const MAX_TOOL_HASHES = 5000;
const MAX_FINDINGS = 1000;
const DEFAULT_TIMEOUT_MS = 3000;

export interface CloudPackage {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
}

/** POST /v1/check request body. */
export interface CloudCheckRequest {
  client: { name: "mcp-security"; version: string };
  packages: CloudPackage[];
  toolHashes: string[];
}

export type CloudMatch = { kind: "package"; ecosystem: Ecosystem; name: string; version?: string } | { kind: "tool"; hash: string };

export interface CloudFeedEntry {
  match: CloudMatch;
  severity: Severity;
  title: string;
  /** https URL with the evidence for the entry. */
  reference?: string;
}

/** POST /v1/check response body. */
export interface CloudCheckResponse {
  findings: CloudFeedEntry[];
  feedUpdatedAt: string;
}

export type CloudFetcher = (
  url: string,
  init: { method: string; body: string; headers: Record<string, string>; signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface CloudOptions {
  apiKey?: string;
  endpoint?: string;
  fetcher?: CloudFetcher;
  timeoutMs?: number;
}

export interface CloudResult {
  status: "disabled" | "ok" | "skipped";
  findings: Finding[];
  /** One line for the report: why the check was skipped, or how fresh the feed is. */
  note?: string;
}

export interface ServerTools {
  server: ServerConfig;
  tools: ToolDefinition[];
}

export function cloudOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): CloudOptions {
  return { apiKey: env.MCP_SECURITY_API_KEY?.trim() || undefined, endpoint: env.MCP_SECURITY_API_URL?.trim() || DEFAULT_ENDPOINT };
}

/** The key is only ever sent over https; plain http is accepted for a local backend during development. */
export function endpointAllowed(endpoint: string): boolean {
  try {
    const u = new URL(endpoint);
    return u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname));
  } catch {
    return false;
  }
}

const packageKey = (p: { ecosystem: string; name: string; version?: string }) => `${p.ecosystem}:${p.name.toLowerCase()}@${p.version ?? ""}`;

/** Deduplicated, sorted and capped, so the request carries nothing about order or which server uses what. */
export function buildCheckRequest(packages: PackageRef[], servers: ServerTools[]): CloudCheckRequest {
  const pkgs = new Map<string, CloudPackage>();
  for (const p of packages) pkgs.set(packageKey(p), p.version ? { ecosystem: p.ecosystem, name: p.name, version: p.version } : { ecosystem: p.ecosystem, name: p.name });
  const hashes = new Set(servers.flatMap((s) => s.tools.map(hashTool)));
  return {
    client: { name: "mcp-security", version: VERSION },
    packages: [...pkgs.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, p]) => p).slice(0, MAX_PACKAGES),
    toolHashes: [...hashes].sort().slice(0, MAX_TOOL_HASHES),
  };
}

const isSeverity = (v: unknown): v is Severity => typeof v === "string" && (SEVERITY_ORDER as string[]).includes(v);

/** The response is untrusted: anything that does not match the contract is dropped, text is made inert. */
export function parseCheckResponse(body: unknown): CloudCheckResponse | undefined {
  if (!body || typeof body !== "object" || !Array.isArray((body as any).findings)) return undefined;
  const findings: CloudFeedEntry[] = [];
  for (const raw of (body as any).findings.slice(0, MAX_FINDINGS)) {
    const m = raw?.match;
    if (!isSeverity(raw?.severity) || typeof raw?.title !== "string") continue;
    let match: CloudMatch;
    if (m?.kind === "tool" && typeof m.hash === "string" && /^[0-9a-f]{64}$/.test(m.hash)) match = { kind: "tool", hash: m.hash };
    else if (m?.kind === "package" && (m.ecosystem === "npm" || m.ecosystem === "PyPI") && typeof m.name === "string")
      match = { kind: "package", ecosystem: m.ecosystem, name: m.name, ...(typeof m.version === "string" ? { version: m.version } : {}) };
    else continue;
    const reference = typeof raw.reference === "string" && /^https:\/\/[^\s]+$/.test(raw.reference) ? excerpt(raw.reference, 200) : undefined;
    findings.push({ match, severity: raw.severity, title: excerpt(raw.title, 160), ...(reference ? { reference } : {}) });
  }
  const at = (body as any).feedUpdatedAt;
  return { findings, feedUpdatedAt: typeof at === "string" ? excerpt(at, 40) : "unknown" };
}

/** Map feed entries back to the servers that use the matching package or tool. */
export function toFindings(entries: CloudFeedEntry[], packages: PackageRef[], servers: ServerTools[]): Finding[] {
  const out: Finding[] = [];
  for (const e of entries) {
    const remediation = `Remove or replace this server until the issue is resolved.${e.reference ? ` Details: ${e.reference}` : ""}`;
    if (e.match.kind === "package") {
      const m = e.match;
      for (const p of packages) {
        if (p.ecosystem !== m.ecosystem || p.name.toLowerCase() !== m.name.toLowerCase() || (m.version && p.version !== m.version)) continue;
        out.push({ severity: e.severity, rule: "feed/package", title: e.title, location: `server "${p.server.name}" (${p.server.scope}) › ${p.ecosystem} ${p.name}${p.version ? `@${p.version}` : ""}`, remediation, file: p.server.source, server: p.server.name });
      }
    } else {
      const hash = e.match.hash;
      for (const s of servers)
        for (const t of s.tools)
          if (hashTool(t) === hash)
            out.push({ severity: e.severity, rule: "feed/tool", title: e.title, location: `server "${s.server.name}" (${s.server.scope}) › tool "${excerpt(t.name, 60)}"`, remediation, file: s.server.source, server: s.server.name });
    }
  }
  return out;
}

const defaultFetcher: CloudFetcher = (url, init) => fetch(url, init);

export async function cloudCheck(packages: PackageRef[], servers: ServerTools[], opts: CloudOptions = cloudOptionsFromEnv()): Promise<CloudResult> {
  if (!opts.apiKey) return { status: "disabled", findings: [] };
  if (!opts.endpoint) return { status: "skipped", findings: [], note: "Threat feed skipped: MCP_SECURITY_API_URL is not set." };
  if (!endpointAllowed(opts.endpoint)) return { status: "skipped", findings: [], note: "Threat feed skipped: MCP_SECURITY_API_URL must be an https URL." };

  const request = buildCheckRequest(packages, servers);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error("timeout"));
    }, timeoutMs);
  });
  try {
    const res = await Promise.race([
      (opts.fetcher ?? defaultFetcher)(new URL("/v1/check", opts.endpoint).href, {
        method: "POST",
        body: JSON.stringify(request),
        headers: { "content-type": "application/json", authorization: `Bearer ${opts.apiKey}` },
        signal: controller.signal,
      }),
      timeout,
    ]);
    if (!res.ok) {
      const why = res.status === 401 ? "the API key was rejected" : res.status === 402 ? "the subscription has expired" : `the service answered ${res.status}`;
      return { status: "skipped", findings: [], note: `Threat feed skipped: ${why}.` };
    }
    const parsed = parseCheckResponse(await Promise.race([res.json(), timeout]));
    if (!parsed) return { status: "skipped", findings: [], note: "Threat feed skipped: unexpected response from the service." };
    return { status: "ok", findings: toFindings(parsed.findings, packages, servers), note: `Threat feed checked (updated ${parsed.feedUpdatedAt}).` };
  } catch (err) {
    const why = (err as Error)?.message === "timeout" ? `no answer within ${timeoutMs / 1000} s` : "the service could not be reached";
    return { status: "skipped", findings: [], note: `Threat feed skipped: ${why}.` };
  } finally {
    clearTimeout(timer);
  }
}
