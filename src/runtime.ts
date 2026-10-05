// Runtime checks on MCP tool calls, used by the PreToolUse/PostToolUse hooks. Pure functions plus the
// audit log; no MCP SDK import, so the hook bundle stays small and starts fast.
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { analyzeTools } from "./rules/tool-rules.js";
import { findKnownSecret } from "./secrets.js";
import type { Finding } from "./types.js";

/** Rules worth interrupting for when they appear in tool *output* (fetched pages, issues, files…). */
const OUTPUT_RULES = new Set([
  "tool/instruction-override",
  "tool/conceal-from-user",
  "tool/role-hijack",
  "tool/hidden-instruction-tag",
  "tool/invisible-characters",
  "tool/ansi-escape",
  "tool/markdown-exfiltration",
  "tool/context-harvesting",
  "tool/sensitive-path",
]);
const MAX_SCAN_BYTES = 256 * 1024;
/** Hostile outputs can nest arbitrarily; recursion stops here instead of overflowing the stack. */
const MAX_DEPTH = 64;
const MAX_LOG_BYTES = 10 * 1024 * 1024;

export interface McpToolName {
  server: string;
  tool: string;
}

/** `mcp__github__create_issue` → { server: "github", tool: "create_issue" }. */
export function parseToolName(name: string): McpToolName | undefined {
  const m = /^mcp__(.+?)__(.+)$/.exec(name);
  return m ? { server: m[1], tool: m[2] } : undefined;
}

export function isOwnTool(server: string): boolean {
  return server === "mcp-security" || server === "plugin_mcp-security_mcp-security";
}

/** Every string inside an arbitrary JSON value, with its path, up to a byte budget. */
export function strings(value: unknown, path = "$", out: { path: string; text: string }[] = [], budget = { left: MAX_SCAN_BYTES }, depth = 0): { path: string; text: string }[] {
  if (budget.left <= 0 || depth > MAX_DEPTH) return out;
  if (typeof value === "string") {
    const text = value.slice(0, budget.left);
    budget.left -= text.length;
    out.push({ path, text });
  } else if (Array.isArray(value)) {
    for (let i = 0; i < value.length && budget.left > 0; i++) strings(value[i], `${path}[${i}]`, out, budget, depth + 1);
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (budget.left <= 0) break;
      strings(v, `${path}.${k}`, out, budget, depth + 1);
    }
  }
  return out;
}

export interface SecretHit {
  path: string;
  kind: string;
  masked: string;
}

export function secretsIn(value: unknown): SecretHit[] {
  return strings(value).flatMap(({ path, text }) => {
    const hit = findKnownSecret(text);
    return hit ? [{ path, ...hit }] : [];
  });
}

/** Prompt-injection and exfiltration patterns in a tool's output, at high severity or above. */
export function injectionsIn(server: string, tool: string, output: unknown): Finding[] {
  const chunks = strings(output).filter((s) => s.text.length >= 12);
  return chunks.flatMap(({ path, text }) =>
    analyzeTools(server, [{ name: tool, description: text }])
      .filter((f) => OUTPUT_RULES.has(f.rule) && (f.severity === "critical" || f.severity === "high"))
      .map((f) => ({ ...f, rule: f.rule === "tool/invisible-characters" || f.rule === "tool/ansi-escape" ? f.rule : "runtime/injection-in-output", location: `output of ${server}/${tool} at ${path}` })),
  );
}

// ── Audit log ────────────────────────────────────────────────────────────

export interface AuditEntry {
  ts: string;
  event: "pre" | "post";
  session?: string;
  server: string;
  tool: string;
  /** SHA-256 of the canonical input. Content is never logged. */
  inputSha256?: string;
  inputBytes?: number;
  outputBytes?: number;
  decision?: "ask" | "deny";
  findings: string[];
}

export function auditLogPath(): string {
  return join(process.env.MCP_SECURITY_HOME ?? join(homedir(), ".claude", "mcp-security"), "audit.jsonl");
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value ?? null)).digest("hex");
}

export function appendAudit(entry: AuditEntry, path = auditLogPath()): void {
  if ((process.env.MCP_SECURITY_AUDIT_LOG ?? "on").toLowerCase() === "off") return;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  if (existsSync(path) && statSync(path).size > MAX_LOG_BYTES) renameSync(path, `${path}.1`);
  appendFileSync(path, JSON.stringify(entry) + "\n", { mode: 0o600 });
}

export function readAudit(path = auditLogPath()): AuditEntry[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .flatMap((l) => {
      try {
        return [JSON.parse(l) as AuditEntry];
      } catch {
        return [];
      }
    });
}

export interface AuditSummary {
  calls: number;
  since?: string;
  byServer: { server: string; calls: number; tools: number; withFindings: number }[];
  flagged: AuditEntry[];
}

export function summarizeAudit(entries: AuditEntry[], sinceHours?: number): AuditSummary {
  const cutoff = sinceHours ? Date.now() - sinceHours * 3600_000 : 0;
  const recent = entries.filter((e) => Date.parse(e.ts) >= cutoff);
  const posts = recent.filter((e) => e.event === "post");
  const servers = new Map<string, { calls: number; tools: Set<string>; withFindings: number }>();
  for (const e of posts) {
    const s = servers.get(e.server) ?? { calls: 0, tools: new Set(), withFindings: 0 };
    s.calls++;
    s.tools.add(e.tool);
    if (e.findings.length) s.withFindings++;
    servers.set(e.server, s);
  }
  return {
    calls: posts.length,
    since: recent[0]?.ts,
    byServer: [...servers.entries()].map(([server, s]) => ({ server, calls: s.calls, tools: s.tools.size, withFindings: s.withFindings })).sort((a, b) => b.calls - a.calls),
    flagged: recent.filter((e) => e.findings.length || e.decision),
  };
}
