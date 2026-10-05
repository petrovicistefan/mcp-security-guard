import { excerpt } from "./sanitize.js";
import type { Finding, ServerConfig, ToolDefinition } from "./types.js";

export type Capability = "command-execution" | "destructive" | "filesystem-write" | "network-egress" | "read-only";

export interface ToolCapabilities {
  tool: string;
  capabilities: Capability[];
}

export interface ServerInventory {
  server: ServerConfig;
  tools: ToolCapabilities[];
  /** True when tools/list succeeded over HTTP with no credentials configured. */
  unauthenticatedRemote: boolean;
}

/** Split snake_case, kebab-case and camelCase names into lower-case words. */
const words = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

const EXEC_WORDS = new Set(["exec", "execute", "shell", "bash", "sh", "cmd", "powershell", "terminal", "spawn", "eval", "subprocess", "script", "repl"]);
// "Executes Python code", "runs shell commands"; but not "runs the code formatter".
const EXEC_PHRASE = /\bexecute[sd]?\s+(?:[a-z-]+\s+){0,2}(?:commands?|scripts?|code)\b|\bruns?\s+(?:an?\s+|the\s+|arbitrary\s+)?(?:shell|terminal|system|python|bash|javascript|js|node|sql)\s+(?:commands?|scripts?|code)\b|\bruns?\s+(?:arbitrary\s+)?commands?\b|\brun_command\b/i;
// "code" and "script" are left out: linters, formatters and fixers take code to analyse, not to run.
const EXEC_PARAMS = new Set(["command", "cmd", "shell", "bash", "shell_command"]);
const DESTRUCTIVE_VERBS = new Set(["delete", "remove", "rm", "drop", "destroy", "purge", "truncate", "kill", "terminate", "reset", "revoke", "wipe", "force"]);
const WRITE_VERBS = new Set(["write", "create", "update", "edit", "modify", "move", "rename", "upload", "push", "merge", "deploy", "publish", "send", "post", "transfer", "pay", "set", "insert", "patch", "commit", "apply", "install", "approve"]);
const FS_PARAMS = /^(path|file|filepath|file_path|filename|dir|directory|dest|destination|target_path)$/i;
const EGRESS_WORDS = new Set(["fetch", "http", "request", "browse", "navigate", "download", "webhook", "curl", "scrape", "crawl"]);
const EGRESS_PARAMS = /^(url|uri|endpoint|href|webhook|webhook_url|callback_url)$/i;
const READ_VERBS = new Set(["get", "list", "read", "search", "find", "query", "describe", "show", "view", "fetch", "lookup", "count", "check", "inspect", "status"]);

function paramNames(schema: unknown): string[] {
  const props = (schema as { properties?: Record<string, unknown> } | undefined)?.properties;
  return props && typeof props === "object" ? Object.keys(props) : [];
}

/** Deterministic classification from MCP annotations, the tool name and its parameter names. */
export function classifyTool(t: ToolDefinition): Capability[] {
  const w = words(t.name);
  const params = paramNames(t.inputSchema);
  const ann = (t.annotations ?? {}) as { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean };
  const caps = new Set<Capability>();

  if (w.some((x) => EXEC_WORDS.has(x)) || EXEC_PHRASE.test(`${t.name} ${t.description ?? ""}`) || params.some((p) => EXEC_PARAMS.has(p.toLowerCase()))) caps.add("command-execution");
  if (ann.destructiveHint === true || w.some((x) => DESTRUCTIVE_VERBS.has(x))) caps.add("destructive");
  if (w.some((x) => WRITE_VERBS.has(x)) && params.some((p) => FS_PARAMS.test(p))) caps.add("filesystem-write");
  if (w.some((x) => EGRESS_WORDS.has(x)) || params.some((p) => EGRESS_PARAMS.test(p))) caps.add("network-egress");

  // An explicit readOnlyHint wins over name heuristics for write classes, never for execution.
  if (ann.readOnlyHint === true) {
    caps.delete("destructive");
    caps.delete("filesystem-write");
  }
  if (!caps.size && (ann.readOnlyHint === true || READ_VERBS.has(w[0]))) caps.add("read-only");
  return [...caps];
}

export function inventory(server: ServerConfig, tools: ToolDefinition[]): ServerInventory {
  const hasCredentials = Object.keys(server.headers ?? {}).length > 0 || /[?&](api[_-]?key|token|key)=/i.test(server.url ?? "");
  return {
    server,
    tools: tools.map((t) => ({ tool: t.name, capabilities: classifyTool(t) })),
    unauthenticatedRemote: !!server.url && !hasCredentials,
  };
}

const list = (xs: string[], max = 6) => xs.slice(0, max).map((x) => `"${excerpt(x, 40)}"`).join(", ") + (xs.length > max ? ` (+${xs.length - max} more)` : "");

/** One finding per server and capability class, so a 40-tool server does not produce 40 findings. */
export function capabilityFindings(inv: ServerInventory): Finding[] {
  const s = inv.server;
  const where = `server "${s.name}" (${s.scope})`;
  const withCap = (c: Capability) => inv.tools.filter((t) => t.capabilities.includes(c)).map((t) => t.tool);
  const exec = withCap("command-execution");
  const destructive = withCap("destructive");
  const fsWrite = withCap("filesystem-write");
  const egress = withCap("network-egress");
  const out: Finding[] = [];

  if (exec.length) out.push({ severity: "medium", rule: "capability/command-execution", title: `${exec.length} tool(s) can execute commands or code: ${list(exec)}`, location: where, remediation: "Require approval for these tools (see the recommended permission rules) and run the server in a sandbox. Any prompt injection that reaches them becomes code execution." });
  if (destructive.length) out.push({ severity: "low", rule: "capability/destructive", title: `${destructive.length} tool(s) can delete or irreversibly change data: ${list(destructive)}`, location: where, remediation: "Set these to \"ask\" so a human confirms every call." });
  if (fsWrite.length) out.push({ severity: "low", rule: "capability/filesystem-write", title: `${fsWrite.length} tool(s) write to the file system: ${list(fsWrite)}`, location: where, remediation: "Limit the directories the server can reach, and require approval for writes outside the project." });
  if (egress.length) out.push({ severity: "info", rule: "capability/network-egress", title: `${egress.length} tool(s) can reach arbitrary URLs: ${list(egress)}`, location: where, remediation: "Arbitrary egress is an exfiltration channel. Prefer servers that restrict destinations." });
  if (inv.unauthenticatedRemote && (exec.length || destructive.length || fsWrite.length)) {
    out.push({ severity: "high", rule: "auth/unauthenticated-write-access", title: "Remote server exposes write or execution tools without any authentication", location: where, remediation: "Anyone who can reach this URL can call these tools. Put the server behind OAuth or a token, or remove it." });
  } else if (inv.unauthenticatedRemote) {
    out.push({ severity: "info", rule: "auth/unauthenticated-remote", title: "Remote server accepts connections without authentication (read-only tools)", location: where, remediation: "Fine for public documentation servers. Make sure it is not meant to expose private data." });
  }
  return out.map((f) => ({ ...f, file: s.source, server: s.name }));
}

/** Claude Code permission-rule name of a server's tool. Plugin servers are namespaced as plugin_<plugin>_<server>. */
export function permissionName(s: ServerConfig, tool: string): string | undefined {
  if (s.scope === "claude-desktop" || s.scope === "claude-ai") return undefined;
  const server = s.scope === "plugin" ? `plugin_${s.name.replace(":", "_")}` : s.name;
  return `mcp__${server}__${tool}`;
}

/** Suggested `permissions` block for settings.json: ask before execution, destructive and file-write tools. */
export function recommendPermissions(invs: ServerInventory[]): { ask: string[] } {
  const ask = invs.flatMap((inv) =>
    inv.tools
      .filter((t) => t.capabilities.some((c) => c === "command-execution" || c === "destructive" || c === "filesystem-write"))
      .map((t) => permissionName(inv.server, t.tool))
      .filter((n): n is string => !!n),
  );
  return { ask: [...new Set(ask)].sort() };
}
