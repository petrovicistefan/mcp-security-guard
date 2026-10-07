// Toxic-flow analysis ("lethal trifecta"): an agent that can read untrusted content, reach private data
// and send data out can be steered by an injected instruction into leaking it. Each leg is harmless on
// its own; the risk is the combination, which often spans several servers. This is a posture finding, not
// a defect: it lists the tools on each leg and which ones to put behind approval.
import { classifyTool, permissionName } from "./capabilities.js";
import { excerpt } from "./sanitize.js";
import type { Finding, ServerConfig, ToolDefinition } from "./types.js";

export type Leg = "untrusted" | "private" | "egress";

const words = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

const READ_VERBS = new Set(["get", "list", "read", "search", "find", "query", "fetch", "view", "show", "lookup", "browse", "scrape", "crawl", "download", "navigate", "open", "load", "cat", "inspect", "retrieve", "pull"]);
const SEND_VERBS = new Set(["send", "post", "publish", "share", "forward", "reply", "tweet", "notify", "webhook", "broadcast", "email"]);
const WRITE_VERBS = new Set(["create", "add", "update", "write", "push", "upload", "submit", "open", "comment", "append", "put"]);
/** Objects other people can see or that leave the machine when written. */
const OUTBOUND_OBJECTS = new Set(["issue", "issues", "comment", "comments", "gist", "pr", "pull", "message", "messages", "email", "emails", "mail", "tweet", "post", "release", "review", "thread", "channel", "page", "ticket", "invite", "event"]);
/** Content written by people other than the user. */
const UNTRUSTED_OBJECTS = new Set(["email", "emails", "mail", "inbox", "message", "messages", "thread", "threads", "channel", "comment", "comments", "issue", "issues", "pr", "prs", "pull", "review", "reviews", "ticket", "tickets", "feed", "rss", "tweet", "tweets", "post", "posts", "web", "webpage", "page", "url", "website", "site", "browse", "scrape", "crawl", "fetch", "navigate", "download", "dm", "dms", "notification", "notifications"]);
const PRIVATE_OBJECTS = new Set(["file", "files", "directory", "dir", "folder", "path", "database", "db", "table", "tables", "sql", "record", "records", "secret", "secrets", "credential", "credentials", "vault", "env", "drive", "note", "notes", "notebook", "calendar", "contact", "contacts", "customer", "customers", "repo", "repos", "repository", "commit", "commits", "branch", "email", "emails", "mail", "inbox", "message", "messages", "memory", "memories", "dm", "dms", "issue", "issues"]);
// `query` is left out on purpose: every search tool has one, and public search is not private data.
const DB_PARAMS = /^(sql|statement)$/i;
const PATH_PARAMS = /^(path|file|filepath|file_path|filename|dir|directory)$/i;

function paramNames(schema: unknown): string[] {
  const props = (schema as { properties?: Record<string, unknown> } | undefined)?.properties;
  return props && typeof props === "object" ? Object.keys(props) : [];
}

/** Which legs of the trifecta a tool provides, from its name, parameters and annotations. Conservative: no description matching. */
export function legsOf(tool: ToolDefinition): Leg[] {
  const w = words(tool.name);
  const params = paramNames(tool.inputSchema);
  const caps = classifyTool(tool);
  const ann = (tool.annotations ?? {}) as { readOnlyHint?: boolean };
  const legs = new Set<Leg>();

  // A tool that runs commands can read files, fetch pages and send data on its own.
  if (caps.includes("command-execution")) return ["untrusted", "private", "egress"];

  const readLike = ann.readOnlyHint === true || READ_VERBS.has(w[0]) || caps.includes("read-only");
  const writeLike = !readLike && (WRITE_VERBS.has(w[0]) || w.some((x) => SEND_VERBS.has(x)));

  if (caps.includes("network-egress")) {
    legs.add("egress");
    if (readLike || w.some((x) => ["fetch", "browse", "scrape", "crawl", "navigate", "download", "http", "curl", "request"].includes(x))) legs.add("untrusted");
  }
  if (readLike) {
    if (w.some((x) => UNTRUSTED_OBJECTS.has(x))) legs.add("untrusted");
    if (w.some((x) => PRIVATE_OBJECTS.has(x)) || params.some((p) => PATH_PARAMS.test(p) || DB_PARAMS.test(p))) legs.add("private");
  }
  if (!readLike) {
    if (w.some((x) => SEND_VERBS.has(x))) legs.add("egress");
    else if (writeLike && w.some((x) => OUTBOUND_OBJECTS.has(x))) legs.add("egress");
  }
  return [...legs];
}

const list = (xs: string[], max = 5) => xs.slice(0, max).map((x) => `"${excerpt(x, 40)}"`).join(", ") + (xs.length > max ? ` (+${xs.length - max} more)` : "");

interface Surface {
  server: ServerConfig;
  tools: ToolDefinition[];
}

const REMEDIATION = "Injected text in the untrusted source can tell the model to read private data and send it out. Put the send-out tools behind approval (permissions.ask), keep untrusted sources and private data out of the same session where you can, and pin the servers involved.";

/**
 * One finding per server that holds all three legs by itself, and one for the whole set when the legs
 * only come together across servers. Servers launched for other clients do not count: only what Claude Code loads.
 */
export function toxicFlowFindings(surfaces: Surface[]): Finding[] {
  const perServer = surfaces.map((s) => {
    const legs: Record<Leg, string[]> = { untrusted: [], private: [], egress: [] };
    for (const t of s.tools) for (const l of legsOf(t)) legs[l].push(t.name);
    return { ...s, legs };
  });
  const has = (legs: Record<Leg, string[]>) => legs.untrusted.length > 0 && legs.private.length > 0 && legs.egress.length > 0;
  const out: Finding[] = [];

  for (const s of perServer) {
    if (!has(s.legs)) continue;
    const ask = s.legs.egress.map((t) => permissionName(s.server, t)).filter((n): n is string => !!n);
    out.push({
      severity: "low",
      rule: "flow/single-server-trifecta",
      title: `One server combines untrusted input, private data and a way to send data out (untrusted: ${list(s.legs.untrusted)}; private: ${list(s.legs.private)}; send out: ${list(s.legs.egress)})`,
      location: `server "${s.server.name}" (${s.server.scope})`,
      remediation: `${REMEDIATION}${ask.length ? ` Suggested permissions.ask entries: ${ask.slice(0, 6).map((n) => `"${excerpt(n, 80)}"`).join(", ")}${ask.length > 6 ? ", …" : ""}.` : ""}`,
      file: s.server.source,
      server: s.server.name,
    });
  }

  const merged: Record<Leg, { server: ServerConfig; tools: string[] }[]> = { untrusted: [], private: [], egress: [] };
  for (const s of perServer) for (const l of ["untrusted", "private", "egress"] as Leg[]) if (s.legs[l].length) merged[l].push({ server: s.server, tools: s.legs[l] });
  const involved = new Set(Object.values(merged).flat().map((x) => x.server));
  const alone = perServer.some((s) => has(s.legs));
  if (!alone && merged.untrusted.length && merged.private.length && merged.egress.length && involved.size >= 2) {
    const who = (l: Leg) => merged[l].map((x) => `${excerpt(x.server.name, 40)}: ${list(x.tools, 3)}`).join("; ");
    const ask = merged.egress.flatMap((x) => x.tools.map((t) => permissionName(x.server, t))).filter((n): n is string => !!n);
    out.push({
      severity: "info",
      rule: "flow/cross-server-trifecta",
      title: `Servers together form a leak path: untrusted input (${who("untrusted")}), private data (${who("private")}), send out (${who("egress")})`,
      location: `servers ${[...involved].map((s) => `"${excerpt(s.name, 40)}"`).join(", ")}`,
      remediation: `${REMEDIATION}${ask.length ? ` Suggested permissions.ask entries: ${[...new Set(ask)].slice(0, 6).map((n) => `"${excerpt(n, 80)}"`).join(", ")}${ask.length > 6 ? ", …" : ""}.` : ""}`,
    });
  }
  return out;
}
