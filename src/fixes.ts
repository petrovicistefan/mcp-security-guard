// Automatic fixes. Every fix is computed as a plan first (dry run) and written only on explicit
// confirmation, atomically, after a backup. Only project files are written: `.mcp.json` and
// `.claude/settings.json`. ~/.claude.json is never touched because Claude Code rewrites it live.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { baseCommand, NODE_RUNNERS, PY_RUNNERS } from "./rules/config-rules.js";
import { excerpt, maskSecret } from "./sanitize.js";
import { isEnvReference, looksLikeSecretValue } from "./secrets.js";
import { packagesOf, type Fetcher } from "./supply-chain.js";
import type { ServerConfig } from "./types.js";

export type FixKind = "permissions" | "pin-versions" | "env-refs";

export interface FileChange {
  path: string;
  /** Human-readable, secret-free description of each edit. */
  edits: string[];
  /** Full new file content. */
  content: string;
  /** Present when the original content holds secrets: the backup is written 0600 and must be deleted by the user. */
  backupHoldsSecrets?: boolean;
}

export interface FixPlan {
  changes: FileChange[];
  /** Things the user must do by hand (e.g. export a variable), or fixes that could not be planned. */
  notes: string[];
}

function readJsonFile(path: string): any {
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : {};
}

const serialize = (data: unknown) => JSON.stringify(data, null, 2) + "\n";

/** Merge `ask` rules into the project's .claude/settings.json, skipping rules already in ask or deny. */
export function planPermissions(projectDir: string, ask: string[]): FixPlan {
  const path = join(projectDir, ".claude", "settings.json");
  const settings = readJsonFile(path);
  const perms = (settings.permissions ??= {});
  const existing = new Set<string>([...(perms.ask ?? []), ...(perms.deny ?? [])]);
  const add = ask.filter((r) => !existing.has(r));
  if (!add.length) return { changes: [], notes: ask.length ? ["All recommended permission rules are already present."] : ["No tools need an approval rule."] };
  perms.ask = [...(perms.ask ?? []), ...add];
  return { changes: [{ path, edits: add.map((r) => `permissions.ask += "${r}"`), content: serialize(settings) }], notes: [] };
}

/** Rewrite unpinned npx/uvx packages in the project's .mcp.json to the registry's current version. */
export async function planPinVersions(projectDir: string, servers: ServerConfig[], fetcher: Fetcher = fetch as unknown as Fetcher): Promise<FixPlan> {
  const path = join(projectDir, ".mcp.json");
  if (!existsSync(path)) return { changes: [], notes: ["No project .mcp.json."] };
  const data = readJsonFile(path);
  const notes: string[] = [];
  const edits: string[] = [];
  for (const s of servers.filter((x) => x.source === path)) {
    const [pkg] = packagesOf(s);
    if (!pkg || pkg.version) continue;
    const raw = data.mcpServers?.[s.name];
    const args: string[] = raw?.args ?? [];
    const idx = args.findIndex((a) => a === pkg.name || a.startsWith(`${pkg.name}@`) || a.startsWith(`${pkg.name}==`) || a.startsWith(`${pkg.name}[`));
    if (idx < 0) continue;
    let version: string | undefined;
    try {
      const url = pkg.ecosystem === "npm" ? `https://registry.npmjs.org/${pkg.name.replace("/", "%2f")}` : `https://pypi.org/pypi/${encodeURIComponent(pkg.name)}/json`;
      const r = await fetcher(url);
      const d = r.ok ? await r.json() : undefined;
      version = pkg.ecosystem === "npm" ? d?.["dist-tags"]?.latest : d?.info?.version;
    } catch {
      // Reported below.
    }
    if (!version || !/^[0-9][0-9A-Za-z.+-]*$/.test(version)) {
      notes.push(`Could not resolve the current version of ${pkg.ecosystem} ${excerpt(pkg.name, 60)} for server "${excerpt(s.name, 40)}"; pin it by hand.`);
      continue;
    }
    const cmd = baseCommand(s.command ?? "");
    const pinned = NODE_RUNNERS.has(cmd) || cmd === "npm" || cmd === "pnpm" ? `${pkg.name}@${version}` : PY_RUNNERS.has(cmd) ? `${pkg.name}==${version}` : undefined;
    if (!pinned) continue;
    edits.push(`server "${excerpt(s.name, 40)}": ${excerpt(args[idx], 60)} → ${pinned}`);
    args[idx] = pinned;
  }
  return { changes: edits.length ? [{ path, edits, content: serialize(data) }] : [], notes: edits.length || notes.length ? notes : ["Every npx/uvx package in .mcp.json is already pinned."] };
}

/** Replace literal secrets in the project's .mcp.json env/headers with ${VAR} references. */
export function planEnvRefs(projectDir: string): FixPlan {
  const path = join(projectDir, ".mcp.json");
  if (!existsSync(path)) return { changes: [], notes: ["No project .mcp.json."] };
  const data = readJsonFile(path);
  const edits: string[] = [];
  const notes: string[] = [];
  for (const [name, raw] of Object.entries<any>(data.mcpServers ?? {})) {
    for (const field of ["env", "headers"] as const) {
      for (const [k, v] of Object.entries<string>(raw?.[field] ?? {})) {
        if (typeof v !== "string") continue;
        const bare = field === "headers" ? v.replace(/^Bearer\s+/i, "") : v;
        if (isEnvReference(bare) || !looksLikeSecretValue(k, bare)) continue;
        const varName = `${name}_${k}`.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
        raw[field][k] = field === "headers" && /^Bearer\s+/i.test(v) ? `Bearer \${${varName}}` : `\${${varName}}`;
        edits.push(`server "${excerpt(name, 40)}": ${field}.${k} (${maskSecret(bare)}) → \${${varName}}`);
        notes.push(`Set ${varName} in your shell or secret manager before starting Claude Code, e.g. \`export ${varName}=…\`, then rotate the old key if this file was ever committed or shared.`);
      }
    }
  }
  return { changes: edits.length ? [{ path, edits, content: serialize(data), backupHoldsSecrets: true }] : [], notes: edits.length ? notes : ["No literal secrets in .mcp.json."] };
}

/**
 * Backups live outside the project (so a backup holding a secret can never be committed), under
 * ~/.claude/mcp-security/backups/, named after the file, a hash of its path and the time.
 */
function backupPath(file: string): string {
  const dir = join(process.env.MCP_SECURITY_HOME ?? join(homedir(), ".claude", "mcp-security"), "backups");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const id = createHash("sha256").update(file).digest("hex").slice(0, 8);
  return join(dir, `${basename(file)}-${id}-${new Date().toISOString().replace(/[:.]/g, "-")}`);
}

/** Writes each change atomically after backing up the original (0600 when it holds secrets). */
export interface Applied {
  written: string[];
  backups: string[];
  /** Changed file → its backup (files that did not exist before have none). */
  backupOf: Record<string, string>;
}

export function applyPlan(plan: FixPlan): Applied {
  const written: string[] = [];
  const backups: string[] = [];
  const backupOf: Record<string, string> = {};
  for (const c of plan.changes) {
    mkdirSync(dirname(c.path), { recursive: true });
    if (existsSync(c.path)) {
      const backup = backupPath(c.path);
      // Recreate rather than overwrite: `mode` only applies to new files, and a backup holding a
      // secret must never exist with wider permissions, even briefly.
      rmSync(backup, { force: true });
      writeFileSync(backup, readFileSync(c.path), { mode: c.backupHoldsSecrets ? 0o600 : 0o644, flag: "wx" });
      if (c.backupHoldsSecrets) chmodSync(backup, 0o600);
      backups.push(backup);
      backupOf[c.path] = backup;
    }
    const tmp = `${c.path}.mcpsec-tmp`;
    writeFileSync(tmp, c.content);
    renameSync(tmp, c.path);
    written.push(c.path);
  }
  return { written, backups, backupOf };
}

export function describePlan(plan: FixPlan, applied?: Applied): string {
  const lines: string[] = [];
  for (const c of plan.changes) {
    lines.push(`**${c.path}**`, ...c.edits.map((e) => `- ${e}`));
    const backup = applied?.backupOf[c.path];
    if (c.backupHoldsSecrets && backup) lines.push(`- ⚠️ The backup \`${backup}\` still contains the secret (readable only by you): delete it once the variable is set.`);
  }
  if (plan.notes.length) lines.push("", ...plan.notes.map((n) => `- ${n}`));
  if (!plan.changes.length && !plan.notes.length) lines.push("Nothing to fix.");
  lines.unshift(applied ? `# Fixes applied (${applied.written.length} file(s))` : `# Proposed fixes (dry run, nothing written)`);
  if (applied?.backups.length) lines.push("", `Backups: ${applied.backups.join(", ")}`);
  return lines.join("\n");
}
