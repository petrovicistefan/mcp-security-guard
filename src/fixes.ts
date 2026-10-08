// Automatic fixes. Every fix is computed as a plan first (dry run) and written only on explicit
// confirmation, atomically, after a backup. Only project files are written: `.mcp.json` and
// `.claude/settings.json`. ~/.claude.json is never touched because Claude Code rewrites it live.
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { baseCommand, NODE_RUNNERS, PY_RUNNERS } from "./rules/config-rules.js";
import { excerpt, maskSecret } from "./sanitize.js";
import { isEnvReference, looksLikeSecretValue } from "./secrets.js";
import { packagesOf, type Fetcher } from "./supply-chain.js";
import type { ServerConfig } from "./types.js";

export type FixKind = "permissions" | "pin-versions" | "env-refs";

export interface FileChange {
  path: string;
  /** Canonical project boundary captured during planning. */
  projectRoot: string;
  /** SHA-256 of the reviewed bytes, or null if the target did not exist. */
  originalHash: string | null;
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

function statIfPresent(path: string) {
  try { return lstatSync(path); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
}

/** Reject symlinks, non-regular targets and paths outside the two supported project files. */
function checkTarget(root: string, path: string): void {
  if (realpathSync(root) !== root || !lstatSync(root).isDirectory()) throw new Error("Project root changed or is not a real directory.");
  const rel = relative(root, resolve(path));
  if (isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`) ||
      ![".mcp.json", join(".claude", "settings.json")].includes(rel)) throw new Error("Fix target must be a supported file inside the project.");
  const parts = rel.split(sep);
  let current = root;
  for (let i = 0; i < parts.length; i++) {
    current = join(current, parts[i]);
    const stat = statIfPresent(current);
    if (!stat) continue;
    if (stat.isSymbolicLink()) throw new Error("Refusing symlink in fix target path.");
    if (i < parts.length - 1 ? !stat.isDirectory() : !stat.isFile()) throw new Error("Fix target path contains a non-regular file or directory.");
  }
}

function reviewedBytes(root: string, path: string): Buffer | undefined {
  checkTarget(root, path);
  if (!statIfPresent(path)) return undefined;
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd);
    if (!before.isFile()) throw new Error("Fix target is not a regular file.");
    const bytes = readFileSync(fd);
    checkTarget(root, path);
    const after = lstatSync(path);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) throw new Error("Fix target changed while reading.");
    return bytes;
  } finally { closeSync(fd); }
}

const hash = (bytes: Buffer | undefined) => bytes === undefined ? null : createHash("sha256").update(bytes).digest("hex");
function review(projectDir: string, file: string) {
  const projectRoot = realpathSync(projectDir);
  const path = join(projectRoot, file);
  const bytes = reviewedBytes(projectRoot, path);
  return { projectRoot, path, originalHash: hash(bytes), data: bytes === undefined ? {} : JSON.parse(bytes.toString("utf8")) };
}

const serialize = (data: unknown) => JSON.stringify(data, null, 2) + "\n";

/** Merge `ask` rules into the project's .claude/settings.json, skipping rules already in ask or deny. */
export function planPermissions(projectDir: string, ask: string[]): FixPlan {
  const { path, projectRoot, originalHash, data: settings } = review(projectDir, join(".claude", "settings.json"));
  const perms = (settings.permissions ??= {});
  const existing = new Set<string>([...(perms.ask ?? []), ...(perms.deny ?? [])]);
  const add = ask.filter((r) => !existing.has(r));
  if (!add.length) return { changes: [], notes: ask.length ? ["All recommended permission rules are already present."] : ["No tools need an approval rule."] };
  perms.ask = [...(perms.ask ?? []), ...add];
  return { changes: [{ path, projectRoot, originalHash, edits: add.map((r) => `permissions.ask += "${r}"`), content: serialize(settings) }], notes: [] };
}

/** Rewrite unpinned npx/uvx packages in the project's .mcp.json to the registry's current version. */
export async function planPinVersions(projectDir: string, servers: ServerConfig[], fetcher: Fetcher = fetch as unknown as Fetcher): Promise<FixPlan> {
  const { path, projectRoot, originalHash, data } = review(projectDir, ".mcp.json");
  if (originalHash === null) return { changes: [], notes: ["No project .mcp.json."] };
  const notes: string[] = [];
  const edits: string[] = [];
  for (const s of servers.filter((x) => resolve(x.source) === resolve(join(projectDir, ".mcp.json")))) {
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
  return { changes: edits.length ? [{ path, projectRoot, originalHash, edits, content: serialize(data) }] : [], notes: edits.length || notes.length ? notes : ["Every npx/uvx package in .mcp.json is already pinned."] };
}

/** Replace literal secrets in the project's .mcp.json env/headers with ${VAR} references. */
export function planEnvRefs(projectDir: string): FixPlan {
  const { path, projectRoot, originalHash, data } = review(projectDir, ".mcp.json");
  if (originalHash === null) return { changes: [], notes: ["No project .mcp.json."] };
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
  return { changes: edits.length ? [{ path, projectRoot, originalHash, edits, content: serialize(data), backupHoldsSecrets: true }] : [], notes: edits.length ? notes : ["No literal secrets in .mcp.json."] };
}

/**
 * Backups live outside the project (so a backup holding a secret can never be committed), under
 * ~/.claude/mcp-security/backups/, named after the file, a hash of its path and the time.
 */
function backupPath(file: string): string {
  const home = process.env.MCP_SECURITY_HOME;
  const base = home ? resolve(home) : realpathSync(homedir());
  const suffix = home ? ["backups"] : [".claude", "mcp-security", "backups"];
  // The configured home is trusted, but must itself be a real directory. System
  // ancestors may resolve through /var -> /private/var on macOS.
  const baseStat = statIfPresent(base);
  if (baseStat?.isSymbolicLink() || (baseStat && !baseStat.isDirectory())) throw new Error("Backup home must be a real directory.");
  mkdirSync(base, { recursive: true, mode: 0o700 });
  let dir = realpathSync(base);
  for (const part of suffix) {
    dir = join(dir, part);
    const stat = statIfPresent(dir);
    if (stat && (stat.isSymbolicLink() || !stat.isDirectory())) throw new Error("Backup path must not contain symlinks or non-directories.");
    if (!stat) mkdirSync(dir, { mode: 0o700 });
  }
  const id = createHash("sha256").update(file).digest("hex").slice(0, 8);
  // Exclusive private directory: concurrent plans cannot collide or overwrite a prepared backup.
  return join(mkdtempSync(join(dir, `${basename(file)}-${id}-`)), "original");
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
  // Preflight the entire batch before creating directories or backing up any file.
  const seen = new Set<string>();
  for (const c of plan.changes) {
    if (typeof c.projectRoot !== "string" || !(c.originalHash === null || typeof c.originalHash === "string")) throw new Error("Fix plan lacks a reviewed project boundary or version; replan.");
    checkTarget(c.projectRoot, c.path);
    if (seen.has(c.path)) throw new Error("Duplicate fix target in plan.");
    seen.add(c.path);
    if (hash(reviewedBytes(c.projectRoot, c.path)) !== c.originalHash) throw new Error("Fix conflict: file changed after planning; replan.");
  }
  for (const c of plan.changes) {
    checkTarget(c.projectRoot, c.path);
    mkdirSync(dirname(c.path), { recursive: true, mode: 0o700 });
    checkTarget(c.projectRoot, c.path);
    // Cooperative exclusive lock also serializes independent applyPlan processes.
    const lock = `${c.path}.mcpsec-lock`;
    const lockFd = openSync(lock, "wx", 0o600);
    let tempDir: string | undefined;
    try {
      const original = reviewedBytes(c.projectRoot, c.path);
      if (hash(original) !== c.originalHash) throw new Error("Fix conflict: file changed after planning; replan.");
      if (original !== undefined) {
        const backup = backupPath(c.path);
        writeFileSync(backup, original, { mode: 0o600, flag: "wx" });
        backups.push(backup);
        backupOf[c.path] = backup;
      }
      checkTarget(c.projectRoot, c.path);
      tempDir = mkdtempSync(join(dirname(c.path), ".mcpsec-"));
      const tmp = join(tempDir, "content");
      writeFileSync(tmp, c.content, { mode: 0o600, flag: "wx" });
      checkTarget(c.projectRoot, c.path);
      if (hash(reviewedBytes(c.projectRoot, c.path)) !== c.originalHash) throw new Error("Fix conflict: file changed during apply; replan.");
      renameSync(tmp, c.path);
      written.push(c.path);
    } finally {
      closeSync(lockFd);
      // Revalidate before cleaning up so a replaced parent cannot redirect removals.
      checkTarget(c.projectRoot, c.path);
      rmSync(lock, { force: true });
      if (tempDir) rmSync(tempDir, { recursive: true, force: true });
    }
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
