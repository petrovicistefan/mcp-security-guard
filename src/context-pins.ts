// Pins for the text Claude reads besides MCP tools: a SHA-256 per skill, command, agent, rule, CLAUDE.md,
// hook config and bundled script, grouped by origin (user, project, one plugin). A later scan reports
// what changed since, which is how a plugin or repository that rewrites a skill after you approved it
// (a rug pull) shows up. A plugin that changed under the same version is the dangerous case.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { ContextDiscovery, ContextFile } from "./context-files.js";
import { analyzeContextFile } from "./rules/context-rules.js";
import { excerpt } from "./sanitize.js";
import type { Finding } from "./types.js";

export interface ContextPinOrigin {
  pinnedAt: string;
  /** Plugin version when it was pinned. */
  version?: string;
  /** Path inside the origin's root → SHA-256 of the file. */
  files: Record<string, string>;
}

export interface ContextPinFile {
  version: 1;
  origins: Record<string, ContextPinOrigin>;
}

export function contextPinsPath(): string {
  return join(process.env.MCP_SECURITY_HOME ?? join(homedir(), ".claude", "mcp-security"), "context-pins.json");
}

export const hashText = (text: string) => createHash("sha256").update(text).digest("hex");

/** Plugins and the user's home are the same everywhere; a project is identified by its directory. */
export const originKey = (origin: string, projectDir: string) => (origin === "project" ? `project:${resolve(projectDir)}` : origin);

export function loadContextPins(path = contextPinsPath()): ContextPinFile {
  if (!existsSync(path)) return { version: 1, origins: {} };
  try {
    const data = JSON.parse(readFileSync(path, "utf8"));
    return data?.version === 1 && data.origins && typeof data.origins === "object" ? data : { version: 1, origins: {} };
  } catch {
    return { version: 1, origins: {} };
  }
}

export function saveContextPins(pins: ContextPinFile, path = contextPinsPath()): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(pins, null, 2), { mode: 0o600 });
  renameSync(tmp, path);
}

interface Snapshot {
  key: string;
  origin: string;
  version?: string;
  files: Record<string, string>;
}

/** Current hashes grouped by origin. */
export function snapshotContext(d: ContextDiscovery, projectDir: string): Snapshot[] {
  const byOrigin = new Map<string, Snapshot>();
  for (const f of d.files) {
    const key = originKey(f.origin, projectDir);
    const snap = byOrigin.get(key) ?? { key, origin: f.origin, ...(d.versions[f.origin] ? { version: d.versions[f.origin] } : {}), files: {} };
    snap.files[f.rel] = hashText(f.text);
    byOrigin.set(key, snap);
  }
  return [...byOrigin.values()].sort((a, b) => a.key.localeCompare(b.key));
}

/** Origins that have at least one critical or high finding right now; these are not pinned without `force`. */
export function flaggedOrigins(files: ContextFile[], projectDir: string): Set<string> {
  const out = new Set<string>();
  for (const f of files) if (analyzeContextFile(f).some((x) => x.severity === "critical" || x.severity === "high")) out.add(originKey(f.origin, projectDir));
  return out;
}

export interface PinResult {
  pinned: { key: string; files: number; version?: string }[];
  skipped: { key: string; reason: string }[];
}

/** Records the current hashes of every origin (or only `only`). Origins with critical/high findings are skipped unless `force`. */
export function pinContext(d: ContextDiscovery, projectDir: string, opts: { only?: string[]; force?: boolean } = {}, path = contextPinsPath()): PinResult {
  const pins = loadContextPins(path);
  const flagged = opts.force ? new Set<string>() : flaggedOrigins(d.files, projectDir);
  const result: PinResult = { pinned: [], skipped: [] };
  for (const snap of snapshotContext(d, projectDir)) {
    if (opts.only?.length && !opts.only.includes(snap.origin) && !opts.only.includes(snap.key)) continue;
    if (flagged.has(snap.key)) {
      result.skipped.push({ key: snap.key, reason: "has critical or high findings; review them, or pin with force" });
      continue;
    }
    pins.origins[snap.key] = { pinnedAt: new Date().toISOString(), ...(snap.version ? { version: snap.version } : {}), files: snap.files };
    result.pinned.push({ key: snap.key, files: Object.keys(snap.files).length, ...(snap.version ? { version: snap.version } : {}) });
  }
  saveContextPins(pins, path);
  return result;
}

export interface ContextDrift {
  /** One line per origin for the report: unchanged, changed or not pinned. */
  lines: string[];
  findings: Finding[];
}

const list = (xs: string[], max = 4) => xs.slice(0, max).map((x) => `"${excerpt(x, 60)}"`).join(", ") + (xs.length > max ? ` (+${xs.length - max} more)` : "");

/**
 * Compares the current files of every pinned origin with its pin. A pinned plugin whose files changed under the
 * same version is the rug-pull pattern (high); a version bump is an ordinary update (low); your own files and
 * the repository's are medium or low. Changed or added files that now carry critical/high findings raise it to high.
 */
export function contextDrift(d: ContextDiscovery, projectDir: string, pins = loadContextPins()): ContextDrift {
  const lines: string[] = [];
  const findings: Finding[] = [];
  const present = new Set<string>();

  for (const snap of snapshotContext(d, projectDir)) {
    present.add(snap.key);
    const label = snap.key.startsWith("project:") ? "project" : snap.key;
    const pin = pins.origins[snap.key];
    if (!pin) {
      lines.push(`- **${excerpt(label, 60)}**: not pinned yet`);
      continue;
    }
    const changed = Object.keys(snap.files).filter((r) => r in pin.files && pin.files[r] !== snap.files[r]);
    const added = Object.keys(snap.files).filter((r) => !(r in pin.files));
    const removed = Object.keys(pin.files).filter((r) => !(r in snap.files));
    if (!changed.length && !added.length && !removed.length) {
      lines.push(`- **${excerpt(label, 60)}**: unchanged since ${pin.pinnedAt}`);
      continue;
    }
    lines.push(`- **${excerpt(label, 60)}**: ⚠️ changed since ${pin.pinnedAt}`);

    const versionBump = !!(pin.version && snap.version && pin.version !== snap.version);
    const isPlugin = snap.origin.startsWith("plugin:");
    const touched = new Set([...changed, ...added]);
    const serious = d.files.filter((f) => originKey(f.origin, projectDir) === snap.key && touched.has(f.rel)).flatMap(analyzeContextFile).filter((f) => f.severity === "critical" || f.severity === "high");
    let severity: Finding["severity"] = isPlugin ? (versionBump ? "low" : "high") : snap.origin === "project" ? "medium" : "low";
    if (serious.length) severity = "high";
    const parts = [changed.length && `${changed.length} changed`, added.length && `${added.length} added`, removed.length && `${removed.length} removed`].filter(Boolean).join(", ");
    const what = isPlugin && versionBump ? `Plugin updated ${excerpt(pin.version!, 20)} → ${excerpt(snap.version!, 20)}` : isPlugin ? "Plugin files changed without a version change" : snap.origin === "project" ? "Project skills, commands or CLAUDE.md changed since pinning" : "Your skills, commands or CLAUDE.md changed since pinning";
    findings.push({
      severity,
      rule: isPlugin && versionBump ? "drift/context-updated" : "drift/context-changed",
      title: `${what}: ${parts}${serious.length ? `, ${serious.length} critical/high finding(s) in them` : ""}`,
      location: `${label} › ${[...changed, ...added].slice(0, 4).map((r) => excerpt(r, 50)).join(", ") || "removed files only"}`,
      evidence: [changed.length && `changed: ${list(changed)}`, added.length && `added: ${list(added)}`, removed.length && `removed: ${list(removed)}`].filter(Boolean).join("; "),
      remediation: isPlugin && !versionBump
        ? "A plugin that rewrites files without a new version is the rug-pull pattern. Read the changed files, or reinstall the plugin from its source, then re-pin."
        : "Read what changed (git diff for a repository, the plugin's changelog for an update). If you expected it, run pin_context to accept it.",
    });
  }
  for (const key of Object.keys(pins.origins)) {
    const belongs = !key.startsWith("project:") || key === `project:${resolve(projectDir)}`;
    if (belongs && !present.has(key)) lines.push(`- **${excerpt(key.startsWith("project:") ? "project" : key, 60)}**: pinned, but no files found now`);
  }
  return { lines, findings };
}
