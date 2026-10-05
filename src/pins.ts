import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { ServerConfig, ToolDefinition } from "./types.js";

export interface PinEntry {
  pinnedAt: string;
  tools: Record<string, string>;
  /** Hash of the launch config (command/args/url/env *names*). Absent in pins written before 0.2. */
  config?: string;
  /** True when instructions, prompts and resources were pinned too (v0.6+). Older pins hold tools only. */
  surface?: boolean;
}

export interface PinFile {
  version: 1;
  servers: Record<string, PinEntry>;
}

export interface Drift {
  added: string[];
  removed: string[];
  changed: string[];
}

export function pinsPath(): string {
  return join(process.env.MCP_SECURITY_HOME ?? join(homedir(), ".claude", "mcp-security"), "pins.json");
}

function stableStringify(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v as object)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify((v as any)[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

/** Hash of everything the model sees about a tool. Any change to wording or schema changes the hash. */
export function hashTool(t: ToolDefinition): string {
  return createHash("sha256")
    .update(stableStringify({ name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations }))
    .digest("hex");
}

const MAX_HASHED_FILE = 20 * 1024 * 1024;

/**
 * Content hashes of local files the launch command points at (`node ./server.js`, `python /opt/x.py`),
 * so editing a local server counts as drift too. Relative paths resolve against the config file's directory.
 */
export function localFileHashes(s: ServerConfig): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of [s.command, ...(s.args ?? [])]) {
    if (!a || a.startsWith("-") || a.includes("${") || !/[\\/]|\.(m?[jt]s|cjs|py|rb|sh|php|jar)$/i.test(a)) continue;
    const p = isAbsolute(a) ? a : resolve(dirname(s.source), a);
    try {
      const st = statSync(p);
      if (st.isFile() && st.size <= MAX_HASHED_FILE) out[a] = createHash("sha256").update(readFileSync(p)).digest("hex");
    } catch {
      // Not a local file (e.g. a package name): nothing to hash.
    }
  }
  return out;
}

/** Detects a changed launch command, package version or local server file. Env and header *values* are excluded so rotating a secret is not drift. */
export function hashConfig(s: ServerConfig): string {
  const files = localFileHashes(s);
  return createHash("sha256")
    .update(stableStringify({ type: s.type, command: s.command, args: s.args, url: s.url, env: Object.keys(s.env ?? {}).sort(), headers: Object.keys(s.headers ?? {}).sort(), ...(Object.keys(files).length ? { files } : {}) }))
    .digest("hex");
}

/** `definitions` are the tools plus the prefixed instruction/prompt/resource definitions. */
export function pinEntry(s: ServerConfig, definitions: ToolDefinition[]): PinEntry {
  return { pinnedAt: new Date().toISOString(), tools: Object.fromEntries(definitions.map((t) => [t.name, hashTool(t)])), config: hashConfig(s), surface: true };
}

export function loadPins(path = pinsPath()): PinFile {
  if (!existsSync(path)) return { version: 1, servers: {} };
  try {
    const data = JSON.parse(readFileSync(path, "utf8"));
    return data?.version === 1 && data.servers ? data : { version: 1, servers: {} };
  } catch {
    return { version: 1, servers: {} };
  }
}

export function savePins(pins: PinFile, path = pinsPath()): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(pins, null, 2), { mode: 0o600 });
  renameSync(tmp, path);
}

export function pinKey(scope: string, name: string): string {
  return `${scope}:${name}`;
}

/** Instructions, prompts and resources are pinned under prefixed names (see surfaceDefinitions). */
const NON_TOOL = /^(#instructions$|prompt:|resource:|template:)/;

export function computeDrift(pin: Pick<PinEntry, "tools" | "surface">, tools: ToolDefinition[]): Drift {
  const pinned = pin.tools;
  // Pins written before v0.6 hold tools only: do not report every prompt or resource as "added".
  const legacy = !pin.surface;
  const current = Object.fromEntries(tools.filter((t) => !(legacy && NON_TOOL.test(t.name))).map((t) => [t.name, hashTool(t)]));
  return {
    added: Object.keys(current).filter((n) => !(n in pinned)),
    removed: Object.keys(pinned).filter((n) => !(n in current)),
    changed: Object.keys(current).filter((n) => n in pinned && pinned[n] !== current[n]),
  };
}

export function hasDrift(d: Drift): boolean {
  return d.added.length + d.removed.length + d.changed.length > 0;
}
