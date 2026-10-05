import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ToolDefinition } from "./types.js";

export interface PinFile {
  version: 1;
  servers: Record<string, { pinnedAt: string; tools: Record<string, string> }>;
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

export function computeDrift(pinned: Record<string, string>, tools: ToolDefinition[]): Drift {
  const current = Object.fromEntries(tools.map((t) => [t.name, hashTool(t)]));
  return {
    added: Object.keys(current).filter((n) => !(n in pinned)),
    removed: Object.keys(pinned).filter((n) => !(n in current)),
    changed: Object.keys(current).filter((n) => n in pinned && pinned[n] !== current[n]),
  };
}

export function hasDrift(d: Drift): boolean {
  return d.added.length + d.removed.length + d.changed.length > 0;
}
