import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import type { ConfigScope, ServerConfig } from "./types.js";

export interface DiscoveryResult {
  servers: ServerConfig[];
  /** Config files that were looked at, and whether they existed / parsed. */
  sources: { path: string; status: "ok" | "missing" | "unreadable" }[];
}

function claudeDesktopConfigPath(home: string): string {
  switch (platform()) {
    case "darwin":
      return join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
    case "win32":
      return join(process.env.APPDATA ?? join(home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
    default:
      return join(home, ".config", "Claude", "claude_desktop_config.json");
  }
}

function readJson(path: string, sources: DiscoveryResult["sources"]): any | undefined {
  if (!existsSync(path)) {
    sources.push({ path, status: "missing" });
    return undefined;
  }
  try {
    const data = JSON.parse(readFileSync(path, "utf8"));
    sources.push({ path, status: "ok" });
    return data;
  } catch {
    sources.push({ path, status: "unreadable" });
    return undefined;
  }
}

function toServers(block: unknown, scope: ConfigScope, source: string): ServerConfig[] {
  if (!block || typeof block !== "object") return [];
  return Object.entries(block as Record<string, any>).map(([name, raw]) => ({
    name,
    scope,
    source,
    type: typeof raw?.type === "string" ? raw.type : undefined,
    command: typeof raw?.command === "string" ? raw.command : undefined,
    args: Array.isArray(raw?.args) ? raw.args.map(String) : undefined,
    env: raw?.env && typeof raw.env === "object" ? stringRecord(raw.env) : undefined,
    url: typeof raw?.url === "string" ? raw.url : undefined,
    headers: raw?.headers && typeof raw.headers === "object" ? stringRecord(raw.headers) : undefined,
  }));
}

function stringRecord(obj: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, String(v)]));
}

/** Reads every MCP config Claude Code and Claude Desktop use. Read-only. */
export function discoverServers(projectDir: string, home = homedir()): DiscoveryResult {
  const sources: DiscoveryResult["sources"] = [];
  const servers: ServerConfig[] = [];
  const project = resolve(projectDir);

  const claudeJsonPath = join(home, ".claude.json");
  const claudeJson = readJson(claudeJsonPath, sources);
  if (claudeJson) {
    servers.push(...toServers(claudeJson.mcpServers, "user", claudeJsonPath));
    servers.push(...toServers(claudeJson.projects?.[project]?.mcpServers, "local", claudeJsonPath));
  }

  const projectMcpPath = join(project, ".mcp.json");
  servers.push(...toServers(readJson(projectMcpPath, sources)?.mcpServers, "project", projectMcpPath));

  const desktopPath = claudeDesktopConfigPath(home);
  servers.push(...toServers(readJson(desktopPath, sources)?.mcpServers, "claude-desktop", desktopPath));

  return { servers, sources };
}

export function describeServer(s: ServerConfig): string {
  return `server "${s.name}" (${s.scope})`;
}

export function transportOf(s: ServerConfig): "stdio" | "http" | "sse" | "unknown" {
  if (s.type === "sse") return "sse";
  if (s.url) return "http";
  if (s.command) return "stdio";
  return "unknown";
}
