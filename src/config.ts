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

export function toServers(block: unknown, scope: ConfigScope, source: string): ServerConfig[] {
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

  servers.push(...discoverPluginServers(project, home, sources));

  const desktopPath = claudeDesktopConfigPath(home);
  servers.push(...toServers(readJson(desktopPath, sources)?.mcpServers, "claude-desktop", desktopPath));

  return { servers, sources };
}

/** `enabledPlugins` merged from user, project and local settings; later files win. */
function enabledPlugins(project: string, home: string, sources: DiscoveryResult["sources"]): Record<string, boolean> {
  const merged: Record<string, boolean> = {};
  for (const p of [join(home, ".claude", "settings.json"), join(project, ".claude", "settings.json"), join(project, ".claude", "settings.local.json")]) {
    if (!existsSync(p)) continue;
    const ep = readJson(p, sources)?.enabledPlugins;
    if (ep && typeof ep === "object") Object.assign(merged, ep);
  }
  return merged;
}

function substitutePluginRoot(s: ServerConfig, root: string): ServerConfig {
  const sub = (v: string) => v.replaceAll("${CLAUDE_PLUGIN_ROOT}", root);
  const subRec = (r?: Record<string, string>) => (r ? Object.fromEntries(Object.entries(r).map(([k, v]) => [k, sub(v)])) : undefined);
  return { ...s, command: s.command && sub(s.command), args: s.args?.map(sub), env: subRec(s.env), url: s.url && sub(s.url), headers: subRec(s.headers) };
}

/**
 * MCP servers shipped inside installed Claude Code plugins, from the plugin's `.mcp.json` and the
 * `mcpServers` field of `.claude-plugin/plugin.json` (inline object or path). Disabled plugins and
 * project-scoped installs for other projects are skipped. Names are `<plugin>:<server>`.
 */
function discoverPluginServers(project: string, home: string, sources: DiscoveryResult["sources"]): ServerConfig[] {
  const installedPath = join(home, ".claude", "plugins", "installed_plugins.json");
  if (!existsSync(installedPath)) return [];
  const installed = readJson(installedPath, sources)?.plugins;
  if (!installed || typeof installed !== "object") return [];
  const enabled = enabledPlugins(project, home, sources);
  const out: ServerConfig[] = [];

  for (const [key, entries] of Object.entries(installed as Record<string, any[]>)) {
    if (enabled[key] === false || !Array.isArray(entries)) continue;
    const pluginName = key.split("@")[0];
    for (const e of entries) {
      if (typeof e?.installPath !== "string") continue;
      if (e.scope && e.scope !== "user" && e.projectPath && resolve(e.projectPath) !== project) continue;
      const root = e.installPath as string;
      const blocks: { block: unknown; source: string }[] = [];

      const mcpPath = join(root, ".mcp.json");
      if (existsSync(mcpPath)) blocks.push({ block: readJson(mcpPath, sources)?.mcpServers, source: mcpPath });

      const manifestPath = join(root, ".claude-plugin", "plugin.json");
      const field = existsSync(manifestPath) ? readJson(manifestPath, sources)?.mcpServers : undefined;
      for (const f of Array.isArray(field) ? field : [field]) {
        if (typeof f === "string") {
          const p = resolve(root, f.replaceAll("${CLAUDE_PLUGIN_ROOT}", root));
          // Never follow a manifest path outside the plugin directory.
          if (p.startsWith(resolve(root)) && p !== mcpPath && existsSync(p)) {
            const data = readJson(p, sources);
            blocks.push({ block: data?.mcpServers ?? data, source: p });
          }
        } else if (f && typeof f === "object") {
          blocks.push({ block: f, source: manifestPath });
        }
      }

      for (const { block, source } of blocks) {
        for (const s of toServers(block, "plugin", source)) {
          out.push(substitutePluginRoot({ ...s, name: `${pluginName}:${s.name}` }, root));
        }
      }
    }
  }
  return out;
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
