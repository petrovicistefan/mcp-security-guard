import { existsSync, readFileSync, readdirSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join, resolve } from "node:path";
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

/** JSON with comments and trailing commas (VS Code settings), string-aware so "http://x" survives. */
export function stripJsonComments(text: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === "\\") out += text[++i] ?? "";
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
    } else {
      out += c;
    }
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function readJson(path: string, sources: DiscoveryResult["sources"], jsonc = false): any | undefined {
  if (!existsSync(path)) {
    sources.push({ path, status: "missing" });
    return undefined;
  }
  try {
    const raw = readFileSync(path, "utf8");
    const data = JSON.parse(jsonc ? stripJsonComments(raw) : raw);
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
    // Cursor uses `transport`, Windsurf `serverUrl`.
    type: typeof raw?.type === "string" ? raw.type : typeof raw?.transport === "string" ? raw.transport : undefined,
    command: typeof raw?.command === "string" ? raw.command : undefined,
    args: Array.isArray(raw?.args) ? raw.args.map(String) : undefined,
    env: raw?.env && typeof raw.env === "object" ? stringRecord(raw.env) : undefined,
    url: typeof raw?.url === "string" ? raw.url : typeof raw?.serverUrl === "string" ? raw.serverUrl : undefined,
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
    servers.push(...discoverClaudeAiConnectors(claudeJson, claudeJsonPath));
  }

  const projectMcpPath = join(project, ".mcp.json");
  servers.push(...toServers(readJson(projectMcpPath, sources)?.mcpServers, "project", projectMcpPath));

  servers.push(...discoverPluginServers(project, home, sources));

  servers.push(...discoverOtherClients(project, home, sources));

  const desktopPath = claudeDesktopConfigPath(home);
  servers.push(...toServers(readJson(desktopPath, sources)?.mcpServers, "claude-desktop", desktopPath));

  return { servers, sources };
}

function appDataDir(home: string): string {
  return platform() === "darwin" ? join(home, "Library", "Application Support") : platform() === "win32" ? (process.env.APPDATA ?? join(home, "AppData", "Roaming")) : join(home, ".config");
}

function managedMcpPath(): string {
  return platform() === "darwin"
    ? "/Library/Application Support/ClaudeCode/managed-mcp.json"
    : platform() === "win32"
      ? join(process.env.ProgramData ?? "C:\\ProgramData", "ClaudeCode", "managed-mcp.json")
      : "/etc/claude-code/managed-mcp.json";
}

/**
 * MCP servers of other clients on this machine (Cursor, VS Code, Windsurf), Claude Desktop extensions
 * and the organisation-managed Claude Code file. They do not all reach Claude, but they are part of the
 * machine's MCP exposure and a common place for shadow servers.
 */
function discoverOtherClients(project: string, home: string, sources: DiscoveryResult["sources"]): ServerConfig[] {
  const out: ServerConfig[] = [];
  const add = (path: string, scope: ConfigScope, key: "mcpServers" | "servers", jsonc = false) => {
    if (!existsSync(path)) return;
    const data = readJson(path, sources, jsonc);
    out.push(...toServers(key === "servers" ? (data?.servers ?? data?.mcp?.servers) : data?.mcpServers, scope, path));
  };
  add(managedMcpPath(), "managed", "mcpServers");
  add(join(home, ".cursor", "mcp.json"), "cursor", "mcpServers");
  add(join(project, ".cursor", "mcp.json"), "cursor", "mcpServers");
  add(join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf", "mcpServers");
  add(join(project, ".vscode", "mcp.json"), "vscode", "servers", true);
  add(join(appDataDir(home), "Code", "User", "mcp.json"), "vscode", "servers", true);
  const vsSettings = join(appDataDir(home), "Code", "User", "settings.json");
  if (existsSync(vsSettings)) {
    // Only read the `mcp` key of the (large) settings file; ignore the file when it has none.
    try {
      const mcp = JSON.parse(stripJsonComments(readFileSync(vsSettings, "utf8")))?.mcp;
      if (mcp?.servers) {
        sources.push({ path: vsSettings, status: "ok" });
        out.push(...toServers(mcp.servers, "vscode", vsSettings));
      }
    } catch {
      sources.push({ path: vsSettings, status: "unreadable" });
    }
  }

  // Claude Desktop extensions (.mcpb / DXT): <extensions dir>/<id>/manifest.json with server.mcp_config.
  const extDir = join(dirname(claudeDesktopConfigPath(home)), "Claude Extensions");
  for (const id of listDirs(extDir)) {
    const manifestPath = join(extDir, id, "manifest.json");
    if (!existsSync(manifestPath)) continue;
    const m = readJson(manifestPath, sources);
    const cfg = m?.server?.mcp_config;
    if (!cfg) continue;
    const root = join(extDir, id);
    const sub = (v: unknown) => String(v).replaceAll("${__dirname}", root);
    out.push({
      name: typeof m.name === "string" ? m.name : id,
      scope: "claude-desktop-extension",
      source: manifestPath,
      command: cfg.command ? sub(cfg.command) : undefined,
      args: Array.isArray(cfg.args) ? cfg.args.map(sub) : undefined,
      env: cfg.env && typeof cfg.env === "object" ? Object.fromEntries(Object.entries(cfg.env).map(([k, v]) => [k, sub(v)])) : undefined,
    });
  }
  return out;
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
/** MCP servers declared by one plugin directory: its `.mcp.json` and the `mcpServers` field of plugin.json (inline or path). */
function pluginDirServers(root: string, pluginName: string, sources: DiscoveryResult["sources"]): ServerConfig[] {
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
  return blocks.flatMap(({ block, source }) => toServers(block, "plugin", source).map((sv) => substitutePluginRoot({ ...sv, name: `${pluginName}:${sv.name}` }, root)));
}

/**
 * MCP servers shipped inside plugins: installed ones (installed_plugins.json, honouring enabledPlugins
 * and project-scoped installs) and plugins synced from the claude.ai account
 * (~/.claude/plugins/synced/<account>/<plugin>/). Names are `<plugin>:<server>`.
 */
function discoverPluginServers(project: string, home: string, sources: DiscoveryResult["sources"]): ServerConfig[] {
  const enabled = enabledPlugins(project, home, sources);
  const out: ServerConfig[] = [];

  const installedPath = join(home, ".claude", "plugins", "installed_plugins.json");
  const installed = existsSync(installedPath) ? readJson(installedPath, sources)?.plugins : undefined;
  if (installed && typeof installed === "object") {
    for (const [key, entries] of Object.entries(installed as Record<string, any[]>)) {
      if (enabled[key] === false || !Array.isArray(entries)) continue;
      const pluginName = key.split("@")[0];
      for (const e of entries) {
        if (typeof e?.installPath !== "string") continue;
        if (e.scope && e.scope !== "user" && e.projectPath && resolve(e.projectPath) !== project) continue;
        out.push(...pluginDirServers(e.installPath, pluginName, sources));
      }
    }
  }

  const syncedRoot = join(home, ".claude", "plugins", "synced");
  for (const bucket of listDirs(syncedRoot)) {
    for (const dir of listDirs(join(syncedRoot, bucket))) {
      const root = join(syncedRoot, bucket, dir);
      const manifest = join(root, ".claude-plugin", "plugin.json");
      if (!existsSync(manifest)) continue;
      const name = readJson(manifest, sources)?.name;
      const pluginName = typeof name === "string" && name ? name : dir;
      if (enabled[`${pluginName}@synced`] === false) continue;
      for (const sv of pluginDirServers(root, pluginName, sources)) {
        if (!out.some((o) => o.name === sv.name)) out.push(sv);
      }
    }
  }
  return out;
}

function listDirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && !d.name.startsWith("."))
      .map((d) => d.name)
      .sort();
  } catch {
    return [];
  }
}

/**
 * Connectors added in the claude.ai account (Claude Docs, Canva…). Their configuration lives in the
 * account, so only the names Claude Code has recorded locally are known.
 */
function discoverClaudeAiConnectors(claudeJson: any, source: string): ServerConfig[] {
  const names = Array.isArray(claudeJson?.claudeAiMcpEverConnected) ? claudeJson.claudeAiMcpEverConnected : [];
  return [...new Set<string>(names.filter((n: unknown): n is string => typeof n === "string"))].map((n) => ({ name: n.replace(/^claude\.ai\s+/, ""), scope: "claude-ai" as const, source }));
}

export function describeServer(s: ServerConfig): string {
  return `server "${s.name}" (${s.scope})`;
}

export function transportOf(s: ServerConfig): "stdio" | "http" | "sse" | "claude-ai" | "unknown" {
  if (s.scope === "claude-ai") return "claude-ai";
  if (s.type === "sse") return "sse";
  if (s.url) return "http";
  if (s.command) return "stdio";
  return "unknown";
}
