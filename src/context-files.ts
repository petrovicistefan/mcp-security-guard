// Discovery of the text files that end up in Claude's context besides MCP tool definitions: CLAUDE.md,
// skills, slash commands, subagents, rules, plugin hook configs and the scripts bundled with skills.
// Read-only; never follows symlinks, so a link cannot make the scan read files outside the folders below.
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { basename, extname, join, relative, resolve, sep } from "node:path";
import { pluginRoots, type DiscoveryResult } from "./config.js";

export type ContextKind = "claude-md" | "skill" | "command" | "agent" | "rule" | "hooks" | "script";

export interface ContextFile {
  path: string;
  kind: ContextKind;
  /** `user`, `project` or `plugin:<name>`. */
  origin: string;
  /** Skill, command or agent name (the folder or file name), for reports. */
  name: string;
  text: string;
}

export interface ContextDiscovery {
  files: ContextFile[];
  /** Files skipped because they were too large, unreadable or past the limit. */
  skipped: string[];
}

const MAX_FILE_BYTES = 256 * 1024;
const MAX_FILES = 2000;
const MAX_DEPTH = 4;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv"]);
const SCRIPT_EXT = new Set([".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb", ".pl"]);

function walk(dir: string, depth = 0): string[] {
  if (depth > MAX_DEPTH) return [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (e.isSymbolicLink()) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith(".")) out.push(...walk(p, depth + 1));
    } else if (e.isFile()) out.push(p);
  }
  return out;
}

function isRegularFile(path: string): boolean {
  try {
    return lstatSync(path).isFile();
  } catch {
    return false;
  }
}

/** Skills, commands, agents, rules, hooks and CLAUDE.md under one `.claude`-style root (a user's ~/.claude, a project's .claude, or a plugin directory). */
function collectRoot(root: string, origin: string, add: (path: string, kind: ContextKind, name: string) => void, opts: { pluginLayout: boolean }): void {
  const skills = join(root, "skills");
  for (const f of walk(skills)) {
    const rel = relative(skills, f).split(sep);
    const skillName = rel[0];
    const ext = extname(f).toLowerCase();
    if (basename(f).toLowerCase() === "skill.md") add(f, "skill", skillName);
    else if (ext === ".md" || ext === ".mdx" || ext === ".txt") add(f, "skill", skillName);
    else if (SCRIPT_EXT.has(ext)) add(f, "script", skillName);
  }
  for (const [dir, kind] of [["commands", "command"], ["agents", "agent"], ["rules", "rule"]] as const) {
    const base = join(root, dir);
    for (const f of walk(base)) if ([".md", ".mdx"].includes(extname(f).toLowerCase())) add(f, kind, relative(base, f).replace(/\.mdx?$/i, "").split(sep).join("/"));
  }
  if (opts.pluginLayout) {
    for (const f of [join(root, "hooks", "hooks.json"), join(root, "hooks.json")]) add(f, "hooks", "hooks");
    for (const f of walk(join(root, "hooks"))) if (SCRIPT_EXT.has(extname(f).toLowerCase())) add(f, "script", "hooks");
  }
}

/**
 * Everything the agent reads that is not an MCP tool: user (~/.claude), project, and every enabled plugin.
 * Pass `projectOnly` for CI, where only the repository's own files count.
 */
export function discoverContext(projectDir: string, opts: { home?: string; projectOnly?: boolean } = {}): ContextDiscovery {
  const home = opts.home ?? homedir();
  const project = resolve(projectDir);
  const files: ContextFile[] = [];
  const skipped: string[] = [];
  const seen = new Set<string>();

  const add = (origin: string) => (file: string, kind: ContextKind, name: string) => {
    const p = resolve(file);
    if (seen.has(p) || !isRegularFile(p)) return;
    seen.add(p);
    if (files.length >= MAX_FILES) {
      skipped.push(`${p} (limit of ${MAX_FILES} files reached)`);
      return;
    }
    try {
      const buf = readFileSync(p);
      if (buf.length > MAX_FILE_BYTES) {
        skipped.push(`${p} (larger than ${MAX_FILE_BYTES / 1024} KB)`);
        return;
      }
      files.push({ path: p, kind, origin, name, text: buf.toString("utf8") });
    } catch {
      skipped.push(`${p} (unreadable)`);
    }
  };

  // Project: CLAUDE.md in the project root, in .claude/, and the local (uncommitted) variant.
  const addProject = add("project");
  for (const f of [join(project, "CLAUDE.md"), join(project, "CLAUDE.local.md"), join(project, ".claude", "CLAUDE.md")]) addProject(f, "claude-md", basename(f));
  collectRoot(join(project, ".claude"), "project", addProject, { pluginLayout: false });

  if (!opts.projectOnly) {
    const addUser = add("user");
    addUser(join(home, ".claude", "CLAUDE.md"), "claude-md", "CLAUDE.md");
    collectRoot(join(home, ".claude"), "user", addUser, { pluginLayout: false });

    const sources: DiscoveryResult["sources"] = [];
    for (const { name, root } of pluginRoots(project, home, sources)) {
      collectRoot(root, `plugin:${name}`, add(`plugin:${name}`), { pluginLayout: true });
    }
  }
  return { files, skipped };
}
