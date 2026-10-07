import { discoverContext, type ContextDiscovery, type ContextFile } from "./context-files.js";
import { analyzeContext } from "./rules/context-rules.js";
import type { Finding } from "./types.js";

export interface ContextAudit extends ContextDiscovery {
  findings: Finding[];
}

/** Static scan of skills, commands, subagents, rules, CLAUDE.md, plugin hooks and bundled scripts. Read-only. */
export function auditContext(projectDir: string, opts: { projectOnly?: boolean; home?: string } = {}): ContextAudit {
  const discovered = discoverContext(projectDir, opts);
  return { ...discovered, findings: analyzeContext(discovered.files) };
}

const KIND_LABEL: Record<ContextFile["kind"], string> = {
  "claude-md": "CLAUDE.md file(s)",
  skill: "skill file(s)",
  command: "command(s)",
  agent: "subagent(s)",
  rule: "rule file(s)",
  hooks: "plugin hook config(s)",
  script: "bundled script(s)",
};

/** One line per kind and one per origin, for the report header. */
export function contextSummary(a: ContextAudit): string[] {
  const count = <K extends string>(keys: K[]) => keys.reduce<Record<string, number>>((m, k) => ((m[k] = (m[k] ?? 0) + 1), m), {});
  const kinds = count(a.files.map((f) => f.kind));
  const origins = count(a.files.map((f) => (f.origin.startsWith("plugin:") ? "plugins" : f.origin)));
  const pluginNames = new Set(a.files.filter((f) => f.origin.startsWith("plugin:")).map((f) => f.origin.slice(7)));
  return [
    `Scanned **${a.files.length}** file(s): ${Object.entries(kinds).map(([k, n]) => `${n} ${KIND_LABEL[k as ContextFile["kind"]]}`).join(", ") || "none"}.`,
    `Sources: ${Object.entries(origins).map(([k, n]) => `${k} (${n})`).join(", ") || "none"}${pluginNames.size ? `; ${pluginNames.size} plugin(s)` : ""}.`,
    a.skipped.length ? `**Skipped:**\n${a.skipped.slice(0, 10).map((s) => `- ${s}`).join("\n")}${a.skipped.length > 10 ? `\n- … and ${a.skipped.length - 10} more` : ""}` : "",
  ];
}
