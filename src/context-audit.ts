import { discoverContext, type ContextDiscovery, type ContextFile } from "./context-files.js";
import { cloudCheck, cloudOptionsFromEnv, type CloudOptions } from "./cloud.js";
import { contextDrift, contextPinsPath, loadContextPins } from "./context-pins.js";
import { auditPluginPolicy, loadPolicy } from "./policy.js";
import { analyzeContext } from "./rules/context-rules.js";
import type { Finding } from "./types.js";

export interface ContextAudit extends ContextDiscovery {
  findings: Finding[];
  /** Pin status per origin; empty when nothing was ever pinned. */
  driftLines: string[];
}

/** Static scan of skills, commands, subagents, rules, CLAUDE.md, plugin hooks and bundled scripts. Read-only. */
export function auditContext(projectDir: string, opts: { projectOnly?: boolean; home?: string } = {}): ContextAudit {
  const discovered = discoverContext(projectDir, opts);
  const pins = loadContextPins();
  // Pin status is only reported once something was pinned, so a first scan is not buried in "not pinned" lines.
  const drift = Object.keys(pins.origins).length ? contextDrift(discovered, projectDir, pins) : { lines: [], findings: [] };
  // Plugins the policy (yours, the project's or the team's) blocks or does not list. A repository's policy file applies in CI too.
  const policyFindings = auditPluginPolicy(discovered.plugins, loadPolicy(projectDir));
  return { ...discovered, findings: [...analyzeContext(discovered.files), ...drift.findings, ...policyFindings], driftLines: drift.lines };
}

/**
 * Opt-in threat feed check of the scanned files and plugins (needs an API key; a no-op without one).
 * Sends SHA-256 hashes of the files and plugin names and versions, nothing else; fails open.
 */
export async function feedCheckContext(a: ContextAudit, opts: CloudOptions = cloudOptionsFromEnv()): Promise<{ findings: Finding[]; note?: string }> {
  if (!a.files.length) return { findings: [] };
  const r = await cloudCheck([], [], opts, { files: a.files, versions: a.versions, plugins: a.plugins });
  return { findings: r.findings, note: r.note };
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
    a.driftLines.length ? `**Pinning status** (${contextPinsPath()}):\n${a.driftLines.join("\n")}` : "",
    a.skipped.length ? `**Skipped:**\n${a.skipped.slice(0, 10).map((s) => `- ${s}`).join("\n")}${a.skipped.length > 10 ? `\n- … and ${a.skipped.length - 10} more` : ""}` : "",
  ];
}
