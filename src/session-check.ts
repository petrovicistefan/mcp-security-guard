import { fetchSurface, surfaceDefinitions } from "./client.js";
import { discoverServers, pluginRoots } from "./config.js";
import { discoverContext } from "./context-files.js";
import { contextDrift, loadContextPins } from "./context-pins.js";
import { computeDrift, hasDrift, hashConfig, loadPins, pinKey } from "./pins.js";
import { auditPluginPolicy, auditPolicy, loadPolicy } from "./policy.js";
import { resolve } from "node:path";
import { homedir } from "node:os";
import { analyzeTools } from "./rules/tool-rules.js";
import { excerpt } from "./sanitize.js";

export type CheckMode = "off" | "config" | "full";

export interface SessionCheckResult {
  /** One line per affected server, already sanitised. Empty when everything matches the pins. */
  problems: string[];
  checked: number;
}

/**
 * Checks the approved-server policy, and re-verifies servers the user has pinned (pinning is the consent to launch them).
 * "config" mode compares launch configs without starting anything; "full" also re-lists tools.
 */
export async function sessionCheck(projectDir: string, mode: CheckMode, timeoutMs = 10_000): Promise<SessionCheckResult> {
  if (mode === "off") return { problems: [], checked: 0 };
  const pins = loadPins();
  const { servers } = discoverServers(projectDir);
  const pinned = servers.map((s) => ({ s, pin: pins.servers[pinKey(s.scope, s.name)] })).filter((x) => x.pin);

  const results = await Promise.all(
    pinned.map(async ({ s, pin }) => {
      const label = `"${excerpt(s.name, 50)}" (${s.scope})`;
      const issues: string[] = [];
      if (pin.config && pin.config !== hashConfig(s)) issues.push("launch command or version changed");
      if (mode === "full") {
        try {
          const surface = await fetchSurface(s, timeoutMs);
          const tools = [...surface.tools, ...surfaceDefinitions(surface).map((x) => x.def)];
          const d = computeDrift(pin, tools);
          if (hasDrift(d)) {
            const parts = [d.changed.length && `${d.changed.length} definition(s) changed`, d.added.length && `${d.added.length} added`, d.removed.length && `${d.removed.length} removed`].filter(Boolean);
            const severe = analyzeTools(s.name, tools.filter((t) => d.changed.includes(t.name) || d.added.includes(t.name))).filter((f) => f.severity === "critical" || f.severity === "high");
            issues.push(parts.join(", ") + (severe.length ? `, ${severe.length} critical/high poisoning finding(s) in them` : ""));
          }
        } catch (e) {
          issues.push(`could not verify (${excerpt(e instanceof Error ? e.message : String(e), 80)})`);
        }
      }
      return issues.length ? `${label}: ${issues.join("; ")}` : undefined;
    }),
  );
  // Policy violations need no launch, so they are reported for every configured server.
  const loadedPolicy = loadPolicy(projectDir);
  const plugins = pluginRoots(resolve(projectDir), homedir(), []).map((p) => ({ name: p.name, ...(p.version ? { version: p.version } : {}) }));
  const policyProblems = [...auditPolicy(servers, loadedPolicy), ...auditPluginPolicy(plugins, loadedPolicy)]
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .map((f) => `${f.server ? `"${excerpt(f.server, 50)}"` : f.location.startsWith("plugin ") ? excerpt(f.location, 80) : "policy"}: ${f.title}`);

  // Pinned skills, commands, agents and CLAUDE.md: local files only, nothing is launched.
  const contextPins = loadContextPins();
  const contextProblems = Object.keys(contextPins.origins).length
    ? contextDrift(discoverContext(projectDir), projectDir, contextPins).findings.filter((f) => f.severity === "high" || f.severity === "critical").map((f) => `${f.title} (${f.location})`)
    : [];
  return { problems: [...results.filter((r): r is string => !!r), ...policyProblems, ...contextProblems.map((p) => excerpt(p, 240))], checked: pinned.length };
}
