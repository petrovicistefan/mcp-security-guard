import { fetchTools } from "./client.js";
import { discoverServers } from "./config.js";
import { computeDrift, hasDrift, hashConfig, loadPins, pinKey } from "./pins.js";
import { analyzeTools } from "./rules/tool-rules.js";
import { excerpt } from "./sanitize.js";

export type CheckMode = "off" | "config" | "full";

export interface SessionCheckResult {
  /** One line per affected server, already sanitised. Empty when everything matches the pins. */
  problems: string[];
  checked: number;
}

/**
 * Re-verifies only servers the user has pinned (pinning is the consent to launch them).
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
          const tools = await fetchTools(s, timeoutMs);
          const d = computeDrift(pin.tools, tools);
          if (hasDrift(d)) {
            const parts = [d.changed.length && `${d.changed.length} tool(s) changed`, d.added.length && `${d.added.length} added`, d.removed.length && `${d.removed.length} removed`].filter(Boolean);
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
  return { problems: results.filter((r): r is string => !!r), checked: pinned.length };
}
