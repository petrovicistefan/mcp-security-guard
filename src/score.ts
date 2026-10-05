import { excerpt } from "./sanitize.js";
import type { Finding, ServerConfig, Severity } from "./types.js";

/** Points deducted per finding, capped per rule so one noisy rule cannot zero a server alone. */
const PENALTY: Record<Severity, number> = { critical: 45, high: 25, medium: 10, low: 3, info: 0 };
const RULE_CAP = 50;

export interface ServerScore {
  server: ServerConfig;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  /** Whether tool definitions were part of the assessment, or configuration only. */
  basis: "config" | "config+tools";
}

export function grade(score: number): ServerScore["grade"] {
  return score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
}

/**
 * Deterministic security score, 100 = no findings. Any critical finding caps the grade at F,
 * any high finding at D, so a single poisoned tool is never hidden by an otherwise clean server.
 */
export function scoreServer(server: ServerConfig, findings: Finding[], basis: ServerScore["basis"]): ServerScore {
  const own = findings.filter((f) => f.server === server.name && f.file === server.source);
  const byRule = new Map<string, number>();
  for (const f of own) byRule.set(f.rule, Math.min(RULE_CAP, (byRule.get(f.rule) ?? 0) + PENALTY[f.severity]));
  let score = Math.max(0, 100 - [...byRule.values()].reduce((a, b) => a + b, 0));
  if (own.some((f) => f.severity === "critical")) score = Math.min(score, 39);
  else if (own.some((f) => f.severity === "high")) score = Math.min(score, 59);
  return { server, score, grade: grade(score), basis };
}

export function scoreTable(scores: ServerScore[]): string {
  scores = scores.filter((s) => s.server.scope !== "claude-ai");
  if (!scores.length) return "";
  const rows = [...scores]
    .sort((a, b) => a.score - b.score)
    .map((s) => `| ${excerpt(s.server.name, 50)} | ${s.server.scope} | **${s.score}** | ${s.grade} | ${s.basis === "config" ? "config only" : "config + tools"} |`);
  return ["**Security score per server** (100 = no findings; any critical caps at F, any high at D):", "", "| Server | Scope | Score | Grade | Basis |", "|---|---|---|---|---|", ...rows].join("\n");
}
