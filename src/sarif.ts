import { existsSync, readFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { owaspFor } from "./owasp.js";
import type { Finding, Severity } from "./types.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
/** GitHub code scanning maps this property to its critical/high/medium/low labels. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };

/** Best-effort line of the server's entry (`"name":`) in its config file. */
function lineOf(file: string | undefined, server: string | undefined): number {
  if (!file || !server || !existsSync(file)) return 1;
  const key = server.split(":").pop()!;
  const lines = readFileSync(file, "utf8").split("\n");
  const idx = lines.findIndex((l) => l.includes(`"${key}"`) && /:\s*\{?\s*$/.test(l.split(`"${key}"`)[1] ?? ""));
  return idx >= 0 ? idx + 1 : 1;
}

function artifactUri(file: string | undefined, projectDir: string): string {
  if (!file) return ".mcp.json";
  const rel = relative(resolve(projectDir), file);
  return rel.startsWith("..") ? file : rel.split(sep).join("/");
}

export function toSarif(findings: Finding[], projectDir: string, version: string): object {
  const rules = [...new Map(findings.map((f) => [f.rule, f])).values()].map((f) => ({
    id: f.rule,
    name: f.rule.replace(/[/-](\w)/g, (_, c: string) => c.toUpperCase()),
    shortDescription: { text: f.title },
    help: { text: f.remediation },
    properties: { tags: ["security", "mcp", ...owaspFor(f.rule).map((id) => `OWASP-${id}`)], "security-severity": SECURITY_SEVERITY[f.severity] },
  }));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "mcp-security", version, informationUri: "https://github.com/petrovicistefan/mcp-security", rules } },
        results: findings.map((f) => ({
          ruleId: f.rule,
          level: LEVEL[f.severity],
          message: { text: `${f.title}${f.evidence ? ` (${f.evidence})` : ""}. ${f.remediation}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: artifactUri(f.file, projectDir) }, region: { startLine: lineOf(f.file, f.server) } } }],
          properties: { severity: f.severity, "security-severity": SECURITY_SEVERITY[f.severity], where: f.location, owasp: owaspFor(f.rule) },
        })),
      },
    ],
  };
}
