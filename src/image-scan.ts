// Known-vulnerability scan of container images used by MCP servers (OWASP MCP04), delegated to Trivy
// or Grype when one is installed. Nothing is installed by this module. Scanning may pull the image
// and the scanner's vulnerability database, so it only runs when the user opts in.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dockerImageOf } from "./rules/config-rules.js";
import { excerpt } from "./sanitize.js";
import type { Finding, ServerConfig, Severity } from "./types.js";

export type Runner = (cmd: string, args: string[], timeoutMs: number) => Promise<{ stdout: string }>;

const defaultRunner: Runner = (cmd, args, timeoutMs) => promisify(execFile)(cmd, args, { timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024 });

export type Scanner = "trivy" | "grype";

export async function detectScanner(run: Runner = defaultRunner): Promise<Scanner | undefined> {
  for (const s of ["trivy", "grype"] as const) {
    try {
      await run(s, ["--version"], 10_000);
      return s;
    } catch {
      // Not installed.
    }
  }
  return undefined;
}

type Counts = Record<"critical" | "high" | "medium" | "low", number>;

function countTrivy(json: any): Counts {
  const c: Counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of json?.Results ?? []) for (const v of r?.Vulnerabilities ?? []) {
    const s = String(v?.Severity ?? "").toLowerCase();
    if (s in c) c[s as keyof Counts]++;
  }
  return c;
}

function countGrype(json: any): Counts {
  const c: Counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const m of json?.matches ?? []) {
    const s = String(m?.vulnerability?.severity ?? "").toLowerCase();
    if (s in c) c[s as keyof Counts]++;
  }
  return c;
}

export async function scanImages(servers: ServerConfig[], run: Runner = defaultRunner): Promise<{ findings: Finding[]; scanned: string[]; scanner?: Scanner; notes: string[] }> {
  const targets = servers.map((s) => ({ s, image: dockerImageOf(s) })).filter((x): x is { s: ServerConfig; image: string } => !!x.image);
  if (!targets.length) return { findings: [], scanned: [], notes: [] };
  const scanner = await detectScanner(run);
  if (!scanner) return { findings: [], scanned: [], notes: [`${targets.length} server(s) run in containers, but neither Trivy nor Grype is installed, so their images were not checked for known vulnerabilities.`] };

  const findings: Finding[] = [];
  const scanned: string[] = [];
  const notes: string[] = [];
  for (const image of [...new Set(targets.map((t) => t.image))]) {
    try {
      const args = scanner === "trivy" ? ["image", "--quiet", "--format", "json", "--scanners", "vuln", image] : [image, "-o", "json", "-q"];
      const { stdout } = await run(scanner, args, 10 * 60_000);
      const counts = scanner === "trivy" ? countTrivy(JSON.parse(stdout)) : countGrype(JSON.parse(stdout));
      scanned.push(image);
      const severity: Severity | undefined = counts.critical ? "high" : counts.high ? "medium" : counts.medium || counts.low ? "low" : undefined;
      if (!severity) continue;
      for (const { s } of targets.filter((t) => t.image === image)) {
        findings.push({
          severity,
          rule: "supply-chain/image-vulnerabilities",
          title: `Image "${excerpt(image, 80)}" has known vulnerabilities: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`,
          location: `server "${s.name}" (${s.scope}) › image`,
          remediation: `Update to a patched image tag or digest, then re-pin. Details: ${scanner} image ${image}`,
          file: s.source,
          server: s.name,
        });
      }
    } catch (e) {
      notes.push(`${scanner} could not scan ${excerpt(image, 80)}: ${excerpt(e instanceof Error ? e.message : String(e), 120)}`);
    }
  }
  return { findings, scanned, scanner, notes };
}
