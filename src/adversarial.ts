// Active testing of an MCP server the user owns (OWASP MCP05). Unlike every other check, this *calls*
// tools: each string parameter receives command-injection payloads that would create an empty canary
// file, and path parameters receive traversal payloads. Destructive tools are skipped by default.
import { randomBytes } from "node:crypto";
import { existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyTool } from "./capabilities.js";
import { listAllTools, withClient } from "./client.js";
import { excerpt } from "./sanitize.js";
import type { Finding, ServerConfig, ToolDefinition } from "./types.js";

export interface AdversarialOptions {
  /** Directory the server can write to, as seen by the server. Defaults to the OS temp directory. */
  canaryDir?: string;
  /** Same directory as seen by this process (differs when the server runs in a container with a mount). */
  hostCanaryDir?: string;
  includeDestructive?: boolean;
  maxCalls?: number;
  callTimeoutMs?: number;
}

export interface AdversarialResult {
  findings: Finding[];
  calls: number;
  testedTools: string[];
  skippedTools: { tool: string; reason: string }[];
}

interface Schema {
  type?: string | string[];
  properties?: Record<string, Schema>;
  required?: string[];
  enum?: unknown[];
  default?: unknown;
}

const PATH_PARAM = /(^|_)(path|file|filename|filepath|dir|directory|folder|src|source|dest|destination)$/i;
/** /etc/passwd on Unix, win.ini on Windows: either proves the read escaped the intended directory. */
const LEAK_RE = /root:[x*]?:0:0:|\[fonts\]|for 16-bit app support/i;

// POSIX shells and cmd.exe: `& echo x > file` works in both.
const commandPayloads = (canary: string) => [`; touch ${canary}`, `$(touch ${canary})`, `\`touch ${canary}\``, `| touch ${canary}`, `&& touch ${canary}`, `\ntouch ${canary}\n`, `& echo x > ${canary}`];
const PATH_PAYLOADS = [
  "../../../../../../../../../../etc/passwd",
  "/etc/passwd",
  "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
  "..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
  "C:\\Windows\\win.ini",
];

function typeOf(s: Schema | undefined): string {
  const t = s?.type;
  return Array.isArray(t) ? (t.find((x) => x !== "null") ?? "string") : (t ?? "string");
}

/** Minimal valid value for a parameter that is not under test. */
function filler(s: Schema | undefined): unknown {
  if (s?.default !== undefined) return s.default;
  if (s?.enum?.length) return s.enum[0];
  switch (typeOf(s)) {
    case "number":
    case "integer":
      return 1;
    case "boolean":
      return false;
    case "array":
      return [];
    case "object":
      return {};
    default:
      return "test";
  }
}

function baseArgs(schema: Schema): Record<string, unknown> {
  return Object.fromEntries(Object.entries(schema.properties ?? {}).map(([k, v]) => [k, filler(v)]));
}

function responseText(r: unknown): string {
  const content = (r as { content?: { type: string; text?: string }[] })?.content ?? [];
  return content.map((c) => c.text ?? "").join("\n");
}

/** Path as the *server* sees it: a container on a Windows host still wants forward slashes. */
function serverPath(dir: string, name: string): string {
  return `${dir}${dir.includes("\\") && !dir.includes("/") ? "\\" : "/"}${name}`;
}

export async function adversarialTest(s: ServerConfig, opts: AdversarialOptions = {}): Promise<AdversarialResult> {
  const canaryDir = (opts.canaryDir ?? tmpdir()).replace(/[\\/]$/, "");
  const hostDir = (opts.hostCanaryDir ?? canaryDir).replace(/[\\/]$/, "");
  const maxCalls = opts.maxCalls ?? 300;
  const callTimeout = opts.callTimeoutMs ?? 5_000;
  const runId = randomBytes(4).toString("hex");
  const findings: Finding[] = [];
  const skippedTools: AdversarialResult["skippedTools"] = [];
  const testedTools: string[] = [];
  /** canary file name → what produced it */
  const planted = new Map<string, { tool: string; param: string; payload: string }>();
  let calls = 0;

  await withClient(s, 10 * 60_000, async (client) => {
    const tools: ToolDefinition[] = await listAllTools(client);
    for (const tool of tools) {
      if (!opts.includeDestructive && classifyTool(tool).includes("destructive")) {
        skippedTools.push({ tool: tool.name, reason: "destructive (use --include-destructive in a disposable environment)" });
        continue;
      }
      const schema = (tool.inputSchema ?? {}) as Schema;
      const stringParams = Object.entries(schema.properties ?? {}).filter(([, v]) => typeOf(v) === "string" && !v.enum);
      if (!stringParams.length) {
        skippedTools.push({ tool: tool.name, reason: "no free-text string parameters" });
        continue;
      }
      testedTools.push(tool.name);
      const call = async (args: Record<string, unknown>) => {
        if (calls >= maxCalls) return undefined;
        calls++;
        try {
          return await client.callTool({ name: tool.name, arguments: args }, undefined, { timeout: callTimeout });
        } catch {
          return undefined; // Rejected input is the desired outcome.
        }
      };

      for (const [param] of stringParams) {
        for (const payload of commandPayloads("CANARY")) {
          const name = `mcpsec-${runId}-${planted.size}`;
          planted.set(name, { tool: tool.name, param, payload });
          await call({ ...baseArgs(schema), [param]: `test${payload.replace("CANARY", serverPath(canaryDir, name))}` });
        }
        if (PATH_PARAM.test(param)) {
          for (const payload of PATH_PAYLOADS) {
            const r = await call({ ...baseArgs(schema), [param]: payload });
            if (LEAK_RE.test(responseText(r))) {
              findings.push({ severity: "high", rule: "adversarial/path-traversal", title: `Tool "${excerpt(tool.name, 50)}" returned a system file outside its directory for parameter "${excerpt(param, 40)}"`, location: `server "${s.name}" › tool "${excerpt(tool.name, 50)}" › ${excerpt(param, 40)}`, evidence: excerpt(payload, 80), remediation: "Resolve the path, then reject anything outside the allowed root (compare realpath prefixes). Never pass user paths straight to the file system.", file: s.source, server: s.name });
              break;
            }
          }
        }
      }
    }
  });

  // Give fire-and-forget subprocesses a moment to run before checking for canaries.
  await new Promise((r) => setTimeout(r, 300));
  const hit = new Set<string>();
  for (const [name, origin] of planted) {
    const path = join(hostDir, name);
    if (!existsSync(path)) continue;
    rmSync(path, { force: true });
    const key = `${origin.tool}|${origin.param}`;
    if (hit.has(key)) continue;
    hit.add(key);
    findings.push({ severity: "critical", rule: "adversarial/command-injection", title: `Command injection in tool "${excerpt(origin.tool, 50)}", parameter "${excerpt(origin.param, 40)}"`, location: `server "${s.name}" › tool "${excerpt(origin.tool, 50)}" › ${excerpt(origin.param, 40)}`, evidence: excerpt(origin.payload.replace("CANARY", "<canary>"), 80), remediation: "The parameter reaches a shell. Use execFile/spawn with an argument array (no shell), and validate the value against an allow-list.", file: s.source, server: s.name });
  }
  return { findings, calls, testedTools, skippedTools };
}
