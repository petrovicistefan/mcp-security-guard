import { describeServer } from "../config.js";
import { excerpt } from "../sanitize.js";
import { findKnownSecret, isEnvReference, looksLikeSecretValue } from "../secrets.js";
import type { Finding, ServerConfig } from "../types.js";

const NODE_RUNNERS = new Set(["npx", "bunx", "pnpx"]);
const PY_RUNNERS = new Set(["uvx", "pipx"]);
const SHELLS = new Set(["sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"]);
const EXACT_NPM_VERSION = /@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

function baseCommand(cmd: string): string {
  return cmd.split(/[\\/]/).pop()!.toLowerCase();
}

/** First positional arg after the runner, skipping flags and `dlx`/`exec`/`run` subcommands. */
function packageSpec(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") continue;
    if (a === "--from" || a === "-p" || a === "--package") return args[i + 1];
    if (a.startsWith("-")) continue;
    if (["dlx", "exec", "run"].includes(a)) continue;
    return a;
  }
  return undefined;
}

function checkUnpinned(s: ServerConfig, loc: string): Finding[] {
  if (!s.command) return [];
  const cmd = baseCommand(s.command);
  const args = s.args ?? [];
  const isNode = NODE_RUNNERS.has(cmd) || ((cmd === "npm" || cmd === "pnpm") && (args[0] === "exec" || args[0] === "dlx"));
  const isPy = PY_RUNNERS.has(cmd);
  if (!isNode && !isPy) return [];

  const spec = packageSpec(args);
  if (!spec || spec.startsWith(".") || spec.startsWith("/")) return [];
  const pinned = isNode ? EXACT_NPM_VERSION.test(spec) : /==\d|@\d/.test(spec);
  if (pinned) return [];
  return [
    {
      severity: "medium",
      rule: "config/unpinned-package",
      title: `Package "${excerpt(spec, 80)}" is not pinned to an exact version`,
      location: `${loc} › args`,
      evidence: excerpt([s.command, ...args].join(" ")),
      remediation: isNode
        ? `Pin an exact version (e.g. "${spec.replace(/@[^@/]*$/, "")}@1.2.3"). Every launch otherwise runs whatever the registry serves today, including a compromised release.`
        : `Pin an exact version (e.g. "${spec.split(/[=@]/)[0]}==1.2.3").`,
    },
  ];
}

function checkDocker(s: ServerConfig, loc: string): Finding[] {
  if (!s.command || !["docker", "podman"].includes(baseCommand(s.command))) return [];
  const args = s.args ?? [];
  const out: Finding[] = [];
  const joined = args.join(" ");
  if (args.includes("--privileged")) {
    out.push({ severity: "high", rule: "config/docker-privileged", title: "Container runs with --privileged", location: loc, evidence: excerpt(joined), remediation: "Remove --privileged; grant only the specific capabilities the server needs." });
  }
  if (/(^|\s)(-v|--volume)[ =]\/:/.test(joined) || /(^|\s)(-v|--volume)[ =](~|\$HOME|\/Users\/[^/:]+|\/home\/[^/:]+):/.test(joined)) {
    out.push({ severity: "high", rule: "config/docker-broad-mount", title: "Container mounts the root or home directory", location: loc, evidence: excerpt(joined), remediation: "Mount only the project directory the server needs, read-only (:ro) when possible." });
  }
  if (/--network[ =]host|--net[ =]host/.test(joined)) {
    out.push({ severity: "medium", rule: "config/docker-host-network", title: "Container uses host networking", location: loc, evidence: excerpt(joined), remediation: "Use the default bridge network unless host networking is required." });
  }
  const runIdx = args.indexOf("run");
  if (runIdx >= 0) {
    // The image is the first positional after `run` whose previous token is not a flag expecting a value.
    for (let i = runIdx + 1; i < args.length; i++) {
      const a = args[i];
      if (a.startsWith("-")) {
        if (!a.includes("=") && /^(-e|--env|-v|--volume|--name|--network|--net|-p|--publish|--mount|-w|--workdir|-u|--user|--entrypoint)$/.test(a)) i++;
        continue;
      }
      if (!a.includes("@sha256:") && (!/:[^/]+$/.test(a) || a.endsWith(":latest"))) {
        out.push({ severity: "medium", rule: "config/docker-unpinned-image", title: `Image "${excerpt(a, 80)}" has no fixed tag or digest`, location: loc, evidence: excerpt(joined), remediation: "Reference the image by digest (image@sha256:…) or at least an immutable version tag." });
      }
      break;
    }
  }
  return out;
}

function checkShell(s: ServerConfig, loc: string): Finding[] {
  if (!s.command) return [];
  const full = [s.command, ...(s.args ?? [])].join(" ");
  const out: Finding[] = [];
  if (/\b(curl|wget|iwr|Invoke-WebRequest)\b[^|]*\|\s*(sh|bash|zsh|python3?|node|iex)\b/i.test(full)) {
    out.push({ severity: "high", rule: "config/pipe-to-shell", title: "Launch command downloads and executes a remote script", location: loc, evidence: excerpt(full), remediation: "Install the server from a pinned package or a reviewed local checkout instead of piping a download into a shell." });
  } else if (SHELLS.has(baseCommand(s.command)) && (s.args ?? []).some((a) => /^(-c|\/c|-Command)$/i.test(a))) {
    out.push({ severity: "medium", rule: "config/shell-wrapper", title: "Server is launched through an inline shell command", location: loc, evidence: excerpt(full), remediation: "Call the server binary directly so the launched command is explicit and auditable." });
  }
  return out;
}

function checkSecrets(s: ServerConfig, loc: string): Finding[] {
  const out: Finding[] = [];
  for (const [k, v] of Object.entries(s.env ?? {})) {
    const hit = looksLikeSecretValue(k, v);
    if (hit) {
      const fix =
        s.scope === "claude-desktop"
          ? `Claude Desktop does not reliably expand variables here, so launch the server through a small wrapper script that reads ${k} from the OS keychain (e.g. \`security find-generic-password\` on macOS) instead of storing it in this file.`
          : `Replace the literal with a reference such as "\${${k}}" and set the variable in your shell or a secret manager.`;
      out.push({ severity: "high", rule: "config/plaintext-secret", title: `${hit.kind} stored in plain text in env.${k}`, location: `${loc} › env.${k}`, evidence: hit.masked, remediation: `${fix} Rotate the key if this file was ever shared, synced or committed.` });
    }
  }
  for (const [k, v] of Object.entries(s.headers ?? {})) {
    if (isEnvReference(v.replace(/^Bearer\s+/i, ""))) continue;
    const hit = looksLikeSecretValue(k, v) ?? (/^authorization$/i.test(k) && v.length > 12 ? { kind: "Authorization header", masked: excerpt(v, 12) + "…" } : undefined);
    if (hit) {
      out.push({ severity: "high", rule: "config/plaintext-secret", title: `${hit.kind} stored in plain text in headers.${k}`, location: `${loc} › headers.${k}`, evidence: hit.masked, remediation: `Use an environment variable reference (e.g. "Bearer \${TOKEN}") or the server's OAuth flow. Rotate the token if it was exposed.` });
    }
  }
  (s.args ?? []).forEach((a, i) => {
    const hit = findKnownSecret(a);
    if (hit) {
      out.push({ severity: "high", rule: "config/secret-in-args", title: `${hit.kind} passed as a command-line argument`, location: `${loc} › args[${i}]`, evidence: hit.masked, remediation: "Pass secrets via env references, not args: args are visible to every local process (ps) and end up in logs." });
    }
  });
  if (s.url) {
    const hit = findKnownSecret(s.url);
    const qs = /[?&](api[_-]?key|token|access_token|key|secret)=([^&]+)/i.exec(s.url);
    if (hit || (qs && !isEnvReference(decodeURIComponent(qs[2])))) {
      out.push({ severity: "high", rule: "config/secret-in-url", title: "Credential embedded in the server URL", location: `${loc} › url`, evidence: hit?.masked ?? `${qs![1]}=****`, remediation: "Move the credential into a header that references an environment variable." });
    }
  }
  return out;
}

function checkRemote(s: ServerConfig, loc: string): Finding[] {
  if (!s.url) return [];
  let u: URL;
  try {
    u = new URL(s.url.replace(/\$\{[^}]+\}/g, "x"));
  } catch {
    return [{ severity: "low", rule: "config/invalid-url", title: "Server URL could not be parsed", location: `${loc} › url`, evidence: excerpt(s.url), remediation: "Fix the URL." }];
  }
  const local = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(u.hostname) || u.hostname.endsWith(".localhost");
  if (u.protocol === "http:" && !local) {
    return [{ severity: "high", rule: "config/insecure-transport", title: "Remote MCP server reached over plain HTTP", location: `${loc} › url`, evidence: `${u.protocol}//${u.host}`, remediation: "Use https://. Over plain HTTP anyone on the network can read your requests and rewrite tool definitions in transit." }];
  }
  return [];
}

export function auditServerConfig(s: ServerConfig): Finding[] {
  const loc = describeServer(s);
  return [...checkSecrets(s, loc), ...checkRemote(s, loc), ...checkShell(s, loc), ...checkUnpinned(s, loc), ...checkDocker(s, loc)];
}

/** The same server name defined in several scopes: the one that wins may not be the one you reviewed. */
export function auditDuplicates(servers: ServerConfig[]): Finding[] {
  const byName = new Map<string, ServerConfig[]>();
  for (const s of servers.filter((s) => s.scope !== "claude-desktop")) byName.set(s.name, [...(byName.get(s.name) ?? []), s]);
  return [...byName.entries()]
    .filter(([, list]) => list.length > 1)
    .map(([name, list]) => ({
      severity: "low" as const,
      rule: "config/duplicate-name",
      title: `Server name "${name}" is defined in ${list.length} scopes (${list.map((s) => s.scope).join(", ")})`,
      location: list.map((s) => s.source).join(", "),
      remediation: "Keep one definition. Claude Code picks one by scope precedence (local > project > user), so a project .mcp.json can silently replace a server you trust.",
    }));
}
