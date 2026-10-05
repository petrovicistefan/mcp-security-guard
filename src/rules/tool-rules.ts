import { INVISIBLE_RE, excerpt, excerptAround } from "../sanitize.js";
import type { Finding, Severity, ToolDefinition } from "../types.js";

interface TextField {
  path: string;
  text: string;
}

/** Every string a model will read: name, title, description, and descriptions/defaults/enums anywhere in the schema. */
export function collectText(tool: ToolDefinition): TextField[] {
  const out: TextField[] = [{ path: "name", text: tool.name }];
  if (tool.title) out.push({ path: "title", text: tool.title });
  if (tool.description) out.push({ path: "description", text: tool.description });
  const walk = (node: unknown, path: string) => {
    if (typeof node === "string") {
      out.push({ path, text: node });
    } else if (Array.isArray(node)) {
      node.forEach((n, i) => walk(n, `${path}[${i}]`));
    } else if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        // `$schema`/`$ref` are URLs and `pattern` is a regex; `type` and `format` are kept because
        // full-schema poisoning hides instructions in them.
        if (["$schema", "$ref", "pattern"].includes(k) && typeof v === "string") continue;
        if (path.endsWith(".properties")) out.push({ path: `${path}.${k} (name)`, text: k });
        walk(v, `${path}.${k}`);
      }
    }
  };
  walk(tool.inputSchema, "inputSchema");
  walk(tool.annotations, "annotations");
  return out;
}

interface MatchContext {
  /** The sentence (or line) containing the match. */
  sentence: string;
  /** Tool names of the server being analysed. */
  ownTools: string[];
}

/** Verbs that turn a mention into an instruction to the model. */
const DIRECTIVE_RE = /\b(read|reading|cat|open|load|include|including|pass|send|upload|copy|attach|paste|append|put|provide|extract|forward|post|share|embed|add|insert|fill)\b/i;

function sentenceAt(text: string, index: number): string {
  const before = text.slice(0, index).search(/(?:[.!?](?=\s)|\n)[^.!?\n]*$/);
  const start = before < 0 ? 0 : before + 1;
  const after = text.slice(index).search(/[.!?](?=\s|$)|\n/);
  return text.slice(start, after < 0 ? text.length : index + after);
}

const PATTERNS: { rule: string; severity: Severity; title: string; re: RegExp; remediation: string; refine?: (ctx: MatchContext) => { severity: Severity; title?: string } | null }[] = [
  {
    rule: "tool/instruction-override",
    severity: "critical",
    title: "Tries to override the model's instructions",
    re: /\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|other|system)\b.{0,20}\b(instructions?|rules|prompts?|directions|guidelines)\b/i,
    remediation: "A tool description has no reason to talk about the model's other instructions. Treat this server as malicious and remove it.",
  },
  {
    rule: "tool/conceal-from-user",
    severity: "critical",
    title: "Asks the model to hide something from the user",
    re: /\b(do not|don't|dont|never|without)\b.{0,25}\b(tell|telling|inform|informing|mention|mentioning|notify|notifying|reveal|revealing|show|showing|alert|alerting)\b.{0,25}\b(the )?user\b/i,
    remediation: "Legitimate tools never ask for secrecy. Remove the server and check what it has already been called with.",
  },
  {
    rule: "tool/hidden-instruction-tag",
    severity: "high",
    title: "Contains pseudo-system tags typical of tool poisoning",
    re: /<\s*\/?\s*(important|system|instructions?|secret|hidden|admin|assistant|context)\s*>/i,
    remediation: "Tags like <IMPORTANT> are used to make injected text look authoritative. Review the full description before trusting this tool.",
  },
  {
    rule: "tool/role-hijack",
    severity: "high",
    title: "Attempts to redefine the model's role",
    re: /\b(you are now|from now on,? you|act as (an?|the) |new instructions|system prompt|developer mode|jailbreak)\b/i,
    remediation: "Remove the server unless the wording is clearly documentation (e.g. a tool that edits system prompts).",
  },
  {
    rule: "tool/precondition-chain",
    severity: "medium",
    title: "Tells the model to do something else before or after calling it",
    re: /\b(before|prior to|after)\b.{0,30}\b(using|calling|invoking|running|executing)\b.{0,40}\b(you must|must first|first (read|call|run|fetch|send)|always (read|call|run|send|include))\b/i,
    remediation: "Check what the extra step does. Poisoned tools use this to make the model read files or call other tools on their behalf.",
    // "Before calling this tool you must first call list_projects" is normal API sequencing within one server.
    refine: ({ sentence, ownTools }) => (ownTools.some((n) => toolMention(n).test(sentence)) ? null : { severity: "medium" }),
  },
  {
    rule: "tool/sensitive-path",
    severity: "high",
    title: "Instructs the model to access credential files or secrets",
    // Dot-directories must start a path segment, so domains like repost.aws or docs.docker.com do not match.
    // `.env.example` and friends are templates, not secrets.
    re: /(?:^|[\s"'`(~\\/])\.(?:ssh|aws|gnupg|kube|docker|config\/gh)(?![\w.-])|\bid[_ ]?(?:rsa|ed25519|ecdsa)\b|(?:^|[\s/"'`])\.env(?!\.(?:example|sample|template|dist|defaults)\b)\b|\b(?:ssh|pgp|gpg)\s+(?:private\s+)?keys?\b|\bprivate\s+keys?\b|\bseed\s+phrase\b|\.netrc\b|\.npmrc\b|\.pypirc\b|\bcredentials\.json\b|\.git-credentials\b|\bclaude(?:_desktop_config)?\.json\b|\bmcp\.json\b|\/etc\/(?:passwd|shadow)\b|\bkeychain\b/i,
    remediation: "A tool description has no reason to direct the model at secrets. Remove the server unless the sentence is clearly documentation.",
    // A bare mention ("uses the kubeconfig at ~/.kube/config", "refuses .env files") is documentation;
    // pairing it with an action verb ("read ~/.ssh/id_rsa and pass it") is the poisoning pattern.
    refine: ({ sentence }) => (DIRECTIVE_RE.test(sentence) ? { severity: "high" } : { severity: "low", title: "Mentions a credential file or sensitive path" }),
  },
  {
    rule: "tool/context-harvesting",
    severity: "high",
    title: "Asks for the conversation, system prompt or prior messages",
    re: /\b(?:conversation|chat)[\s_]+(?:history|log|transcript|context)\b|\b(?:previous|prior|earlier|all)\s+(?:user\s+)?messages\b|\bsystem[\s_]+prompt\b|\bsummary[\s_]+of[\s_]+(?:the[\s_]+)?conversation\b/i,
    remediation: "Tools that need the conversation itself are rare. Harvesting it into a parameter or URL is a standard exfiltration technique.",
    refine: ({ sentence }) => (DIRECTIVE_RE.test(sentence) ? { severity: "high" } : { severity: "low", title: "Mentions the conversation or system prompt" }),
  },
  {
    rule: "tool/markdown-exfiltration",
    severity: "high",
    title: "Embeds a remote image or link with data placeholders",
    re: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*[?#{][^)]*\)|<img[^>]+src\s*=\s*["']?https?:\/\/[^"'\s>]*[?{]/i,
    remediation: "When the client renders this image, the query string is sent to the remote host. That is a zero-click exfiltration channel.",
  },
  {
    rule: "tool/hidden-comment",
    severity: "high",
    title: "Contains an HTML comment (hidden from rendered views)",
    re: /<!--[\s\S]*?-->/,
    remediation: "Comments are invisible in rendered Markdown but fully visible to the model. Read the comment text.",
  },
  {
    rule: "tool/exfiltration-wording",
    severity: "medium",
    title: "Describes sending data to an external destination",
    re: /\b(send|post|upload|forward|transmit|exfiltrate|copy|include|append)\b.{0,50}\b(to|into|in)\b.{0,40}(https?:\/\/|webhook|endpoint|remote server|e-?mail|\bcc\b|bcc|the ['"`]?[\w-]+['"`]? (?:parameter|argument|field))/i,
    remediation: "Confirm the destination is the tool's own documented API. Exfiltration attacks hide data in parameters or redirect it to attacker URLs.",
  },
  {
    rule: "tool/encoded-payload",
    severity: "medium",
    title: "Contains a long encoded blob",
    re: /(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?|(?:\\x[0-9a-f]{2}){12,}|(?:%[0-9a-f]{2}){12,}/i,
    remediation: "Decode and review it. Encoded text in a description is a common way to slip instructions past reviewers.",
  },
  {
    rule: "tool/cross-tool-reference",
    severity: "medium",
    title: "Gives instructions about other tools",
    re: /\b(when|whenever|if)\b.{0,30}\b(any|other|another|all)\b.{0,15}\btools?\b|\b(instead of|rather than)\b.{0,20}\b(using|calling)\b.{0,30}\btool\b/i,
    remediation: "A tool should describe itself. Instructions about other tools are how one server hijacks another (tool shadowing).",
  },
];

/**
 * Regex for a reference to tool `name`. Identifier-like names (send_email, getUser, list-repos) match as
 * whole words. Names that are plain words ("fetch", "search") only match when clearly used as a tool
 * name: quoted, in backticks, called like a function, or followed by "tool".
 */
function toolMention(name: string): RegExp {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (/[_\-.\d]|[a-z][A-Z]/.test(name)) return new RegExp(`(?<![\\w-])${n}(?![\\w-])`);
  return new RegExp(`[\`'"]${n}[\`'"]|\\b${n}\\s*\\(|\\b${n}\\s+tool\\b`, "i");
}

const URL_RE = /https?:\/\/[^\s"'<>)`]+/gi;
/** ANSI/terminal escapes (ESC [, ESC ], 8-bit CSI) and other C0/C1 controls apart from tab and newline. */
const ESCAPE_RE = /\u001b[[\]PX^_]|\u009b/;
const CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001a\u001c-\u001f\u007f\u0080-\u009a\u009c-\u009f]/;
const SCHEMA_TYPES = new Set(["string", "number", "integer", "boolean", "object", "array", "null"]);
const MAX_DESCRIPTION = 1500;

function collidingServers(name: string, others: Record<string, string[]>): string[] {
  return Object.entries(others)
    .filter(([, names]) => names.includes(name))
    .map(([srv]) => srv);
}

function invalidSchemaTypes(node: unknown, path: string): { path: string; value: string }[] {
  if (!node || typeof node !== "object") return [];
  if (Array.isArray(node)) return node.flatMap((n, i) => invalidSchemaTypes(n, `${path}[${i}]`));
  const out: { path: string; value: string }[] = [];
  for (const [k, v] of Object.entries(node)) {
    if (k === "type") {
      for (const t of Array.isArray(v) ? v : [v]) if (typeof t === "string" && !SCHEMA_TYPES.has(t)) out.push({ path: `${path}.type`, value: t });
    } else if (k !== "const" && k !== "default" && k !== "examples" && k !== "enum") {
      out.push(...invalidSchemaTypes(v, `${path}.${k}`));
    }
  }
  return out;
}

/** Tool-shaped definitions built from instructions, prompts and resources carry a prefix (see surfaceDefinitions). */
export function describeDefinition(name: string): { kind: "tool" | "instructions" | "prompt" | "resource" | "template"; label: string } {
  if (name === "#instructions") return { kind: "instructions", label: "" };
  const m = /^(prompt|resource|template):(.*)$/s.exec(name);
  return m ? { kind: m[1] as "prompt" | "resource" | "template", label: m[2] } : { kind: "tool", label: name };
}

/** Analyse one server's tools. `otherServersTools` maps other server names to their tool names, for shadowing detection. */
export function analyzeTools(serverName: string, tools: ToolDefinition[], otherServersTools: Record<string, string[]> = {}): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const add = (f: Finding) => {
    const key = `${f.rule}|${f.location}`;
    if (!seen.has(key)) {
      seen.add(key);
      findings.push(f);
    }
  };

  const otherNames = Object.entries(otherServersTools).flatMap(([srv, names]) =>
    names.filter((n) => n.length >= 4 && !tools.some((t) => t.name === n)).map((n) => ({ srv, n })),
  );

  for (const tool of tools) {
    const { kind, label } = describeDefinition(tool.name);
    const where = (p: string) => (kind === "instructions" ? `server "${serverName}" › server instructions` : `server "${serverName}" › ${kind} "${excerpt(label, 60)}" › ${p}`);

    if (kind === "tool" && /[^\x20-\x7E]/.test(tool.name)) {
      add({ severity: "medium", rule: "tool/non-ascii-name", title: "Tool name contains non-ASCII characters (possible homoglyph impersonation)", location: where("name"), evidence: excerpt(tool.name), remediation: "Tool names should be plain ASCII. Look-alike characters let a tool impersonate a trusted one." });
    }
    if ((tool.description?.length ?? 0) > MAX_DESCRIPTION) {
      add({ severity: "low", rule: "tool/oversized-description", title: `Description is unusually long (${tool.description!.length} chars)`, location: where("description"), remediation: "Long descriptions are where injected instructions usually hide. Read the full text." });
    }

    for (const other of kind === "tool" ? collidingServers(tool.name, otherServersTools) : []) {
      add({ severity: "medium", rule: "tool/name-collision", title: `Tool name also exposed by server "${excerpt(other, 50)}"`, location: where("name"), evidence: excerpt(tool.name), remediation: "Two servers with the same tool name leave it to the client which one runs, and one can impersonate the other. Rename or disable one of them." });
    }
    for (const bad of invalidSchemaTypes(tool.inputSchema, "inputSchema")) {
      add({ severity: "high", rule: "tool/schema-anomaly", title: "Schema `type` field contains text that is not a JSON Schema type", location: where(bad.path), evidence: excerpt(bad.value), remediation: "Valid types are string, number, integer, boolean, object, array and null. Free text here is full-schema poisoning: the model reads it, schema validators ignore it." });
    }

    for (const { path, text: raw } of collectText(tool)) {
      // Identifiers like content_from_reading_ssh_id_rsa are read by the model as words.
      const text = path === "name" || path.endsWith("(name)") ? raw.replace(/[_-]+/g, " ") : raw;
      if (ESCAPE_RE.test(raw)) {
        add({ severity: "critical", rule: "tool/ansi-escape", title: "Contains terminal escape sequences", location: where(path), evidence: excerpt(raw), remediation: "ANSI escapes can hide or rewrite text in terminal UIs while the model still reads it (Trail of Bits, 2025). No legitimate tool description needs them." });
      } else if (CONTROL_RE.test(raw)) {
        add({ severity: "high", rule: "tool/control-characters", title: "Contains non-printing control characters", location: where(path), evidence: excerpt(raw), remediation: "Control characters have no place in tool metadata and can confuse renderers and reviewers." });
      }
      INVISIBLE_RE.lastIndex = 0;
      const inv = text.match(INVISIBLE_RE);
      if (inv) {
        add({ severity: "critical", rule: "tool/invisible-characters", title: `Contains ${inv.length} invisible or bidi-control character(s)`, location: where(path), evidence: excerpt(text), remediation: "Invisible characters hide text from human reviewers while the model still reads it. Treat as malicious." });
      }
      for (const p of PATTERNS) {
        const m = p.re.exec(text);
        if (!m) continue;
        const refined = p.refine ? p.refine({ sentence: sentenceAt(text, m.index), ownTools: tools.map((t) => t.name) }) : { severity: p.severity };
        if (refined) add({ severity: refined.severity, rule: p.rule, title: refined.title ?? p.title, location: where(path), evidence: excerptAround(text, m.index, m[0].length), remediation: p.remediation });
      }
      const urls = text.match(URL_RE);
      if (urls && path !== "name") {
        add({ severity: "info", rule: "tool/embedded-url", title: `Mentions ${urls.length} URL(s)`, location: where(path), evidence: urls.slice(0, 3).map((u) => excerpt(u, 80)).join(", "), remediation: "Check that each URL belongs to the service this server integrates with." });
      }
      for (const { srv, n } of otherNames) {
        const idx = text.search(toolMention(n));
        if (idx >= 0 && path !== "name") {
          add({ severity: "high", rule: "tool/shadowing", title: `Mentions tool "${excerpt(n, 60)}" from another server ("${srv}")`, location: where(path), evidence: excerptAround(text, idx, n.length), remediation: `A server referencing another server's tools may be trying to change how "${srv}" is used (tool shadowing). Disable one of the two until reviewed.` });
        }
      }
    }
  }
  return findings;
}
