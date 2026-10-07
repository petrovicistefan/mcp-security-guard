// Checks for the text files that end up in Claude's context besides MCP tools: CLAUDE.md, skills,
// slash commands, subagents, rules, plugin hooks and the scripts bundled with skills. Prose is
// checked for instruction override and concealment, hidden text and credential exfiltration; shell
// text (scripts, hooks, inline `!` commands, shell snippets) for download-and-run, encoded execution
// and commands that ship credential files off the machine.
import { excerpt, excerptAround } from "../sanitize.js";
import type { ContextFile } from "../context-files.js";
import type { Finding, Severity } from "../types.js";
import { DIRECTIVE_RE, PATTERNS, sentenceAt } from "./tool-rules.js";
import { sep } from "node:path";

const lineAt = (text: string, index: number) => text.slice(0, index).split("\n").length;

/** [start, end) ranges of fenced code blocks (``` or ~~~). An unclosed fence runs to the end of the file. */
function fenceRanges(text: string): [number, number][] {
  const out: [number, number][] = [];
  const re = /^[ \t]*(```|~~~)[^\n]*$/gm;
  let open: number | undefined;
  let marker = "";
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (open === undefined) {
      open = m.index;
      marker = m[1];
    } else if (m[1] === marker) {
      out.push([open, m.index + m[0].length]);
      open = undefined;
    }
  }
  if (open !== undefined) out.push([open, text.length]);
  return out;
}

const inRanges = (ranges: [number, number][], index: number) => ranges.some(([a, b]) => index >= a && index < b);

/** Words that mean a sentence is about attacks rather than carrying one. */
const ABOUT_ATTACKS_RE = /\b(?:attack(?:s|er|ers)?|malicious|payloads?|prompt[- ]injections?|jailbreak(?:s|ing)?|poison(?:ed|ing)?|red[- ]team(?:ing)?|untrusted|adversar\w+|exploit(?:s|ed)?)\b/i;

function isQuoted(text: string, index: number): boolean {
  return /["'“‘`«]\s*$/.test(text.slice(Math.max(0, index - 3), index));
}

// ── shell text ──────────────────────────────────────────────────────────────

/** Stores whose contents are secrets: private keys, cloud and package credentials, keychains, browser profiles, wallets. */
const STRONG_STORE = String.raw`\.ssh\b|\.aws\b|\.gnupg\b|\.kube\b|\.npmrc\b|\.netrc\b|\.pypirc\b|\.git-credentials\b|\bid_(?:rsa|ed25519|ecdsa)\b|credentials\.json\b|\bKeychains?\b|Login Data|\bwallet\.dat\b|\.config\/gcloud|\/etc\/(?:passwd|shadow)\b|(?:Chrome|Chromium|Firefox|BraveSoftware|Edge)\/[^\s"']*(?:Cookies|Login Data|key4\.db|logins\.json)`;
const ENV_FILE = String.raw`(?:^|[\s/"'\x60=@<~])\.env(?!\.(?:example|sample|template|dist|defaults)\b)\b`;
const NET_TOOLS = String.raw`(?:curl|wget|nc|ncat|netcat|scp|rsync|socat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)`;

const EXFIL_RE = new RegExp(`\\b${NET_TOOLS}\\b[^\\n]*?(?:(${STRONG_STORE})|(${ENV_FILE}))|(?:(${STRONG_STORE})|(${ENV_FILE}))[^\\n]*?\\|\\s*(?:base64[^\\n]*\\|\\s*)?${NET_TOOLS}\\b`, "gim");

const PIPE_TO_SHELL_RE = /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby)\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b|\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b/gi;

/** Hosts that carry payloads or collect data and that a legitimate install line never uses. */
const SUSPICIOUS_HOST_RE = /https?:\/\/(?:\d{1,3}(?:\.\d{1,3}){3}|[^/\s"']*(?:pastebin\.com|paste\.ee|hastebin|bit\.ly|tinyurl\.com|is\.gd|webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|transfer\.sh|interact\.sh|oast\.\w+|burpcollaborator|discord(?:app)?\.com\/api\/webhooks)[^\s"']*)/i;

const ENCODED_EXEC_RE = /\bbase64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\b(?:eval|exec)\b[^\n]*\bbase64\b[^\n]*(?:-d\b|--decode|b64decode|atob)|\bpowershell(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\b(?:python3?|node)\s+-[ce]\s+["'][^\n]*(?:b64decode|atob)|\bxxd\s+-r[^\n]*\|\s*(?:ba)?sh\b/gi;

const STEALER_STORE_RE = new RegExp(`(?:${STRONG_STORE})`, "i");
const NETWORK_CODE_RE = /\b(?:requests\.(?:post|put|get)|urllib\.request|http\.client|httpx\.|aiohttp|fetch\s*\(|axios\.|XMLHttpRequest|net\.connect|socket\.(?:socket|create_connection)|https?\.request)\b|\b(?:curl|wget|nc|ncat|Invoke-WebRequest)\b/;

interface ShellMeta {
  /** Runs without the user typing it: scripts, hooks and inline `!` commands, as opposed to a snippet in prose. */
  executes: boolean;
}

function shellFindings(text: string, base: number, meta: ShellMeta, make: (f: Omit<Finding, "location" | "file" | "line">, index: number) => Finding | undefined): Finding[] {
  const out: Finding[] = [];
  const push = (f: Omit<Finding, "location" | "file" | "line">, index: number) => {
    const made = make(f, base + index);
    if (made) out.push(made);
  };
  for (const m of text.matchAll(EXFIL_RE)) {
    const strong = Boolean(m[1] ?? m[3]);
    push(
      {
        severity: strong ? "critical" : "high",
        rule: "context/exfil-command",
        title: strong ? "Command sends credential files off the machine" : "Command sends an .env file off the machine",
        evidence: excerptAround(text, m.index!, m[0].length),
        remediation: "No skill, command or hook needs to upload private keys or credential files. Treat the plugin or file as malicious, remove it and rotate the credentials it could reach.",
      },
      m.index!,
    );
  }
  for (const m of text.matchAll(PIPE_TO_SHELL_RE)) {
    const suspicious = SUSPICIOUS_HOST_RE.test(text.slice(m.index!, m.index! + 400));
    push(
      {
        severity: suspicious || meta.executes ? "high" : "low",
        rule: "context/pipe-to-shell",
        title: suspicious ? "Downloads from a throwaway or anonymous host and runs it" : meta.executes ? "Downloads and runs code in one step" : "Install snippet downloads and runs code in one step",
        evidence: excerptAround(text, m.index!, m[0].length),
        remediation: "Content fetched at run time can change after you reviewed it. Pin a version or checksum, or download, read and then run it.",
      },
      m.index!,
    );
  }
  for (const m of text.matchAll(ENCODED_EXEC_RE)) {
    push(
      {
        severity: "high",
        rule: "context/encoded-execution",
        title: "Decodes a hidden payload and runs it",
        evidence: excerptAround(text, m.index!, m[0].length),
        remediation: "Decode and read the payload. Legitimate setup steps do not hide what they run.",
      },
      m.index!,
    );
  }
  return out;
}

// ── prose ───────────────────────────────────────────────────────────────────

const NEGATION_RE = /\b(?:never|do not|don't|dont|must not|should not|shouldn't|avoid|refuse|refrain|without|not to|no need to|instead of)\b/i;
const EGRESS_RE = /\b(?:send|upload|post|email|e-mail|webhook|curl|wget|exfiltrate|transmit|forward|share|paste|submit)\b|https?:\/\//i;

/** Zero-width and bidi-control characters that hide text. Emoji joiners, variation selectors and RTL marks are legitimate and not listed. */
const HIDDEN_STRONG_RE = /[\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/u;
const HIDDEN_WEAK_RE = /[\u200B\u2060-\u2064\u180E\u3164\uFFA0\u034F]/;
const ESCAPE_RE = /\u001b[[\]PX^_]|\u009b/;

/**
 * Concealment, worded for files that legitimately say "don't tell the user to run X" or "never write memory
 * without showing the user your plan". Only wording that hides *this* instruction or its effects counts.
 */
const CONCEAL_RES: RegExp[] = [
  /\b(?:do not|don't|dont|never|must not|should not)\b[^.!?\n]{0,30}\b(?:tell|inform|mention|notify|reveal|disclose|alert|show)\b[^.!?\n]{0,15}\b(?:this|that|it|these|those|the above|the following|any of)\b[^.!?\n]{0,30}\b(?:to|from)\s+(?:the\s+)?user/i,
  /\b(?:do not|don't|dont|never|must not|should not)\b[^.!?\n]{0,15}\b(?:tell|inform|notify|alert|warn|show)\s+(?:the\s+)?user\s+(?:about|of|that)\s+(?:this|it|these|the above|the following|the extra|the additional|any of)\b/i,
  /\b(?:hide|conceal|withhold)\b[^.!?\n]{0,25}\b(?:this|that|it|these|the above)\b[^.!?\n]{0,25}\bfrom\s+(?:the\s+)?user/i,
  /\bkeep\b[^.!?\n]{0,15}\b(?:this|that|it|these)\b[^.!?\n]{0,15}\b(?:secret|hidden|confidential|quiet)\b[^.!?\n]{0,20}\bfrom\s+(?:the\s+)?user/i,
  /\bwithout\s+(?:the\s+)?user\s+(?:knowing|noticing|seeing|realizing|being\s+aware)\b|\b(?:don't|do not|never)\s+let\s+(?:the\s+)?user\s+(?:know|see|notice|find out)\b/i,
  /\b(?:secretly|covertly|silently)\s+(?:send|upload|post|forward|exfiltrate|copy)\b/i,
];

const OVERRIDE_PATTERNS = PATTERNS.filter((p) => p.rule === "tool/instruction-override");
/** Non-English concealment phrases of the tool rules; the English one is replaced by CONCEAL_RES. */
const CONCEAL_NON_EN = PATTERNS.filter((p) => p.rule === "tool/conceal-from-user" && p.title.includes("non-English"));
const INSTRUCTION_PATTERNS: { rule: "context/instruction-override" | "context/conceal-from-user"; re: RegExp }[] = [
  ...OVERRIDE_PATTERNS.map((p) => ({ rule: "context/instruction-override" as const, re: p.re })),
  ...CONCEAL_NON_EN.map((p) => ({ rule: "context/conceal-from-user" as const, re: p.re })),
  ...CONCEAL_RES.map((re) => ({ rule: "context/conceal-from-user" as const, re })),
];

/** Private keys and credential stores a prose directive should never point the model at (public keys, ssh config and key generation are everyday setup). */
const PROSE_SECRET_RE = /\bid_(?:rsa|ed25519|ecdsa)\b(?!\.pub)|\.aws\/credentials|\.git-credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.gnupg\b|\bcredentials\.json\b|\bKeychains?\b|\bLogin Data\b|\bwallet\.dat\b|\bprivate (?:ssh )?keys?\b|\.ssh\/(?!config\b|known_hosts\b|authorized_keys\b|[\w.-]*\.pub\b)/gi;
const READ_OR_SEND_RE = /\b(?:read|reading|cat|open|load|include|send|upload|copy|attach|paste|extract|forward|post|share|embed|print|dump|output|exfiltrate)\b/i;
const SETUP_RE = /\b(?:ssh-keygen|ssh-add|add-key|generate|create|chmod|chown|\.pub)\b/i;

const MD_EXFIL_RE = /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*(?:[?&#][^)\s]*(?:\{|\$\{?|%s|<|\bdata=|\bq=|\bcontent=|\bprompt=|\bchat=|\bhistory=|\btoken=|\bsecret=)|\{[^})]*\})[^)]*\)|<img[^>]+src\s*=\s*["']?https?:\/\/[^"'\s>]*[?&][^"'\s>]*(?:\{|\$\{?|%s)/gi;

const PERMISSION_WEAKENING_RE = /--dangerously-skip-permissions|["']?defaultMode["']?\s*[:=]\s*["']?bypassPermissions|\benableAllProjectMcpServers["']?\s*[:=]\s*true|--permission-mode[ =]bypassPermissions/gi;

function parseFrontmatter(text: string): { block: string; end: number } | undefined {
  const m = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(text);
  return m ? { block: m[1], end: m[0].length } : undefined;
}

/** `allowed-tools` entries of a skill or command: comma list, space list, inline list or YAML list. */
function allowedTools(block: string): string[] {
  const lines = block.split(/\r?\n/);
  const i = lines.findIndex((l) => /^allowed-tools[ \t]*:/i.test(l));
  if (i < 0) return [];
  const first = lines[i].replace(/^allowed-tools[ \t]*:/i, "").trim().replace(/^\[|\]$/g, "");
  const items = first ? (first.includes(",") || first.includes("(") ? first.split(/,(?![^(]*\))/) : first.split(/\s+/)) : [];
  for (let j = i + 1; j < lines.length && /^[ \t]*-[ \t]+/.test(lines[j]); j++) items.push(lines[j].replace(/^[ \t]*-[ \t]+/, ""));
  return items.map((t) => t.trim().replace(/^["']|["']$/g, "")).filter(Boolean);
}

const shortPath = (p: string) => p.split(sep).slice(-3).join("/");

export function analyzeContextFile(file: ContextFile): Finding[] {
  const { text, kind, origin, name, path } = file;
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const where = (index: number) => `${kind} "${excerpt(name, 50)}" (${origin}) › ${excerpt(shortPath(path), 90)}:${lineAt(text, index)}`;
  const make = (f: Omit<Finding, "location" | "file" | "line">, index: number): Finding | undefined => {
    const line = lineAt(text, index);
    const key = `${f.rule}|${line}`;
    if (seen.has(key)) return undefined;
    seen.add(key);
    return { ...f, location: where(index), file: path, line };
  };
  const add = (f: Omit<Finding, "location" | "file" | "line">, index: number) => {
    const made = make(f, index);
    if (made) findings.push(made);
  };

  // Text that hides itself, whatever the file type.
  const strong = HIDDEN_STRONG_RE.exec(text);
  const weak = HIDDEN_WEAK_RE.exec(text);
  const bom = text.indexOf("\uFEFF", 1);
  if (strong || weak || bom > 0) {
    const index = strong?.index ?? weak?.index ?? bom;
    const count = [...text.matchAll(new RegExp(`${HIDDEN_STRONG_RE.source}|${HIDDEN_WEAK_RE.source}`, "gu"))].length || 1;
    add({ severity: strong ? "critical" : "high", rule: "context/invisible-characters", title: `Contains ${count} invisible or bidi-control character(s)`, evidence: excerptAround(text, index, 1), remediation: "Invisible characters hide text from human reviewers while the model still reads it. Treat the file as malicious." }, index);
  }
  const esc = ESCAPE_RE.exec(text);
  if (esc) add({ severity: "high", rule: "context/ansi-escape", title: "Contains terminal escape sequences", evidence: excerptAround(text, esc.index, 1), remediation: "Escape sequences can hide or rewrite text in terminal UIs while the model still reads it." }, esc.index);

  // Scripts bundled with skills, and plugin hook configs: shell text that runs.
  if (kind === "script" || kind === "hooks") {
    if (kind === "hooks") {
      // Hook commands live in JSON strings: analyse the decoded command, report against the file.
      for (const m of text.matchAll(/"command"\s*:\s*"((?:[^"\\]|\\.)*)"/g)) {
        let cmd = m[1];
        try {
          cmd = JSON.parse(`"${m[1]}"`);
        } catch {}
        findings.push(...shellFindings(cmd, m.index!, { executes: true }, make));
      }
      return findings;
    }
    findings.push(...shellFindings(text, 0, { executes: true }, make));
    // Credential stealers: a script that touches browser profiles, wallets or key stores and also talks to the network.
    const store = STEALER_STORE_RE.exec(text);
    if (store && NETWORK_CODE_RE.test(text) && !/\b(?:tests?|mocks?|fixtures?)\b/i.test(path)) {
      add({ severity: "high", rule: "context/credential-stealer", title: "Script reads credential stores and also has network access", evidence: excerptAround(text, store.index, store[0].length), remediation: "A skill script that opens private keys, keychains, wallets or browser profiles and can reach the network matches the infostealer pattern seen in malicious skills. Read the script before running it." }, store.index);
    }
    return findings;
  }

  // Prose files from here on.
  const fm = parseFrontmatter(text);
  const fences = fenceRanges(text);

  // Instruction override (patterns shared with the tool rules) and concealment.
  for (const p of INSTRUCTION_PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : `${p.re.flags}g`);
    let count = 0;
    for (let m = re.exec(text); m && count < 50; m = re.exec(text), count++) {
      const sentence = sentenceAt(text, m.index);
      const docs = inRanges(fences, m.index) || isQuoted(text, m.index) || ABOUT_ATTACKS_RE.test(sentence);
      const override = p.rule === "context/instruction-override";
      const severity: Severity = docs ? "medium" : override ? "critical" : "high";
      add({
        severity,
        rule: p.rule,
        title: `${override ? "Tries to override the model's instructions" : "Asks the model to hide something from the user"}${docs ? " (appears in an example or documentation)" : ""}`,
        evidence: excerptAround(text, m.index, m[0].length),
        remediation: docs
          ? "This looks like a quoted example. Read the surrounding text to confirm it is not an instruction the model will follow."
          : override
            ? "Skills, commands and CLAUDE.md files have no reason to tell the model to ignore its other instructions. Treat the file as malicious and find where it came from."
            : "Legitimate instructions do not ask for secrecy towards the user. Read the file and remove it unless this is a deliberate persona rule you wrote.",
      }, m.index);
    }
  }

  // HTML comments addressed to the model: invisible in rendered Markdown, fully visible to the model.
  for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) {
    const body = m[1];
    const toModel = /\b(?:assistant|claude|ai agent|ai assistant|the model|language model|llm)\b/i.test(body);
    const override = INSTRUCTION_PATTERNS.some((p) => p.re.test(body));
    const secrets = new RegExp(PROSE_SECRET_RE.source, "i").test(body) && READ_OR_SEND_RE.test(body);
    if (toModel || override || secrets) {
      add({ severity: "high", rule: "context/hidden-comment", title: "HTML comment addressed to the model (hidden from rendered views)", evidence: excerptAround(text, m.index!, m[0].length), remediation: "Comments are invisible in rendered Markdown but fully visible to the model. Read the comment text and remove it if it is not yours." }, m.index!);
    }
  }

  // Directives to read credential stores, outside fenced code and not phrased as a prohibition or as key setup.
  for (const m of text.matchAll(PROSE_SECRET_RE)) {
    if (inRanges(fences, m.index!)) continue;
    const sentence = sentenceAt(text, m.index!);
    if (!READ_OR_SEND_RE.test(sentence) || NEGATION_RE.test(sentence) || ABOUT_ATTACKS_RE.test(sentence) || SETUP_RE.test(sentence)) continue;
    const egress = EGRESS_RE.test(sentence);
    add({
      severity: egress ? "high" : "medium",
      rule: "context/sensitive-path",
      title: egress ? "Tells the model to read credential files and send data out" : "Tells the model to read credential files",
      evidence: excerptAround(text, m.index!, m[0].length),
      remediation: "A skill, command or CLAUDE.md file has no reason to direct the model at private keys or credential stores. Remove it unless the sentence is clearly documentation.",
    }, m.index!);
  }

  // Zero-click exfiltration through rendered images.
  for (const m of text.matchAll(MD_EXFIL_RE)) {
    add({ severity: "high", rule: "context/markdown-exfiltration", title: "Embeds a remote image with data placeholders", evidence: excerptAround(text, m.index!, m[0].length), remediation: "When the client renders this image, the query string is sent to the remote host. That is a zero-click exfiltration channel." }, m.index!);
  }

  // Shell: snippets in prose (documentation, medium) and inline `!` commands that run when a command or skill loads.
  const shellBlocks: { text: string; base: number; executes: boolean }[] = [];
  for (const m of text.matchAll(/!`([^`\n]+)`/g)) shellBlocks.push({ text: m[1], base: m.index! + 2, executes: kind === "command" || kind === "skill" });
  for (const [start, end] of fences) shellBlocks.push({ text: text.slice(start, end), base: start, executes: false });
  const proseOutsideFences = fences.reduce((t, [a, b]) => t.slice(0, a) + " ".repeat(b - a) + t.slice(b), text);
  shellBlocks.push({ text: proseOutsideFences, base: 0, executes: false });
  for (const b of shellBlocks) findings.push(...shellFindings(b.text, b.base, { executes: b.executes }, make));

  // Permissions the file asks the model to give itself.
  for (const m of text.matchAll(PERMISSION_WEAKENING_RE)) {
    add({ severity: "medium", rule: "context/permission-weakening", title: "Tells the model or the user to switch off Claude Code's permission checks", evidence: excerptAround(text, m.index!, m[0].length), remediation: "Permission prompts are the safety net for every other finding. Do not follow instructions that disable them." }, m.index!);
  }

  // Tools a skill or command pre-approves.
  if (fm && (kind === "skill" || kind === "command")) {
    const broad = allowedTools(fm.block).filter((t) => /^(?:\*|Bash|Bash\(\s*\*?\s*\)|Bash\(\*:\*\))$/.test(t));
    if (broad.length) {
      add({ severity: origin === "project" ? "medium" : origin === "user" ? "info" : "low", rule: "context/overbroad-tools", title: `Pre-approves unrestricted shell access (allowed-tools: ${excerpt(broad.join(", "), 60)})`, evidence: excerpt(fm.block.split("\n").find((l) => /^allowed-tools/i.test(l)) ?? "", 120), remediation: "Tools listed in allowed-tools run without asking. Restrict it to the commands this skill needs, e.g. Bash(git status:*)." }, text.indexOf("allowed-tools"));
    }
  }
  return findings;
}

export function analyzeContext(files: ContextFile[]): Finding[] {
  return files.flatMap(analyzeContextFile);
}
