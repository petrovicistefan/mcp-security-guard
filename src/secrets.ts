import { maskSecret } from "./sanitize.js";

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "Anthropic API key", re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: "OpenAI API key", re: /sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/ },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { name: "GitHub fine-grained token", re: /github_pat_[A-Za-z0-9_]{22,}/ },
  { name: "AWS access key ID", re: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
  { name: "Slack token", re: /xox[abposr]-[A-Za-z0-9-]{10,}/ },
  { name: "Stripe live key", re: /(?:sk|rk)_live_[A-Za-z0-9]{20,}/ },
  { name: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/ },
  { name: "Private key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "JWT", re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: "Bearer token", re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/ },
];

const SECRET_KEY_NAME_RE = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH|COOKIE|SESSION)/i;

/** `${VAR}`, `${VAR:-default}` or `$VAR`: a reference, not a literal value. */
export function isEnvReference(value: string): boolean {
  return /^\$\{[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?\}$|^\$[A-Za-z_][A-Za-z0-9_]*$/.test(value.trim());
}

export interface SecretHit {
  kind: string;
  masked: string;
}

export function findKnownSecret(value: string): SecretHit | undefined {
  for (const { name, re } of SECRET_PATTERNS) {
    const m = value.match(re);
    if (m) return { kind: name, masked: maskSecret(m[0]) };
  }
  return undefined;
}

function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** A literal value stored under a secret-looking key name, or a high-entropy token. */
export function looksLikeSecretValue(key: string, value: string): SecretHit | undefined {
  if (isEnvReference(value)) return undefined;
  const known = findKnownSecret(value);
  if (known) return known;
  const v = value.trim();
  if (SECRET_KEY_NAME_RE.test(key) && v.length >= 8 && !/^(true|false|\d+|https?:\/\/\S+)$/i.test(v)) {
    return { kind: "Literal credential", masked: maskSecret(v) };
  }
  if (v.length >= 32 && !/\s/.test(v) && shannonEntropy(v) > 4.2) {
    return { kind: "High-entropy string", masked: maskSecret(v) };
  }
  return undefined;
}
