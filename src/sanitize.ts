// Everything the scanner echoes back is untrusted text written by a possibly
// malicious server. These helpers make it inert before it reaches the model.

/** Zero-width, bidi-control, tag and other invisible code points. */
export const INVISIBLE_RE =
  /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

export function revealInvisible(text: string): string {
  return text.replace(INVISIBLE_RE, (ch) => `<U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`);
}

export function truncate(text: string, max = 160): string {
  return text.length > max ? `${text.slice(0, max)}… (+${text.length - max} chars)` : text;
}

/** Keep a short prefix and suffix so the user can recognise the secret without it being reproduced. */
export function maskSecret(value: string): string {
  if (value.length <= 8) return "****";
  const keep = Math.min(6, Math.floor(value.length / 6));
  return `${value.slice(0, keep)}…${value.slice(-4)}`;
}

/** Excerpt of untrusted text, safe to embed in a report: invisible chars revealed, newlines flattened, length capped, backticks neutralised. */
export function excerpt(text: string, max = 160): string {
  return truncate(revealInvisible(text).replace(/\s+/g, " ").replace(/`/g, "ˋ").trim(), max);
}

/** Excerpt centred on a match so long descriptions still show the relevant part. */
export function excerptAround(text: string, index: number, length: number, radius = 70): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  return `${start > 0 ? "…" : ""}${excerpt(text.slice(start, end), radius * 2 + length + 20)}${end < text.length ? "…" : ""}`;
}
