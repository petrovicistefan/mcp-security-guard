// Everything the scanner echoes back is untrusted text written by a possibly
// malicious server. These helpers make it inert before it reaches the model.

/** Zero-width, bidi-control, tag and other invisible code points. */
export const INVISIBLE_RE =
  /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

/** C0/C1 controls except tab/newline/CR, including ESC: never echo these raw, they can drive the terminal. */
const CONTROL_CHARS_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;

export function revealInvisible(text: string): string {
  return text.replace(CONTROL_CHARS_RE, (ch) => `<U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}>`).replace(INVISIBLE_RE, (ch) => `<U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`);
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
