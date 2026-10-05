import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { INVISIBLE_RE } from "../src/sanitize.js";

// Our own sources must not contain the characters we flag in others. Test payloads use \u escapes instead.
const root = resolve(__dirname, "..");
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|mjs|json|md|yml)$/.test(n) ? [p] : [];
  });
}

describe("source hygiene", () => {
  for (const f of [...files(join(root, "src")), ...files(join(root, "test")), ...files(join(root, "skills")), ...files(join(root, "commands"))]) {
    it(`${f.slice(root.length + 1)} has no literal invisible or control characters`, () => {
      // U+FE0F after an emoji (warning sign + U+FE0F) is a normal variation selector.
      const text = readFileSync(f, "utf8").replace(/(\p{Extended_Pictographic})\uFE0F/gu, "$1");
      INVISIBLE_RE.lastIndex = 0;
      expect(text.match(INVISIBLE_RE) ?? []).toEqual([]);
      expect(CONTROL.test(text)).toBe(false);
    });
  }
});
