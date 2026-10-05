import { describe, expect, it } from "vitest";
import { analyzeTools } from "../src/rules/tool-rules.js";
import { SEVERITY_ORDER, type Severity } from "../src/types.js";
import { CORPUS } from "./corpus.js";

const rank = (s: Severity) => SEVERITY_ORDER.indexOf(s);
const worst = (id: string) => {
  const sample = CORPUS.find((c) => c.id === id)!;
  const fs = analyzeTools(id, sample.tools, sample.others);
  return { fs, worst: fs.reduce<Severity>((w, f) => (rank(f.severity) < rank(w) ? f.severity : w), "info") };
};

/** Malicious samples that are known gaps: documented in bench/RESULTS.md instead of hidden. */
const KNOWN_MISSES = new Set<string>();
/** Benign samples that legitimately deserve a "review" (medium) finding. */
const ACCEPTED_MEDIUM = new Set<string>();

describe("detection corpus", () => {
  const rows = CORPUS.map((c) => ({ ...c, ...worst(c.id) }));

  it("prints the scorecard", () => {
    const mal = rows.filter((r) => r.malicious);
    const ben = rows.filter((r) => !r.malicious);
    const detected = mal.filter((r) => rank(r.worst) <= rank("medium"));
    const fpHigh = ben.filter((r) => rank(r.worst) <= rank("high"));
    const fpMedium = ben.filter((r) => r.worst === "medium");
    console.log(
      [
        `detection: ${detected.length}/${mal.length} malicious samples flagged at medium or above`,
        `false positives: ${fpHigh.length}/${ben.length} benign at high+, ${fpMedium.length}/${ben.length} at medium`,
        ...rows.map((r) => `${r.malicious ? "M" : "B"} ${r.worst.padEnd(8)} ${r.id.padEnd(24)} ${[...new Set(r.fs.map((f) => f.rule))].join(", ")}`),
      ].join("\n"),
    );
  });

  for (const r of rows.filter((r) => r.malicious && !KNOWN_MISSES.has(r.id))) {
    it(`detects ${r.id} (${r.technique})`, () => expect(rank(r.worst)).toBeLessThanOrEqual(rank("medium")));
  }
  for (const r of rows.filter((r) => !r.malicious)) {
    it(`does not flag ${r.id}`, () => expect(rank(r.worst)).toBeGreaterThan(rank(ACCEPTED_MEDIUM.has(r.id) ? "high" : "medium")));
  }
});
