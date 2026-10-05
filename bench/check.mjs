// Regression gate for false positives: scans the real-server benchmarks and fails if any legitimate
// server gets a critical/high/medium finding outside the expected config ones. Needs network, and
// Docker with the bench/sandbox images for the stdio set (skipped with a note when unavailable).
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const sets = ["remote-public"];
const docker = spawnSync("docker", ["image", "inspect", "mcpsec-bench-node", "mcpsec-bench-python"], { stdio: "ignore" });
if (docker.status === 0) sets.push("stdio-sandbox");
else console.log("note: sandbox images not built, skipping stdio-sandbox (see bench/RESULTS.md)");

let failed = false;
for (const set of sets) {
  const out = execFileSync(process.execPath, [join(root, "dist/cli.mjs"), "scan", join(root, `bench/${set}.json`), "--confirm-launch", "--timeout", "60", "--fail-on", "none", "--format", "json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const bad = JSON.parse(out).findings.filter((f) => !f.rule.startsWith("config/") && ["critical", "high", "medium"].includes(f.severity));
  console.log(`${set}: ${bad.length ? `${bad.length} unexpected finding(s)` : "clean"}`);
  for (const f of bad) console.log(`  ${f.severity} ${f.rule} ${f.location}`);
  failed ||= bad.length > 0;
}
process.exit(failed ? 1 : 0);
