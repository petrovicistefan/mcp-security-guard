import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "mcp-offline-demo-"));
try {
  for (const [sample, expectedStatus, expectedRules] of [
    ["poisoned", 1, ["tool/instruction-override", "tool/sensitive-path"]],
    ["clean", 0, []],
  ]) {
    const output = join(temporary, sample + ".json");
    const errors = join(temporary, sample + ".stderr");
    const stdout = openSync(output, "w");
    const stderr = openSync(errors, "w");
    let status;
    try {
      status = await new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [
          "plugin/dist/cli.mjs", "analyze-tools",
          `examples/offline-demo/${sample}.json`,
          "--name", "offline-demo", "--format", "json",
        ], { cwd: root, timeout: 15_000, stdio: ["ignore", stdout, stderr] });
        child.on("error", reject);
        child.on("close", (code, signal) => {
          if (signal) reject(new Error(`Demo terminated by ${signal}`));
          else resolve(code);
        });
      });
    } finally {
      closeSync(stdout);
      closeSync(stderr);
    }
    assert.equal(status, expectedStatus, readFileSync(errors, "utf8"));
    const report = JSON.parse(readFileSync(output, "utf8"));
    assert.deepEqual(report.findings.map(f => f.rule).sort(), [...expectedRules].sort());
    console.log(`${sample}: ${report.findings.length} findings, exit ${status} (expected)`);
  }
  console.log("Offline demo passed. No MCP servers were launched.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
