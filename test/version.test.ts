import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { VERSION } from "../src/version.js";

const root = resolve(__dirname, "..");
const readJson = (rel: string) => JSON.parse(readFileSync(resolve(root, rel), "utf8"));

describe("version single source of truth", () => {
  it("VERSION matches package.json", () => {
    expect(VERSION).toBe(readJson("package.json").version);
  });

  it("server.json and the plugin manifest match package.json", () => {
    const { version } = readJson("package.json");
    const server = readJson("server.json");
    expect(server.version).toBe(version);
    for (const p of server.packages) expect(p.version).toBe(version);
    expect(readJson("plugin/.claude-plugin/plugin.json").version).toBe(version);
  });

  it("src/version.ts does not hardcode the package version", () => {
    const src = readFileSync(resolve(root, "src/version.ts"), "utf8");
    expect(src).not.toContain(readJson("package.json").version);
  });
});
