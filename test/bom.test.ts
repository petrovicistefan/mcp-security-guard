// The agent bill of materials: CycloneDX shape, what it holds, and what it must never hold.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { bomSummary, buildBom } from "../src/bom.js";

let root: string;
let project: string;
const saved = process.env.MCP_SECURITY_HOME;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "mcpsec-bom-"));
  project = join(root, "project");
  mkdirSync(project, { recursive: true });
  process.env.MCP_SECURITY_HOME = join(root, "state");
});
afterEach(() => {
  saved === undefined ? delete process.env.MCP_SECURITY_HOME : (process.env.MCP_SECURITY_HOME = saved);
});
const put = (rel: string, text: string) => {
  const p = join(project, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
};
const prop = (c: { properties: { name: string; value: string }[] }, k: string) => c.properties.find((p) => p.name === `mcp-security-guard:${k}`)?.value;

function fixture() {
  put(
    ".mcp.json",
    JSON.stringify({
      mcpServers: {
        files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2026.1.1", "/Users/secret/private"], env: { API_KEY: "sk-live-supersecretvalue1234567890" } },
        remote: { type: "http", url: "https://mcp.example.com/v1/path?token=abc123", headers: { Authorization: "Bearer topsecrettoken" } },
        loose: { command: "uvx", args: ["some-tool"] },
      },
    }),
  );
  put("CLAUDE.md", "# Project\nUse tabs.\n");
  put(".claude/skills/helper/SKILL.md", "---\nname: helper\ndescription: Formats text.\n---\nFormats text.\n");
}

describe("agent bill of materials", () => {
  it("is a CycloneDX 1.6 document with servers and context files", () => {
    fixture();
    const { bom } = buildBom(project, { projectOnly: true, serial: "00000000-0000-4000-8000-000000000000", now: new Date("2026-10-09T00:00:00Z") });
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.6");
    expect(bom.serialNumber).toBe("urn:uuid:00000000-0000-4000-8000-000000000000");
    expect(bom.metadata.timestamp).toBe("2026-10-09T00:00:00.000Z");
    const servers = bom.components.filter((c) => prop(c, "kind") === "mcp-server");
    expect(servers.map((s) => s.name).sort()).toEqual(["files", "loose", "remote"]);
    const files = servers.find((s) => s.name === "files")!;
    expect(files.purl).toBe("pkg:npm/%40modelcontextprotocol/server-filesystem@2026.1.1");
    expect(files.version).toBe("2026.1.1");
    const remote = servers.find((s) => s.name === "remote")!;
    expect(remote.type).toBe("service");
    expect(remote.endpoints).toEqual(["https://mcp.example.com"]);
    expect(prop(servers.find((s) => s.name === "loose")!, "version-pinned")).toBe("false");
    const ctx = bom.components.filter((c) => c.type === "file");
    expect(ctx.map((c) => c.name).sort()).toEqual(["CLAUDE.md", "skills/helper/SKILL.md"]);
    for (const c of ctx) expect(c.hashes![0].content).toMatch(/^[0-9a-f]{64}$/);
    expect(new Set(bom.components.map((c) => c["bom-ref"])).size).toBe(bom.components.length);
  });

  it("holds no paths, arguments, secrets, URL paths or file contents", () => {
    fixture();
    const json = JSON.stringify(buildBom(project, { projectOnly: true }).bom);
    for (const leak of ["/Users/secret", "sk-live", "supersecret", "topsecrettoken", "token=abc123", "/v1/path", "Use tabs", "Formats text", project]) expect(json).not.toContain(leak);
  });

  it("counts findings per server and says whether a server is pinned", () => {
    put(".mcp.json", JSON.stringify({ mcpServers: { leaky: { command: "node", args: ["x.js"], env: { TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" } } } }));
    const { bom, findings } = buildBom(project, { projectOnly: true });
    const s = bom.components.find((c) => c.name === "leaky")!;
    expect(Number(prop(s, "findings.high")) + Number(prop(s, "findings.critical"))).toBeGreaterThan(0);
    expect(prop(s, "pinned")).toBe("false");
    expect(prop(s, "grade")).not.toBe("A");
    expect(findings.length).toBeGreaterThan(0);
    expect(prop(s, "owasp")).toContain("MCP01");
  });

  it("summarises for audits with the OWASP MCP Top 10", () => {
    fixture();
    const { bom, findings } = buildBom(project, { projectOnly: true });
    const md = bomSummary(bom, findings);
    expect(md).toContain("# Agent bill of materials");
    expect(md).toContain("MCP servers: **3**");
    expect(md).toContain("| MCP01 |");
    expect(md).toContain("| MCP10 |");
    expect(md).toContain("pkg:npm/%40modelcontextprotocol/server-filesystem@2026.1.1");
  });

  it("works from the command line", () => {
    fixture();
    const cli = resolve(__dirname, "..", "plugin", "dist", "cli.mjs");
    const run = (...args: string[]) => spawnSync(process.execPath, [cli, "bom", "--project", project, "--project-only", ...args], { encoding: "utf8", env: { ...process.env, MCP_SECURITY_HOME: join(root, "state") } });
    const json = run("--format", "json");
    expect(json.status).toBe(0);
    expect(JSON.parse(json.stdout).bomFormat).toBe("CycloneDX");
    const out = join(root, "bom.md");
    expect(run("--output", out).status).toBe(0);
    expect(readFileSync(out, "utf8")).toContain("# Agent bill of materials");
    expect(run("--format", "sarif").status).toBe(2);
  });
});
