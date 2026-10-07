import { describe, expect, it } from "vitest";
import { legsOf, toxicFlowFindings } from "../src/toxic-flow.js";
import type { ServerConfig, ToolDefinition } from "../src/types.js";

const server = (name: string, scope: ServerConfig["scope"] = "project"): ServerConfig => ({ name, scope, source: "/p/.mcp.json", command: "x" });
const obj = (...keys: string[]) => ({ type: "object", properties: Object.fromEntries(keys.map((k) => [k, { type: "string" }])) });
const tool = (name: string, ...params: string[]): ToolDefinition => ({ name, description: "x", inputSchema: obj(...params) });

// Shaped like the official GitHub server: reads issues and code, writes comments and issues.
const github = [tool("get_file_contents", "path"), tool("list_issues"), tool("search_code"), tool("add_issue_comment", "body"), tool("create_pull_request", "title")];
const filesystem = [tool("read_file", "path"), tool("write_file", "path", "content"), tool("list_directory", "path")];
const fetchServer = [tool("fetch", "url")];
const weather = [tool("get_forecast", "city")];
const shell = [tool("run_command", "command")];

describe("toxic flow", () => {
  it("classifies the legs of typical tools", () => {
    expect(legsOf(tool("read_file", "path"))).toEqual(["private"]);
    expect(legsOf(tool("list_issues"))).toEqual(expect.arrayContaining(["untrusted", "private"]));
    expect(legsOf(tool("add_issue_comment", "body"))).toEqual(["egress"]);
    expect(legsOf(tool("fetch", "url"))).toEqual(expect.arrayContaining(["untrusted", "egress"]));
    expect(legsOf(tool("send_email", "to", "body"))).toEqual(["egress"]);
    expect(legsOf(tool("get_forecast", "city"))).toEqual([]);
    expect(legsOf(tool("run_command", "command")).sort()).toEqual(["egress", "private", "untrusted"]);
  });

  it("flags a server that holds all three legs by itself, at low severity, with permission names", () => {
    const fs = toxicFlowFindings([{ server: server("github"), tools: github }]);
    expect(fs).toHaveLength(1);
    expect(fs[0].rule).toBe("flow/single-server-trifecta");
    expect(fs[0].severity).toBe("low");
    expect(fs[0].server).toBe("github");
    expect(fs[0].remediation).toContain("mcp__github__add_issue_comment");
  });

  it("flags a shell server on its own", () => {
    expect(toxicFlowFindings([{ server: server("term"), tools: shell }]).map((f) => f.rule)).toEqual(["flow/single-server-trifecta"]);
  });

  it("flags the combination across servers as info, naming each leg's servers", () => {
    const fs = toxicFlowFindings([
      { server: server("fetch"), tools: fetchServer },
      { server: server("files"), tools: filesystem },
    ]);
    expect(fs.map((f) => f.rule)).toEqual(["flow/cross-server-trifecta"]);
    expect(fs[0].severity).toBe("info");
    expect(fs[0].title).toContain("fetch");
    expect(fs[0].title).toContain("files");
    expect(fs[0].remediation).toContain("mcp__fetch__fetch");
  });

  it("stays silent when a leg is missing", () => {
    expect(toxicFlowFindings([{ server: server("files"), tools: filesystem }])).toEqual([]);
    expect(toxicFlowFindings([{ server: server("weather"), tools: weather }, { server: server("files"), tools: filesystem }])).toEqual([]);
    expect(toxicFlowFindings([{ server: server("fetch"), tools: fetchServer }, { server: server("weather"), tools: weather }])).toEqual([]);
  });

  it("does not add a cross-server finding when one server already has the whole trifecta", () => {
    const fs = toxicFlowFindings([{ server: server("github"), tools: github }, { server: server("files"), tools: filesystem }]);
    expect(fs.map((f) => f.rule)).toEqual(["flow/single-server-trifecta"]);
  });

  it("uses plugin permission names for plugin servers", () => {
    const fs = toxicFlowFindings([{ server: server("p:github", "plugin"), tools: github }]);
    expect(fs[0].remediation).toContain("mcp__plugin_p_github__add_issue_comment");
  });
});
