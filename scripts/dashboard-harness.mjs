// Local MCP Apps host for developing the dashboard: `npm run dashboard:dev [-- <project dir>]`.
// Starts the real mcp-security-guard server over stdio, renders plugin/dist/dashboard.html in a sandboxed iframe
// through the official AppBridge, and proxies the app's tool calls to the server.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const projectDir = resolve(process.argv[2] ?? process.cwd());
const port = Number(process.env.PORT ?? 8792);

const client = new Client({ name: "dashboard-harness", version: "0" });
await client.connect(
  new StdioClientTransport({ command: process.execPath, args: [join(root, "plugin/dist/index.mjs")], env: { ...getDefaultEnvironment(), ...process.env, CLAUDE_PROJECT_DIR: projectDir }, stderr: "inherit" }),
);
const dashboardUri = (await client.listTools()).tools.find((t) => t.name === "security_dashboard")?._meta?.ui?.resourceUri;
if (!dashboardUri) throw new Error("security_dashboard has no _meta.ui.resourceUri");

// Host page: AppBridge wired to /call, which forwards to the MCP server.
const hostJs = (
  await build({
    stdin: {
      contents: `
        import { AppBridge, PostMessageTransport } from "@modelcontextprotocol/ext-apps/app-bridge";
        const call = (name, args) => fetch("/call", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name, arguments: args }) }).then((r) => r.json());
        const params = new URLSearchParams(location.search);
        const theme = params.get("theme") === "dark" ? "dark" : "light";
        document.documentElement.dataset.theme = theme;
        const html = await fetch("/resource").then((r) => r.text());
        const bridge = new AppBridge(null, { name: "dashboard-harness", version: "0" }, { serverTools: {}, openLinks: {}, logging: {}, updateModelContext: { text: {}, structuredContent: {} } });
        bridge.oncalltool = (p) => call(p.name, p.arguments ?? {});
        bridge.onmessage = async (p) => { document.getElementById("log").textContent += "sendMessage: " + JSON.stringify(p.content) + "\\n"; return {}; };
        bridge.onupdatemodelcontext = async (p) => { document.getElementById("log").textContent += "updateModelContext: " + JSON.stringify(p.structuredContent ?? p.content) + "\\n"; return {}; };
        bridge.oninitialized = async () => {
          bridge.setHostContext({ theme });
          await bridge.sendToolResult(await call("security_dashboard", { scan: params.get("scan") === "full" ? "full" : "config", confirm_launch: params.get("scan") === "full" }));
        };
        // Standard host pattern: create the sandboxed iframe with its content, append it, and connect the
        // bridge synchronously, before the app's script can run and send ui/initialize.
        const iframe = document.createElement("iframe");
        iframe.id = "app";
        iframe.sandbox = "allow-scripts";
        iframe.srcdoc = html;
        document.getElementById("frame").append(iframe);
        bridge.connect(new PostMessageTransport(iframe.contentWindow, iframe.contentWindow));
      `,
      resolveDir: root,
      loader: "js",
    },
    bundle: true,
    write: false,
    format: "esm",
    target: "es2022",
  })
).outputFiles[0].text;

const page = `<!doctype html><html><head><meta charset="utf-8"><title>mcp-security-guard dashboard (dev host)</title>
<style>body{margin:0;font:13px system-ui;background:#e9e8e3} [data-theme=dark] body{background:#0f0f0e;color:#ddd} header{padding:8px 12px}
iframe{display:block;width:100%;height:78vh;border:0;background:transparent} pre{margin:0;padding:8px 12px;max-height:18vh;overflow:auto}</style></head>
<body><header>dev host · <a href="?">light</a> · <a href="?theme=dark">dark</a> · <a href="?scan=full">full scan</a></header>
<div id="frame"></div><pre id="log"></pre><script type="module">${hostJs.replace(/<\/script/gi, "<\\/script")}</script></body></html>`;

createServer(async (req, res) => {
  try {
    if (req.method === "POST" && req.url === "/call") {
      let body = "";
      for await (const c of req) body += c;
      const { name, arguments: args } = JSON.parse(body);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(await client.callTool({ name, arguments: args })));
    } else if (req.url === "/resource") {
      const r = await client.readResource({ uri: dashboardUri });
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(r.contents[0].text);
    } else {
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(page);
    }
  } catch (e) {
    res.statusCode = 500;
    res.end(String(e));
  }
}).listen(port, "127.0.0.1", () => console.log(`dashboard dev host: http://localhost:${port} (project ${projectDir})`));
