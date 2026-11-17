// Bundles the MCP server, CLI and hook into plugin/dist/*.mjs. The package version is read from
// package.json and inlined (src/version.ts), so the committed bundles carry the same version.
import { build } from "esbuild";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

await build({
  entryPoints: ["src/index.ts", "src/cli.ts", "src/hook.ts"].map((p) => join(root, p)),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  outdir: join(root, "plugin/dist"),
  outExtension: { ".js": ".mjs" },
  banner: { js: "import{createRequire}from'module';const require=createRequire(import.meta.url);" },
  define: { __PKG_VERSION__: JSON.stringify(version) },
  logLevel: "info",
});
