// Bundles the dashboard UI into one self-contained HTML file (dist/dashboard.html), the format MCP
// Apps hosts render in a sandboxed iframe with a deny-by-default CSP.
import { build } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const result = await build({
  entryPoints: [join(root, "src/app/dashboard-app.ts")],
  bundle: true,
  write: false,
  format: "iife",
  target: "es2022",
  minify: true,
  legalComments: "none",
});
const js = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
const html = readFileSync(join(root, "src/app/dashboard.html"), "utf8").replace("/*__APP_JS__*/", () => js);
writeFileSync(join(root, "dist/dashboard.html"), html);
console.log(`dist/dashboard.html ${(html.length / 1024).toFixed(1)}kb`);
