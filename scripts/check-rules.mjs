// Release consistency gate (npm run check:rules): package.json is the single source of truth for the version.
// Fails if package.json, server.json (top level and every package entry), the plugin manifest and the
// loaded src/version.ts export disagree, or if src/version.ts hardcodes the version literal.
// Not versions of this package and intentionally ignored: SARIF schema 2.1.0, App API 1.0.0.
import { build } from "esbuild";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (rel) => JSON.parse(readFileSync(join(root, rel), "utf8"));
const errors = [];

const pkg = readJson("package.json");
const version = pkg.version;
if (typeof version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  errors.push(`package.json version is not valid semver: ${JSON.stringify(version)}`);
}

// server.json: top-level version and every package entry
const server = readJson("server.json");
if (server.version !== version) errors.push(`server.json version ${JSON.stringify(server.version)} != package.json ${version}`);
for (const [i, p] of (server.packages ?? []).entries()) {
  if (p.version !== version) errors.push(`server.json packages[${i}] (${p.identifier}) version ${JSON.stringify(p.version)} != package.json ${version}`);
}
if (server.name !== pkg.mcpName) errors.push(`server.json name ${JSON.stringify(server.name)} != package.json mcpName ${JSON.stringify(pkg.mcpName)}`);

// Claude plugin manifest ships the same release
const plugin = readJson("plugin/.claude-plugin/plugin.json");
if (plugin.version !== version) errors.push(`plugin/.claude-plugin/plugin.json version ${JSON.stringify(plugin.version)} != package.json ${version}`);

// src/version.ts must not hardcode the package version
const versionSrc = readFileSync(join(root, "src/version.ts"), "utf8");
const codeOnly = versionSrc.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
if (codeOnly.includes(version)) errors.push(`src/version.ts hardcodes the package version literal "${version}"; it must read package.json`);
if (/export\s+const\s+VERSION\s*=\s*["'`]\d+\.\d+\.\d+/.test(codeOnly)) errors.push("src/version.ts exports VERSION as a hardcoded semver literal");

// Load the real export. The bundle goes one directory below the root so ../package.json resolves
// exactly as it does for src/version.ts. __PKG_VERSION__ is deliberately not defined here.
const tmp = join(root, ".check-rules-tmp");
try {
  mkdirSync(tmp, { recursive: true });
  const outfile = join(tmp, "version.mjs");
  await build({ entryPoints: [join(root, "src/version.ts")], bundle: true, platform: "node", format: "esm", target: "node20", outfile, logLevel: "silent" });
  const mod = await import(pathToFileURL(outfile).href);
  if (mod.VERSION !== version) errors.push(`src/version.ts VERSION ${JSON.stringify(mod.VERSION)} != package.json ${version}`);
} catch (e) {
  errors.push(`could not load src/version.ts: ${e instanceof Error ? e.message : String(e)}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (errors.length) {
  console.error("check:rules FAILED");
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}
console.log(`check:rules OK: package.json = server.json = plugin.json = src/version.ts = ${version}`);
