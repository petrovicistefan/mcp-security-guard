// Single source of truth for the package version: package.json.
// - Unbundled (tests, tsx): read package.json relative to this file.
// - Bundled (plugin/dist/*.mjs): scripts/build.mjs inlines the value read from package.json via
//   __PKG_VERSION__, so a plugin-only install without package.json still reports the right version.
import { readFileSync } from "node:fs";

declare const __PKG_VERSION__: string | undefined;

const PACKAGE_NAME = "mcp-security-guard";

function readPackageVersion(): string {
  // src/version.ts -> ../package.json; plugin/dist/*.mjs -> ../../package.json
  for (const rel of ["../package.json", "../../package.json"]) {
    try {
      const pkg = JSON.parse(readFileSync(new URL(rel, import.meta.url), "utf8")) as { name?: unknown; version?: unknown };
      if (pkg.name === PACKAGE_NAME && typeof pkg.version === "string" && pkg.version) return pkg.version;
    } catch {
      // try the next candidate
    }
  }
  throw new Error(`Cannot determine ${PACKAGE_NAME} version: package.json not found next to this module`);
}

export const VERSION: string = typeof __PKG_VERSION__ === "string" ? __PKG_VERSION__ : readPackageVersion();
