# AGENTS.md

Guidance for AI coding agents working in this repository. Product facts live in [docs/PRODUCT.md](docs/PRODUCT.md); user-facing docs in [README.md](README.md).

## What this is

`mcp-security-guard` is a local security scanner for MCP servers, skills, commands and plugins used with Claude Code (also usable from other MCP clients and the CLI). It ships as an npm package, a Claude Code plugin (`plugin/`), a GitHub Action (`action.yml`) and an MCP registry entry (`server.json`).

## Layout

| Path | Purpose |
|------|---------|
| `src/` | TypeScript source (ESM, Node >= 20). Entry points: `index.ts` (MCP server), `cli.ts` (CLI), `hook.ts` (PreToolUse/PostToolUse hook) |
| `src/rules/` | Detection rules: `tool-rules.ts`, `config-rules.ts`, `context-rules.ts` |
| `src/version.ts` | `VERSION`, read from `package.json` (never hardcode it) |
| `src/app/` | Dashboard UI (MCP App), bundled into `plugin/dist/dashboard.html` |
| `plugin/` | What Claude Code installs: manifest, `.mcp.json`, hooks, skill, command, and the committed bundles in `plugin/dist/` |
| `bin/` | npm `bin` entry: no args starts the MCP server, any args run the CLI |
| `scripts/` | `build.mjs`, `build-app.mjs`, `check-rules.mjs`, demo and metrics scripts |
| `test/` | Vitest tests; `test/corpus.ts` is the attack corpus; `test/fixtures/` holds a deliberately malicious server |
| `bench/` | False-positive gate on real servers (network) |

## Commands

```sh
npm ci --ignore-scripts
npm run typecheck     # tsc --noEmit (src, test, scripts)
npm test              # vitest run
npm run build         # bundles to plugin/dist/ (committed) and builds the dashboard
npm run check:rules   # version consistency gate
npm run demo          # offline demo
```

`npm run prepublishOnly` runs typecheck, check:rules, test and build. Do not run `npm publish` from an agent session.

## Rules for changes

- **Version source of truth is `package.json`.** `server.json` (top level and every `packages[]` entry) and `plugin/.claude-plugin/plugin.json` must carry the same version; `src/version.ts` reads it. `npm run check:rules` enforces this and fails if `src/version.ts` contains the version literal. When bumping, edit `package.json`, `package-lock.json`, `server.json`, `plugin/.claude-plugin/plugin.json`, then rebuild. The SARIF schema `2.1.0` and the App API `1.0.0` are not package versions; leave them alone.
- **Rebuild bundles.** `plugin/dist/` is committed and CI fails on `git diff --exit-code -- plugin/dist/`. Run `npm run build` after any change under `src/` and commit the result.
- **Do not weaken tests** to make them pass. Fix the cause. Add a corpus sample (`test/corpus.ts`) for new detections.
- **Source hygiene.** No literal invisible or control characters in `src/`, `test/`, `plugin/skills`, `plugin/commands` (checked by `test/source-hygiene.test.ts`); use `\u` escapes in test payloads.
- **Local-first and opt-in network.** Scanning is local by default. Anything that launches a server needs explicit `confirm_launch`; anything that uses the network needs `confirm_network`/an API key. Do not add telemetry or send paths, arguments, environment, or file contents.
- **Untrusted text.** Text quoted in reports comes from scanned servers; always sanitize/excerpt it (`src/sanitize.ts`).
- **Dependencies are pinned exactly** in `package.json`; CI runs `npm audit --omit=dev`.
- Keep the `Unreleased` section of `CHANGELOG.md` up to date.

## Environment variables read by the code

`MCP_SECURITY_HOME` (state dir, default `~/.claude/mcp-security`), `MCP_SECURITY_AUDIT_LOG` (`on`/`off`), `MCP_SECURITY_SECRET_GUARD` (hook mode, default `ask`), `MCP_SECURITY_SESSION_CHECK` (default `full`), `CLAUDE_PROJECT_DIR`. The threat-feed and team API keys are documented in the README and plugin `userConfig`.
