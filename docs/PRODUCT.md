# MCP Security Guard: product overview

Facts below are taken from `README.md`, `package.json`, `server.json`, `plugin/` and `src/`. See the README for full detail.

## Summary

A local audit tool for the text and configuration that AI clients load from MCP servers, skills, commands, subagents, rules, `CLAUDE.md` and plugin hooks. Findings are mapped to the OWASP MCP Top 10. Nothing leaves the machine unless the user opts in.

- Package: `mcp-security-guard` (npm, MIT, Node >= 20)
- Registry name: `io.github.petrovicistefan/mcp-security-guard` (`server.json`, stdio transport)
- Author: Stefan Petrovici

## Distribution surfaces

| Surface | How |
|---------|-----|
| MCP server | `npx -y mcp-security-guard` (no arguments starts the server over stdio) |
| CLI | `npx -y mcp-security-guard <command>` |
| Claude Code plugin | `plugin/` (MCP server, hooks, `/mcp-audit` command, `mcp-audit` skill) |
| GitHub Action | `petrovicistefan/mcp-security-guard` (`action.yml`), SARIF output, optional `context: true` |

## Capabilities

- **Discovery**: user, local and project scope, servers shipped in plugins, Claude Desktop config and extensions, managed config, other clients (Cursor, VS Code, Windsurf), claude.ai connectors.
- **Tool poisoning and shadowing**: tool names, descriptions, full schemas, server instructions, prompts and resources; hidden Unicode; cross-server collisions.
- **Rug-pull pinning**: SHA-256 of tool definitions and launch commands (`~/.claude/mcp-security/pins.json`), and of skills, commands, subagents, rules, `CLAUDE.md` and plugin hook configs (`context-pins.json`); re-checked at session start.
- **Agent-context scan**: instruction overrides, concealment, invisible text, credential-read and upload directives, download-and-run, encoded execution.
- **Configuration audit**: plaintext secrets, plain-HTTP remotes, unpinned `npx`/`uvx`/Docker, privileged containers, pipe-to-shell launches.
- **Supply chain** (opt-in network): OSV, npm, PyPI checks; typosquats, install scripts, publisher changes.
- **Capabilities and score**: per-tool classification, 0-100 score and A-F grade per server, recommended `permissions.ask` rules, toxic-flow ("lethal trifecta") posture notes.
- **Runtime hooks**: PreToolUse/PostToolUse on `mcp__.*` tools; ask before credentials are sent, warn on injected instructions or credentials in outputs; local content-free audit log.
- **Policy**: `.mcp-security.json` and user policy for approved/blocked servers, hosts and plugins.
- **Fixes**: dry-run-by-default plans for `permissions.ask`, version pinning and `${VAR}` secret references, with backups.
- **BOM**: CycloneDX 1.6 agent bill of materials, or a Markdown summary.
- **Adversarial test**: calls tools of a server you own with injection/traversal payloads; requires explicit confirmation.

## MCP tools

`list_mcp_servers`, `audit_mcp_config`, `audit_agent_context`, `pin_context`, `audit_server_tools`, `pin_tools`, `analyze_tool_definitions`, `check_supply_chain`, `adversarial_test`, `security_dashboard`, `apply_fixes`, `generate_policy`, `team_status`, `request_approval`, `team_report`, `export_bom`, `query_audit_log`.

## CLI commands

`audit`, `audit-context`, `bom`, `pin-context`, `analyze-tools`, `adversarial`, `fix`, `policy-init`, `team`, `scan` (run `mcp-security-guard` with an unknown command for the usage text; the source is the `USAGE` string in `src/cli.ts`).

## Safety model

- Read-only by default; launching scanned servers needs `confirm_launch`, network checks need `confirm_network`.
- Scans never call scanned tools (only `adversarial_test` does, for servers you own).
- Text quoted from scanned servers is untrusted and sanitized in reports.
- Audit log stores hashes and sizes only, never arguments or outputs.

## Team plan (paid, opt-in)

Requires a team API key and the matching backend. Org policy sync (cached, enforced offline, applied next to user and project policy), fleet report (names and versions only, admin must enable), approval requests, admin CLI commands (`approve`, `reject`, `inventory`, `compliance`, `policy-push`, `settings`, keys). The free plugin sends nothing without an API key.

## Versioning

`package.json` is the single source of truth. `server.json`, `plugin/.claude-plugin/plugin.json` and `src/version.ts` must match; `npm run check:rules` enforces it and `prepublishOnly` runs it. SARIF schema `2.1.0` and App API `1.0.0` are format versions, not package versions.

## Source of record

Privacy: `PRIVACY.md`. Security reporting: `SECURITY.md`. Release notes: `CHANGELOG.md`.
