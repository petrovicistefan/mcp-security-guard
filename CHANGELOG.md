# Changelog

## Unreleased

- **Agent-context scan** (`audit_agent_context`, `audit-context`): scans the text Claude reads besides MCP tools: skills and their bundled scripts, slash commands, subagents, rules, `CLAUDE.md` and the hook configs of installed plugins, from the user, the project and every enabled plugin (symlinks are never followed). Rules `context/*`: instruction override (English and 8 languages), concealment from the user, invisible and bidi text, HTML comments addressed to the model, directives to read credential files, commands that upload credentials, download-and-run, encoded execution, infostealer scripts, image exfiltration, switching off permission checks, pre-approved unrestricted `Bash`. Quoted examples and install snippets are downgraded (`medium` and `low`) so security skills and setup docs do not fail builds. Measured on 934 real files from 6 installed plugins: 0 critical or high findings. Findings carry file and line (SARIF too) and map to the OWASP MCP Top 10 ids
- GitHub Action: `context: true` also scans the repository's skills, commands, subagents and CLAUDE.md (second SARIF file in `context-sarif-file`). Off by default

## 0.7.0

- **Threat feed key via plugin settings**: the API key is a sensitive `userConfig` option kept in the system's secure storage and passed to the MCP server by Claude Code; `MCP_SECURITY_API_KEY` remains for the CLI and CI. Listing icon added
- **Plugin moved to `plugin/`** for the Claude directory: users install only the runtime (manifest, MCP server, hooks, skill, command, bundles, README, license). Source, tests, attack corpus and benchmarks stay in the repository. The dashboard bundle is no longer minified, so reviewers can read it
- **Renamed to mcp-security-guard** (plugin, marketplace, MCP server, CLI, Action, release files), because `mcp-security` is taken on npm and by google/mcp-security. Unchanged for compatibility: the state directory `~/.claude/mcp-security/` (pins, audit log, backups), the `MCP_SECURITY_*` variables and the `.mcp-security.json` policy file. Tool names are now `mcp__plugin_mcp-security-guard_mcp-security-guard__*`; permission rules written for the old names need updating
- **Interactive dashboard (MCP App)** `security_dashboard`: servers with scores, filterable findings, OWASP breakdown, recommended permissions, Full scan and Pin buttons; tells Claude which server the user selected. Rendered in Claude Desktop, claude.ai and other MCP Apps hosts; text summary elsewhere. `npm run dashboard:dev` runs it in a local host against the real server

## 0.6.0

- **First run**: the first session after install shows a one-line, read-only config summary and points to `/mcp-audit`
- **Threat feed (paid plan, opt-in)** wired into full audits: with `MCP_SECURITY_API_KEY` set, package names/versions and tool-definition hashes are checked against the mcp-security-guard feed; without it nothing is sent. Fails open
- **HTML report** (`--format html`): self-contained page with severity counts, scores, OWASP MCP Top 10 breakdown and finding cards, light and dark; no scripts, strict CSP, every server-supplied string escaped
- **Container image vulnerabilities** for Docker-based servers via Trivy or Grype when installed (`scan_images`, `audit --scan-images`)
- Discovers MCP servers of **other clients** (Cursor, VS Code incl. JSON-with-comments settings, Windsurf), **Claude Desktop extensions** (.mcpb) and the organisation-managed **managed-mcp.json**
- **Non-English prompt injection**: instruction-override and concealment patterns in Romanian, Spanish, French, German, Portuguese, Italian, Chinese and Russian, kept within one sentence. Corpus: 32/32 attacks detected, 0/14 benign flagged
- Local server files (`node ./server.js`) are hashed into the pinned launch config, so editing them counts as drift
- **Automatic fixes** (`apply_fixes`, `fix`): add recommended `permissions.ask` rules, pin npx/uvx packages to the current version, replace literal secrets with `${VAR}` references. Dry run by default; backups are kept outside the project (secret-bearing ones 0600) so they can never be committed
- Scans and pins **server instructions, prompts, resources and resource templates**, not only tools
- Discovers MCP servers from **plugins synced from the claude.ai account**, and lists **claude.ai connectors** (names only, policy-checkable)
- Adversarial testing works on Windows (`cmd.exe` payload, `win.ini` traversal check) and defaults to the OS temp directory
- Runtime hook: depth limit and hostile-input tests (huge, deeply nested or malformed payloads)
- Fixed: a `code` parameter (linters, fixers) no longer counts as command execution
- `npm run bench`: false-positive gate on 17 real servers
- Release hardening: exact dependency versions, SHA-pinned GitHub Actions, CycloneDX SBOM, signed build provenance for public releases, cross-platform CI on demand
- LICENSE, SECURITY.md, PRIVACY.md

## 0.5.0

- OWASP MCP Top 10 mapping on every rule, in reports and SARIF
- Security score (0–100, A–F) per server and capability inventory with recommended `permissions.ask` rules
- Runtime hooks: credential guard (PreToolUse), injection and credential detection in tool outputs (PostToolUse), content-free audit log
- Approved-server policy (`.mcp-security.json`) for shadow servers
- Supply-chain checks: OSV, malicious packages, typosquats, install scripts, publisher changes
- Adversarial testing for server authors (command injection, path traversal)

## 0.4.0

- Detection corpus of 27 published attack techniques and 13 benign hard negatives: 96% detection, 0 high false positives
- New rules: ANSI escapes, control characters, name collisions, schema anomalies, context harvesting, Markdown exfiltration, hidden comments

## 0.3.0

- CI mode: SARIF/JSON output, `audit`, `analyze-tools` and `scan` CLI commands, GitHub Action
- MCP servers shipped by installed plugins are discovered
- Benchmarks on public remote servers and official marketplace configs

## 0.2.0

- SessionStart drift check for pinned servers, launch-config hashing

## 0.1.0

- Config audit, tool-poisoning detection, shadowing, tool pinning
