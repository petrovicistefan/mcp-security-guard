# Changelog

## 0.6.0

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
