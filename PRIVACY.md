# Privacy

mcp-security-guard runs on your machine. It has **no telemetry**, no account and no server of its own.

## What it reads

- MCP configuration: `~/.claude.json`, project `.mcp.json`, Claude Code settings (`enabledPlugins`), installed and account-synced plugins under `~/.claude/plugins/`, and Claude Desktop's `claude_desktop_config.json`
- The text of `CLAUDE.md`, `.claude/` and `~/.claude/` skills, commands, subagents and rules, and the same folders and hook configs of installed plugins (agent-context scan; symlinks are not followed)
- Its own files: `~/.claude/mcp-security/pins.json`, `context-pins.json`, `audit.jsonl`, `policy.json`, and a project's `.mcp-security.json`
- Tool, prompt and resource *lists* of servers you explicitly ask it to scan

## What it writes

| File | Content |
|---|---|
| `~/.claude/mcp-security/pins.json` | SHA-256 hashes of pinned definitions and launch configs (no secrets) |
| `~/.claude/mcp-security/context-pins.json` | SHA-256 hashes of pinned skills, commands, subagents, CLAUDE.md, hook configs and scripts, per origin, with plugin versions. No content |
| `~/.claude/mcp-security/audit.jsonl` | Per MCP call: time, session id, server, tool, input hash, sizes, rule ids. **Never arguments or outputs.** Rotated at 10 MB; disable with `MCP_SECURITY_AUDIT_LOG=off` |
| `.mcp-security.json` | Only when you run `policy-init` |

Set `MCP_SECURITY_HOME` to keep these files elsewhere.

## What leaves your machine

Only when you opt in:

- **Supply-chain check** (`check_supply_chain`, `audit --supply-chain`, or the GitHub Action's default `supply-chain: true`) sends **package names and versions** to `registry.npmjs.org`, `pypi.org` and `api.osv.dev`.
- **Scanning a remote MCP server** connects to the URL in your own configuration, sending the headers you configured there.

- **Threat feed (paid plan)**, only when you set `MCP_SECURITY_API_KEY`: package names and versions, plus SHA-256 hashes of tool definitions (never the definitions themselves), are sent to the mcp-security-guard service (`mcp-security-cloud.petrovicistefan.workers.dev`, or the URL in `MCP_SECURITY_API_URL`), deduplicated and without saying which server uses what. When you run an agent-context scan (`audit_agent_context`, `audit-context`) the same request also carries the **SHA-256 of the bytes of each skill, command, subagent, rule, `CLAUDE.md`, hook config and bundled script** it found, and the **names and versions of the installed plugins**, so known-malicious files and plugins can be flagged; never their content, paths or the names of your skills. The key is only sent over https. If the service is unreachable the audit continues without it.

**What the threat-feed service keeps:** nothing from your requests. It looks up the SHA-256 hash of your API key and reads the feed; package names, versions and tool hashes are processed in memory and dropped, and there is no request log. Cloudflare, which hosts the service (Workers, D1 in Western Europe), uses your IP address and the hash of your key as 60-second rate-limit counters and keeps its own aggregate request analytics (counts, status codes). No other processor is involved.

Nothing else is sent. Secrets found in configs or tool traffic are masked in every output and never logged.
