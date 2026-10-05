# Privacy

mcp-security runs on your machine. It has **no telemetry**, no account and no server of its own.

## What it reads

- MCP configuration: `~/.claude.json`, project `.mcp.json`, Claude Code settings (`enabledPlugins`), installed and account-synced plugins under `~/.claude/plugins/`, and Claude Desktop's `claude_desktop_config.json`
- Its own files: `~/.claude/mcp-security/pins.json`, `audit.jsonl`, `policy.json`, and a project's `.mcp-security.json`
- Tool, prompt and resource *lists* of servers you explicitly ask it to scan

## What it writes

| File | Content |
|---|---|
| `~/.claude/mcp-security/pins.json` | SHA-256 hashes of pinned definitions and launch configs (no secrets) |
| `~/.claude/mcp-security/audit.jsonl` | Per MCP call: time, session id, server, tool, input hash, sizes, rule ids. **Never arguments or outputs.** Rotated at 10 MB; disable with `MCP_SECURITY_AUDIT_LOG=off` |
| `.mcp-security.json` | Only when you run `policy-init` |

Set `MCP_SECURITY_HOME` to keep these files elsewhere.

## What leaves your machine

Only when you opt in:

- **Supply-chain check** (`check_supply_chain`, `audit --supply-chain`, or the GitHub Action's default `supply-chain: true`) sends **package names and versions** to `registry.npmjs.org`, `pypi.org` and `api.osv.dev`.
- **Scanning a remote MCP server** connects to the URL in your own configuration, sending the headers you configured there.

- **Threat feed (paid plan)**, only when you set `MCP_SECURITY_API_KEY`: package names and versions, plus SHA-256 hashes of tool definitions (never the definitions themselves), are sent to the mcp-security service, deduplicated and without saying which server uses what. The key is only sent over https. If the service is unreachable the audit continues without it.

Nothing else is sent. Secrets found in configs or tool traffic are masked in every output and never logged.
