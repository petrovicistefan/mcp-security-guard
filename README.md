# mcp-security

A Claude Code plugin that audits the **MCP servers you have installed**. Your code is covered by other tools. This one checks the servers that inject text into Claude's context.

| Check | What it catches |
|---|---|
| Tool poisoning | Instruction overrides, "don't tell the user", `<IMPORTANT>` tags, sensitive paths (`~/.ssh`, `.env`), exfiltration wording, encoded payloads, in descriptions *and* schema strings |
| Invisible Unicode | Zero-width, bidi-control and tag characters that hide text from human reviewers |
| Tool shadowing | A server whose descriptions reference another server's tools |
| Rug pulls | Tool definitions that changed after you pinned them (SHA-256 per tool) |
| Configuration | Plaintext secrets in env/headers/args/URLs, plain-HTTP remotes, unpinned `npx`/`uvx` packages, privileged or unpinned Docker images, pipe-to-shell launches, duplicate names across scopes |

Everything runs locally. Nothing is sent anywhere.

## Install

```
/plugin marketplace add <github-user>/mcp-security
/plugin install mcp-security@mcp-security
```

Then run `/mcp-audit`, or ask Claude *"are my MCP servers safe?"*.

## Tools

| Tool | Launches servers? |
|---|---|
| `list_mcp_servers` | No |
| `audit_mcp_config` | No |
| `audit_server_tools` | Yes, after explicit `confirm_launch: true`. Sends only `initialize` and `tools/list`; never calls a scanned tool |
| `pin_tools` | Yes (same as above). Writes `~/.claude/mcp-security/pins.json` |
| `analyze_tool_definitions` | No. Offline analysis of a `tools/list` payload, for MCP server authors |

## Trust model

- Read-only, apart from the pin file.
- Evidence from scanned servers is sanitised (invisible characters revealed, length capped) and labelled as untrusted data.
- Secrets are masked in all output.
- Static checks reduce risk. They do not prove a server safe: malicious behaviour in tool *responses* or server code is out of scope.

## Development

```
npm install
npm run build      # bundles to dist/index.mjs (committed, so the plugin runs without npm install)
npm test
```

`test/fixtures/poisoned-server.mjs` is a deliberately malicious server used by the end-to-end test.

## License

MIT
