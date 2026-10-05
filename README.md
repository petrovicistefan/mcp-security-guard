# mcp-security

A Claude Code plugin that audits the **MCP servers you have installed**. Your code is covered by other tools. This one checks the servers that inject text into Claude's context.

| Check | What it catches |
|---|---|
| Tool poisoning | Instruction overrides, "don't tell the user", `<IMPORTANT>` tags, directives to read secrets (`~/.ssh`, `.env`), conversation harvesting, exfiltration via URLs, parameters and Markdown images, HTML comments, encoded payloads |
| Full-schema poisoning | The same checks on parameter names, descriptions, defaults, enums, `required`, plus non-schema text in `type` |
| Hidden text | Zero-width, bidi-control and Unicode-tag characters, ANSI terminal escapes, homoglyph tool names |
| Tool shadowing | A server whose descriptions reference another server's tools, and tool-name collisions between servers |
| Rug pulls | Tool definitions or launch commands that changed after you pinned them (SHA-256 per tool). Re-checked automatically at every session start |
| Configuration | Plaintext secrets in env/headers/args/URLs, plain-HTTP remotes, unpinned `npx`/`uvx` packages, privileged or unpinned Docker images, pipe-to-shell launches, duplicate names across scopes |

It discovers servers from every place Claude Code and Claude Desktop load them: user, local and project scope, **servers shipped inside installed plugins** (named `plugin:<plugin>:<server>`), and `claude_desktop_config.json`.

Everything runs locally. Nothing is sent anywhere.

**Measured:** detects 26/27 attacks from a corpus of publicly documented techniques, with 0 false positives on 13 hard benign samples and on 17 real servers (83 tools). See [bench/RESULTS.md](bench/RESULTS.md).

## Install

```
/plugin marketplace add petrovicistefan/mcp-security
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

## Session-start check

A `SessionStart` hook re-verifies **only the servers you have pinned** (pinning is your consent to launch them) and stays silent unless something changed. Control it with `MCP_SECURITY_SESSION_CHECK`:

- `full` (default): compare launch configs and re-list tools
- `config`: compare launch configs only, launch nothing
- `off`: disable the check

## CI / GitHub Action

Fail pull requests that add risky MCP servers to `.mcp.json`, and show the findings in GitHub code scanning:

```yaml
name: MCP security
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: petrovicistefan/mcp-security@main
        id: mcp
        with:
          fail-on: high          # critical | high | medium | low | info | none
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.mcp.outputs.sarif-file }}
```

The same checks run locally without Claude:

```
node dist/cli.mjs audit --project-only --format sarif --output mcp.sarif
node dist/cli.mjs analyze-tools tools.json --name my-server   # for MCP server authors: a saved tools/list result
```

Check a server **before installing it** (launches it, sends only `initialize` and `tools/list`):

```
node dist/cli.mjs scan some-server.mcp.json --confirm-launch
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage error.

## Limitations

Remote servers that require OAuth (most hosted MCP servers) cannot be scanned at the tool level: the scanner cannot reuse Claude Code's tokens. Their configuration is still audited.

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
