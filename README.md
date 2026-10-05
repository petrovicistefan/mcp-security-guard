# mcp-security

A Claude Code plugin that audits the **MCP servers you have installed**. Your code is covered by other tools. This one checks the servers that inject text into Claude's context.

| Check | What it catches |
|---|---|
| Tool poisoning | Instruction overrides, "don't tell the user", `<IMPORTANT>` tags, directives to read secrets (`~/.ssh`, `.env`), conversation harvesting, exfiltration via URLs, parameters and Markdown images, HTML comments, encoded payloads |
| Full-schema poisoning | The same checks on parameter names, descriptions, defaults, enums, `required`, plus non-schema text in `type` |
| Hidden text | Zero-width, bidi-control and Unicode-tag characters, ANSI terminal escapes, homoglyph tool names |
| Tool shadowing | A server whose descriptions reference another server's tools, and tool-name collisions between servers |
| Rug pulls | Tool definitions or launch commands that changed after you pinned them (SHA-256 per tool). Re-checked automatically at every session start |
| Capabilities & score | Per-tool classification (execute, delete, write, egress), unauthenticated remote write access, 0–100 score and A–F grade per server, recommended permission rules |
| Supply chain | OSV vulnerabilities and malicious versions, typosquats, missing or brand-new packages, install scripts, publisher changes (opt-in network check) |
| Runtime | Hooks on every MCP call: ask before credentials are sent, warn on injected instructions or credentials in outputs, content-free audit log |
| Policy | `.mcp-security.json` approved/blocked servers and hosts, enforced in audits, CI and at session start |
| Configuration | Plaintext secrets in env/headers/args/URLs, plain-HTTP remotes, unpinned `npx`/`uvx` packages, privileged or unpinned Docker images, pipe-to-shell launches, duplicate names across scopes |

It discovers servers from every place Claude Code and Claude Desktop load them: user, local and project scope, **servers shipped inside installed plugins and plugins synced from your claude.ai account** (named `<plugin>:<server>`), `claude_desktop_config.json`, and the **claude.ai connectors** you have used (names only: their configuration lives in your account).

It scans everything a server puts into Claude's context, not only tools: **server instructions, prompts, resources and resource templates** go through the same poisoning checks and are pinned for rug-pull detection.

Everything runs locally. Nothing is sent anywhere.

## OWASP MCP Top 10 coverage

Every finding is tagged with its [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) id, in reports and in SARIF.

| ID | Risk | Covered by |
|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | ✅ Plaintext secrets in env, headers, args and URLs. At runtime, asks before a credential is sent to an MCP server and warns when one comes back. |
| MCP02 | Privilege Escalation via Scope Creep | ✅ Capability inventory (execute, delete, write, egress), ready-to-paste `permissions.ask` rules, privileged or broadly mounted containers |
| MCP03 | Tool Poisoning | ✅ 26/27 published techniques detected, including full-schema poisoning, shadowing and name collisions, plus rug-pull pinning |
| MCP04 | Supply Chain Attacks | ✅ Unpinned packages, images and git sources; OSV vulnerabilities and malicious versions; typosquats; new packages; install scripts; publisher changes |
| MCP05 | Command Injection & Execution | ✅ Flags tools that can execute commands; `adversarial_test` finds injectable parameters in servers you own |
| MCP06 | Prompt Injection via Contextual Payloads | ✅ In tool metadata and, at runtime, in tool outputs (English patterns) |
| MCP07 | Insufficient AuthN/AuthZ | ✅ Plain-HTTP remotes; remote servers exposing write or exec tools without authentication; OAuth detection |
| MCP08 | Lack of Audit and Telemetry | ✅ Local, content-free audit log of every MCP call, with `query_audit_log` |
| MCP09 | Shadow MCP Servers | ✅ Discovery across user, project, local, plugin and Claude Desktop configs; approved-server policy enforced in audits, CI and at session start |
| MCP10 | Context Injection & Over-Sharing | ✅ Conversation and system-prompt harvesting, Markdown-image exfiltration, credentials in outputs, network-egress inventory |

What a local tool cannot do (planned for a hosted Team plan): org-wide discovery and audit aggregation, and OAuth scope review.

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
| `audit_server_tools` | Yes, after explicit `confirm_launch: true`. Sends only `initialize` and list requests (tools, prompts, resources); never calls a tool, renders a prompt or reads a resource |
| `pin_tools` | Yes (same as above). Writes `~/.claude/mcp-security/pins.json` |
| `analyze_tool_definitions` | No. Offline analysis of a `tools/list` payload, for MCP server authors |
| `check_supply_chain` | No. Sends package names and versions to npm, PyPI and OSV after `confirm_network: true` |
| `generate_policy` | No. Returns a `.mcp-security.json` approving the current servers |
| `query_audit_log` | No. Summarises the runtime audit log |
| `adversarial_test` | Yes, and **calls tools** with injection payloads. Only for servers you own; needs `i_own_this_server` and `confirm_launch`; skips destructive tools |

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

Test your own server for command injection and path traversal (it **calls** the tools; run a test instance, ideally in a container):

```
node dist/cli.mjs adversarial my-server.mcp.json --server my-server --i-own-this-server --confirm-launch
```

Start a team policy from the servers configured today:

```
node dist/cli.mjs policy-init && git add .mcp-security.json
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage error.

## Limitations

Remote servers that require OAuth (most hosted MCP servers) cannot be scanned at the tool level: the scanner cannot reuse Claude Code's tokens. Their configuration is still audited.

## Runtime hooks

| Hook | What it does | Setting |
|---|---|---|
| `PreToolUse` on `mcp__*` | Asks for confirmation when a call's arguments contain a credential | `MCP_SECURITY_SECRET_GUARD=ask` (default), `deny` or `off` |
| `PostToolUse` on `mcp__*` | Warns Claude and you when an output contains injected instructions, hidden characters, exfiltration markup or a credential | always on |
| Audit log | `~/.claude/mcp-security/audit.jsonl`: server, tool, time, input hash and sizes. Never arguments or outputs. Rotates at 10 MB. | `MCP_SECURITY_AUDIT_LOG=off` |

The hooks add about 40 ms per MCP call.

## Trust model

- Read-only, apart from the pin file, the audit log, and `policy-init` (which writes a file you asked for).
- Network only when you opt in: `check_supply_chain` / `--supply-chain` send package names and versions to npm, PyPI and OSV. The `adversarial_test` tool is the only one that calls tools.
- Evidence from scanned servers is sanitised (invisible characters revealed, length capped) and labelled as untrusted data.
- Secrets are masked in all output.
- Static checks reduce risk. They do not prove a server safe: malicious behaviour in tool *responses* or server code is out of scope.

## Development

```
npm install
npm run build      # bundles to dist/index.mjs (committed, so the plugin runs without npm install)
npm test
npm run bench      # false-positive gate on real servers (network; Docker images optional, see bench/RESULTS.md)
```

`test/fixtures/poisoned-server.mjs` is a deliberately malicious server used by the end-to-end test.

## License

MIT
