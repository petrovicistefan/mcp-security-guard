# mcp-security-guard

![mcp-security-guard logo](assets/logo-wide.png)

Security for the MCP servers you use in Claude Code. mcp-security-guard audits every MCP server Claude can reach: servers you configured, servers that plugins bring, and servers from Claude Desktop and other clients on your machine. It finds what can turn a server against you: tool poisoning and hidden instructions, rug pulls (definitions that change after you approved them), shadowing between servers, plaintext secrets, unpinned or vulnerable packages, and tools that can execute code or delete data. Every finding maps to the OWASP MCP Top 10.

It runs locally, needs no account and has no telemetry.

## What you get

- **`/mcp-audit`**: a guided audit with fixes. Claude asks before anything is started or sent over the network.
- **Skills, commands and CLAUDE.md**: `audit_agent_context` scans the text Claude reads besides MCP tools (skills and their scripts, slash commands, subagents, rules, CLAUDE.md and the hooks of installed plugins) for injected instructions, hidden text, credential exfiltration, download-and-run and infostealer scripts. Read-only.
- **Tools for Claude**: list and audit servers, scan tool, prompt and resource definitions, pin trusted servers, check packages on npm/PyPI/OSV, generate a team policy, apply fixes, query the audit log, open an interactive dashboard, and test your own server for command injection.
- **Hooks that run automatically**:
  - at session start: a one-time welcome, re-verification of pinned servers, pinned skills, commands, CLAUDE.md and plugin files (local files only), and the project policy check;
  - before each MCP tool call: asks you to confirm when the arguments contain a credential;
  - after each MCP tool call: warns Claude and you when a response contains injected instructions, hidden characters or a credential.

## What it reads

MCP configuration files: `~/.claude.json`, the project's `.mcp.json`, Claude Code settings, installed and account-synced plugins under `~/.claude/plugins/`, Claude Desktop's config and extensions, Cursor, VS Code and Windsurf MCP configs, and `managed-mcp.json`. For the agent-context scan, the text of `CLAUDE.md`, `.claude/` and `~/.claude/` skills, commands, agents and rules, and the same folders of installed plugins (symlinks are never followed). Also its own files under `~/.claude/mcp-security/` and a project's `.mcp-security.json` policy.

## What it writes

Only under `~/.claude/mcp-security/` (set `MCP_SECURITY_HOME` to move it):

- `pins.json`: hashes of definitions you pinned;
- `context-pins.json`: hashes of the skills, commands, agents, CLAUDE.md and hook files you pinned (never their content);
- `audit.jsonl`: one line per MCP call with the server, tool, time, an input hash and sizes. Never arguments or outputs. Turn it off with `MCP_SECURITY_AUDIT_LOG=off`;
- `backups/`: copies of files before an automatic fix;
- a `welcomed` marker.

It changes a project's `.mcp.json` or `.claude/settings.json` only when you ask for a fix and approve the written plan.

## What it starts or connects to

Nothing without your consent:

- **Scanning a server's definitions** starts that server (stdio) or connects to its URL (remote), using your own configuration. It sends only `initialize` and list requests and never calls a tool.
- **The adversarial test** calls the tools of a server you own with injection payloads. Each payload only creates an empty marker file. It needs two explicit confirmations and skips destructive tools.
- **Container image scans** run Trivy or Grype if they are already installed. Nothing is installed.

## What it sends over the network

Only when you opt in:

- **Supply-chain check**: package names and versions go to `registry.npmjs.org`, `pypi.org` and `api.osv.dev`.
- **Threat feed (paid plan)**: only if you enter an API key in the plugin's settings (it is stored in your system's secure storage). Package names and versions, plus SHA-256 hashes of tool definitions (never the definitions themselves), go to `mcp-security-cloud.petrovicistefan.workers.dev` over https. If the service is unreachable, the audit continues without it. The service stores no request data: it reads your key's hash and the feed, and Cloudflare, its host, uses your IP only for rate limiting.

Nothing else leaves your machine. Secrets found in configs or traffic are masked in every output and never logged.

## Settings

| Variable | Effect |
|---|---|
| `MCP_SECURITY_SESSION_CHECK` | `full` (default), `config` (launch nothing) or `off` |
| `MCP_SECURITY_SECRET_GUARD` | `ask` (default), `deny` or `off` |
| `MCP_SECURITY_AUDIT_LOG` | `off` disables the audit log |
| `MCP_SECURITY_HOME` | Where its files are kept |

Source, tests, benchmarks, privacy and security policy: [github.com/petrovicistefan/mcp-security-guard](https://github.com/petrovicistefan/mcp-security-guard). MIT licensed.
