# Benchmark results (2026-10-05, v0.3.0)

Used to calibrate rules and catch false positives before release. Re-run with:

```
npm run build
node dist/cli.mjs scan bench/remote-public.json --confirm-launch --fail-on none
node dist/cli.mjs audit --project bench/marketplace --project-only --fail-on none
```

## 1. Public remote servers: live `tools/list` (15 servers)

10 scanned (31 tools), 3 need OAuth (GitHub, Linear, Semgrep), 2 unreachable (remote.mcpservers.org).

| Finding | Verdict | Action |
|---|---|---|
| `tool/sensitive-path` on aws-knowledge (`repost.aws` matched as `~/.aws`) | ❌ false positive | Fixed: dot-directories must start a path segment |
| `tool/oversized-description` on context7, aws-knowledge, huggingface (2000+ chars) | ✅ correct, low | Kept as low/informational |

After the fix: **0 critical/high/medium findings on 10 legitimate servers.**

## 2. Official marketplace plugin configs: static (15 servers, nothing executed)

| Server | Finding | Verdict |
|---|---|---|
| context7 | `npx -y @upstash/context7-mcp` not pinned | ✅ true positive |
| firebase | `firebase-tools@latest` not pinned | ✅ true positive |
| playwright | `@playwright/mcp@latest` not pinned | ✅ true positive |
| serena | `uvx --from git+https://github.com/oraios/serena`, no commit SHA | ✅ true positive (rule added during benchmark) |
| terraform | Docker image pinned to `0.4.0` | ✅ correctly not flagged |

## Not yet covered
- Local stdio servers (`@modelcontextprotocol/server-*`, filesystem, git, Slack…): running them executes third-party code, so they will be benchmarked in a network-isolated Docker container.
- OAuth-protected remote servers.
