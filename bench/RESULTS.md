# Benchmark results (2026-10-05, v0.4.0)

Used to calibrate rules and catch false positives before release. Re-run with:

```
npm run build
node dist/cli.mjs scan bench/remote-public.json --confirm-launch --fail-on none
node dist/cli.mjs audit --project bench/marketplace --project-only --fail-on none

# stdio servers, isolated (images built once with network, run with --network none)
docker build -t mcpsec-bench-node -f bench/sandbox/Dockerfile.node bench/sandbox
docker build -t mcpsec-bench-python -f bench/sandbox/Dockerfile.python bench/sandbox
node dist/cli.mjs scan bench/stdio-sandbox.json --confirm-launch --timeout 60 --fail-on none
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

## 3. Official stdio reference servers: sandboxed (7 servers, 52 tools)

filesystem, memory, everything, sequential-thinking (npm 2026.8.31) and git, fetch, time (PyPI 2026.8.18). Each runs with
`--network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 256m --pids-limit 128`.

| Finding | Verdict | Action |
|---|---|---|
| `tool/shadowing`: everything's "ID of the text resource to fetch" matched the `fetch` server's tool | ❌ false positive | Fixed: plain-word tool names only count when quoted, called like `fetch(...)`, or followed by "tool" |
| `tool/embedded-url` (raw.githubusercontent.com default in everything) | ✅ correct, info | Kept |
| `tool/oversized-description` on sequentialthinking | ✅ correct, low | Kept |
| `config/docker-unpinned-image` ×7 | ✅ expected | Local benchmark tags have no digest |

After the fix: **0 critical/high findings across 17 legitimate servers (83 tools)**, and 2 false positives found and fixed in total.

## 4. Detection rate: attack corpus (`test/corpus.ts`, runs in CI)

27 attack samples re-creating publicly documented techniques, plus 13 benign hard negatives modelled on how real servers describe themselves (kubeconfig paths, AWS credential chains, `.env.example`, legit `upload`/`bcc` tools, API sequencing).

Techniques covered: tool poisoning and `<IMPORTANT>` tags (Invariant Labs), line jumping and ANSI escape deception (Trail of Bits), full-schema poisoning in parameter names, defaults, enums, `type` and `required` (CyberArk), tool shadowing (identifier and plain-word names), tool-name collision, zero-width / Unicode-tag / bidi smuggling, homoglyph names, base64 payloads, HTML comments, whitespace padding, exfiltration via URLs, parameters and Markdown images.

| | Before (v0.3.0) | After (v0.4.0) |
|---|---|---|
| Attacks detected (medium or above) | 19/27 (70%) | **26/27 (96%)** |
| Benign samples flagged high or above | 4/13 | **0/13** |
| Benign samples flagged medium | 1/13 | **0/13** |
| Real servers (17 legit, 83 tools): critical/high/medium | 0 | **0** |

What changed:
- **New rules:** `ansi-escape`, `control-characters`, `name-collision`, `schema-anomaly` (non-schema text in `type`), `context-harvesting` (conversation history, system prompt), `markdown-exfiltration`, `hidden-comment`.
- **`sensitive-path` is now context-aware:** high only when the sentence also tells the model to act (read, include, pass, send, paste…). A bare mention such as "uses ~/.kube/config" is low. This removed all 4 high false positives.
- **`precondition-chain`** ignores sequencing between a server's own tools ("first call list_projects").
- **Parameter names** are read as words (`content_from_reading_ssh_id_rsa`), and `type`/`format` fields are analysed.
- **Report output** now escapes ANSI and control characters, so a malicious description cannot drive the terminal that shows the report.

**Known miss:** `multilingual-override` (a Romanian "ignore previous instructions"). The regex rules are English-only. That is the case for the planned LLM-based semantic analysis.

Out of scope for static checks: Advanced Tool Poisoning (instructions in tool *outputs* at runtime, CyberArk) and rug pulls between scans. Pinning covers rug pulls; outputs need the planned `PostToolUse` hook.

## Not yet covered
- OAuth-protected remote servers (GitHub, Linear, Semgrep, Vercel…).
- Community servers, and known-malicious samples beyond our own fixture. Next: collect published tool-poisoning PoCs to measure detection rate, not just false positives.
