# DRAFT: What we found scanning 32 MCP server setups (October 2026)

> **Status: draft, not published.** Numbers come from `bench/` and `test/corpus.ts` in this repository and can be reproduced with `npm run bench` and `npm test`. Before publishing: pick the product name, re-run the numbers, and notify the maintainers of the plugins mentioned in section 2.

## TL;DR

- **Unpinned launches are the most common real-world risk.** 4 of 15 MCP server configs in the official Claude Code plugin marketplace (27%) start a server with no fixed version (`@latest`, a bare package name, or a git branch). Every launch runs whatever the registry serves that day.
- **Legitimate servers are clean, and that is the bar for a scanner.** 17 widely used servers (83 tools, 8 prompts, 374 resources, 6 sets of server instructions) produce **no critical, high or medium findings**. Getting there took fixing 3 false positives found on these real servers.
- **Published attack techniques are detectable before a single tool call.** On 32 attack samples re-creating documented tool-poisoning, line-jumping, full-schema-poisoning, shadowing and Unicode/ANSI-smuggling techniques, static checks flag **32/32**, with **0/14** hard benign samples flagged.
- **Tool descriptions are not the only attack surface.** Servers also put server *instructions*, *prompts* and *resource* descriptions into the model's context, and pinning only tool hashes misses a rug pull in any of them.

## 1. What was scanned

| Set | What | How |
|---|---|---|
| Public remote servers | 15 hosted MCP servers (docs, search, knowledge bases, dev tools) | `initialize` + list requests over HTTPS; nothing executed locally |
| Official stdio servers | 7 reference servers (filesystem, memory, everything, sequential-thinking, git, fetch, time) | Run in Docker with `--network none --read-only --cap-drop ALL` |
| Marketplace configs | 15 MCP server definitions shipped by plugins in the official Claude Code marketplace | Static configuration analysis only |
| Attack corpus | 32 attacks + 14 benign samples | Static analysis of tool definitions |

Of the 15 remote servers, 10 could be scanned. 3 require OAuth (GitHub, Linear, Semgrep), and 2 were unreachable.

## 2. Configuration findings in the marketplace

| Plugin | Launch | Finding |
|---|---|---|
| context7 | `npx -y @upstash/context7-mcp` | No version: every launch takes the current release |
| firebase | `npx -y firebase-tools@latest mcp` | `@latest` |
| playwright | `npx @playwright/mcp@latest` | `@latest` |
| serena | `uvx --from git+https://github.com/oraios/serena …` | Git source without a commit SHA |

None of these is a vulnerability in the server itself. They are supply-chain exposure: a compromised release or a hijacked maintainer account would reach every user at their next session, with no review step. The one Docker-based server (terraform) pins an image version and is not flagged. No config contained plaintext secrets.

## 3. False positives are the real engineering problem

Every rule was tested against the 17 legitimate servers. Three looked reasonable in isolation and were wrong in practice:

| Rule | What tripped it | Fix |
|---|---|---|
| Sensitive path | `repost.aws` in an AWS docs server read as `~/.aws` | Dot-directories must start a path segment |
| Tool shadowing | "the resource to *fetch*" read as a reference to another server's `fetch` tool | Plain-word tool names count only when used as a tool name (quoted, called, or "… tool") |
| Command execution | A Svelte linter taking a `code` parameter flagged as executing code | `code`/`script` parameters no longer imply execution |

The third one was introduced by a new rule and only caught because the real-server benchmark was re-run. It now runs as a gate (`npm run bench`) after every rule change.

## 4. Detection on published techniques

| Technique (source) | Samples | Detected |
|---|---|---|
| Tool poisoning: `<IMPORTANT>` tags, credential directives, concealment (Invariant Labs) | 3 | 3 |
| Line jumping and instruction override, incl. 6 non-English variants (Trail of Bits) | 8 | 8 |
| Full-schema poisoning: parameter names, descriptions, defaults, enums, `type`, `required` (CyberArk) | 6 | 6 |
| Tool shadowing and tool-name collision | 4 | 4 |
| Hidden text: zero-width, bidi, Unicode tags, ANSI escapes, homoglyph names, base64 | 6 | 6 |
| Exfiltration via URLs, parameters and Markdown images | 3 | 3 |
| Hidden instructions in HTML comments and whitespace padding | 2 | 2 |
| **Total** | **32** | **32** |

The 14 benign samples are deliberately hard: kubeconfig and AWS credential documentation, `.env.example`, legitimate upload and bcc tools, API call sequencing, and harmless sentences in Romanian, Spanish and German that use the same words as the attacks. None is flagged at medium or above.

**What static checks cannot see:** instructions injected into tool *outputs* at runtime (CyberArk's "Advanced Tool Poisoning"), and attacks phrased in languages or styles the patterns do not cover. Runtime hooks that inspect every MCP response cover the first. The second needs semantic analysis.

## 5. Limitations

- **Small, non-random sample.** These are popular, well-maintained servers; the long tail of community servers is likely worse.
- **Corpus written by the tool's authors.** It is a re-creation of public techniques, not an independent benchmark. Independent attack samples are welcome.
- **Point in time.** Server definitions change; that is the reason for pinning.

## 6. Recommendations

1. Pin every MCP server: `pkg@x.y.z`, `pkg==x.y.z`, an image digest, or a git commit SHA.
2. Re-check pinned definitions at every session start, including instructions, prompts and resources.
3. Require approval for tools that execute code, delete data or write files.
4. Inspect tool outputs at runtime. A poisoned web page or issue body is as dangerous as a poisoned description.
