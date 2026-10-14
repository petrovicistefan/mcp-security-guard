# Contributing

Small, reproducible contributions are welcome: benign regression samples, synthetic detection cases, client configuration tests, and clearer examples.

## Try the project first

With Node.js 20+, clone your fork and run the offline demo without installing dependencies:

```sh
git clone https://github.com/YOUR-USERNAME/mcp-security-guard.git
cd mcp-security-guard
node scripts/offline-demo.mjs
```

See [the walkthrough](examples/offline-demo/README.md) for individual scans and an HTML report.

## Make your first change

1. Choose an [open issue](https://github.com/petrovicistefan/mcp-security-guard/issues), or describe the gap you want to address. Check existing issues and PRs to avoid duplicate work.
2. Create a branch in your fork.
3. Make one focused change. Include reproduction steps and expected findings.
4. Run the relevant checks, then open a PR against `main`.

For development:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run build
npm test
npm run demo
```

CI uses Node.js 20 and 22. Building updates the committed `plugin/dist/` bundles; include changed bundles when source changes require them. A documentation-only change does not need regenerated bundles.

## Add a detection sample

The existing corpus is [test/corpus.ts](test/corpus.ts), exercised by [test/detection.test.ts](test/detection.test.ts).

Add a unique `Sample` entry:

```ts
{
  id: "benign-calendar-description",
  technique: "benign",
  malicious: false,
  tools: [{
    name: "list_events",
    description: "Lists calendar events in the requested date range.",
    inputSchema: { type: "object", properties: {} },
  }],
},
```

Run the focused check:

```sh
npm test -- test/detection.test.ts
```

For synthetic malicious cases, explain the technique and pair it with a legitimate description that looks similar. The corpus currently expects malicious cases at medium severity or above and benign cases below medium. Some legitimate tools warrant review: discuss that expected classification rather than weakening a rule just to make a test pass.

For a false positive, include a minimal sanitized sample and the rule that fired. A failing regression is useful evidence in an issue; a mergeable fix should make it pass without breaking malicious cases. Do not change the known-miss or accepted-medium lists merely to hide a failing case. Add focused rule assertions when the precise rule or severity matters.

## Client configuration contributions

Start with `src/config.ts` and `test/rules.test.ts`; inspect the existing tests before choosing where to add coverage. Use temporary directories and synthetic values. State the client version, OS, config shape, and expected discovery behavior. Tests should not rely on your home directory or installed clients.

## Reports and privacy

Never submit real tokens, private keys, personal conversations, or private configuration paths. Use placeholder credentials and reserved example domains. Share only material you may redistribute, credit sources, and preserve licenses. Do not launch unknown servers to obtain a sample.

Report vulnerabilities in this project using [SECURITY.md](SECURITY.md), rather than a public issue.

## Before opening a PR

- Explain the problem, the resulting behavior, and how you verified it.
- Keep changes scoped; avoid unrelated refactors.
- Include exact commands and any checks you could not run.
- For examples, state expected findings and exit codes.
- For detector changes, include both the problematic case and a benign regression.

The real-server benchmark (`npm run bench`) uses network access and may involve Docker. It is not required to try the offline demo; detector changes may need benchmark evidence during review. See [bench/RESULTS.md](bench/RESULTS.md).
