# First-week community launch

These are proposed experiments, not predictions of traffic or stars. Post only after the onboarding PR is merged and its checks pass. Social posts and directory submissions are not published by this document.

## Start with one useful demonstration

Record a short walkthrough using [the offline demo](../examples/offline-demo/README.md): problematic description, two findings, clean description, no findings, HTML report. Put the recording in the README when available.

Explain what the scanner checks and its limits. Do not present a clean report as proof of safety.

## Distribution experiments

| Channel | Concrete content | Next action for the reader |
| --- | --- | --- |
| LinkedIn | 30–60 second demonstration and one reproducible example | Try the demo; report unclear output |
| DEV Community or Hashnode | Tutorial: "Review MCP tool descriptions locally without an API key" | Reproduce the two scans |
| Relevant MCP community showcase channels | Concise project introduction following that community's rules | Give feedback or choose a small issue |
| GitHub Discussions Q&A | One real design question at a time from discussion-questions.md | Provide an example and explain the expected behavior |
| Relevant curated tool lists | Submission following the list's contribution rules | Discover the project through a precise description |

Check existing MCP Registry/directory listings before submitting duplicates. Do not promote the project in unrelated support questions.

## Launch copy

I built MCP Security Guard to review MCP configurations and tool descriptions locally. It flags patterns such as instruction overrides, hidden text and risky configuration; a clean scan is not proof that a server is safe.

Try a synthetic offline demo with Node.js 20+, without an account, API key or dependency installation:

```sh
git clone https://github.com/petrovicistefan/mcp-security-guard.git
cd mcp-security-guard
node scripts/offline-demo.mjs
```

I'd welcome feedback on the setup and the findings, especially legitimate descriptions that get flagged. Small contributions are welcome: examples, sanitized regression samples, and client compatibility documentation.

Repository: https://github.com/petrovicistefan/mcp-security-guard
Open tasks: https://github.com/petrovicistefan/mcp-security-guard/issues

If you try it, which client and OS are you using, and was any result unclear?

## Sequence

1. Merge onboarding after review; verify the commands from main.
2. Record the walkthrough and publish one demonstration.
3. Publish one real Q&A question and the tutorial.
4. Share in one relevant showcase channel and review directory eligibility.
5. Respond to feedback, help contributors, and summarize results after seven days.

## Measure useful participation

Record a baseline from GitHub Insights > Traffic before launch. Repository owners can view visitors, views and referring sites; record the results during the week because the traffic window is short.

| Metric | Baseline | After seven days |
| --- | --- | --- |
| Unique visitors | Record at launch | Record |
| Repository views | Record at launch | Record |
| Stars | Record at launch | Record |
| People reporting a demo attempt | 0 for this campaign | Count distinct people |
| Reproducible feedback reports | 0 for this campaign | Count |
| External PRs / merged contributions | Record at launch | Record |

Downloads are not unique users. Compare equal reporting windows and avoid attributing all traffic to one post. Prioritize setup problems and false positives before adding more features.
