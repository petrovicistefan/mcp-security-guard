# Offline tool-poisoning demo

Requires Node.js 20+. Run these commands from the repository root. The committed CLI bundle needs no dependency installation for this demo.

## 1. Scan the problematic description

```sh
node plugin/dist/cli.mjs analyze-tools examples/offline-demo/poisoned.json --name offline-demo
```

Expected: `tool/instruction-override` at critical severity and `tool/sensitive-path` at high severity. The command exits with code **1**, meaning it found a problem, not that it crashed.

## 2. Compare the clean description

```sh
node plugin/dist/cli.mjs analyze-tools examples/offline-demo/clean.json --name offline-demo
```

Expected: no findings and exit code **0**. Only the description changes between the two files.

## 3. Save an HTML report

```sh
node plugin/dist/cli.mjs analyze-tools examples/offline-demo/poisoned.json --name offline-demo --format html --output demo-report.html --fail-on none
```

Open `demo-report.html` in a browser. `--fail-on none` keeps this report-generation command successful even when findings exist.

To verify both samples automatically, run `npm run demo`. This launches the local CLI against saved JSON only: no MCP server is launched, no tools are called, and no API key or network access is needed. The poisoned file contains synthetic text, not executable attack code.

A clean report means no modeled pattern was found; it does not prove a server safe. See the root README's trust model.

## Recording a short walkthrough

Show the problematic description, run its scan, show the clean description, and run the clean scan. End with the generated HTML report and the contribution guide. Explain the two exit codes rather than presenting the first one as a crash.
