#!/usr/bin/env node
// One entry point for npm: no arguments = the MCP server over stdio (what an MCP client launches),
// any argument = the command line tool (audit, scan, fix, ...).
const dist = new URL("../plugin/dist/", import.meta.url);
await import(new URL(process.argv.length > 2 ? "cli.mjs" : "index.mjs", dist).href);
