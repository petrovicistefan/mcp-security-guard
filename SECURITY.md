# Security policy

mcp-security-guard is a security tool, so a flaw in it can hurt the people relying on it. Reports are very welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead: **Security › Report a vulnerability** on this repository.

Include what you found, how to reproduce it, and the impact you expect. You will get an acknowledgement within 3 working days and a status update at least weekly until it is resolved. Credit is given in the release notes unless you prefer otherwise.

## In scope

- Ways to make the scanner or the hooks **execute code**, write outside `~/.claude/mcp-security`, or send data anywhere other than npm, PyPI and OSV
- **Leaks of secrets** in reports, SARIF, the audit log or hook messages
- Output that lets a scanned server **inject instructions or terminal escapes** into the report or hook text
- **Bypasses**: a server definition, rug pull or runtime payload that should be caught by a documented rule but is not
- Anything that makes a hook **block or crash** a Claude Code session

Detection gaps that are already documented in [bench/RESULTS.md](bench/RESULTS.md), such as non-English prompt injection, are known limitations. Still tell us if you find a cheap way to close one.

## Supported versions

Only the latest release receives fixes.
