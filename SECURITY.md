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

## Local automatic fixes

Fix planning records the canonical project root and SHA-256 of the reviewed target bytes.
Applying a plan refuses symlink targets/directories, paths other than `.mcp.json` and
`.claude/settings.json`, non-regular files, duplicate targets and changed contents.
Targets and backups are written with owner-only permissions. Temporary files live in
unique private directories; an exclusive per-target lock serializes cooperating writers.
A leftover `.mcpsec-lock` after process termination requires inspection before manual removal.

These portable Node filesystem checks are not OS-level isolation from another hostile
process that can continuously replace project directories between system calls. Run
fixes only while the project is quiescent and under a trusted filesystem owner. A batch
is preflighted, but individual file replacements are atomic rather than a multi-file transaction.
