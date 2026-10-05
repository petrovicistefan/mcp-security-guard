---
description: Security audit of the MCP servers configured for this project (config, tool poisoning, shadowing, rug pulls)
argument-hint: "[server names, default: all]"
---

Run a security audit of the configured MCP servers using the `mcp-audit` skill.

Servers to scan: $ARGUMENTS (if empty, scan all).

1. Call `list_mcp_servers` and `audit_mcp_config`, then summarise the configuration findings.
2. List the servers that `audit_server_tools` would start, and ask me before launching them.
3. After I confirm, run `audit_server_tools` and give a prioritised summary with fixes.
4. For servers that came out clean, offer to pin them with `pin_tools`.
