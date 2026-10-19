# VHS tape for generating a demo GIF
# Install VHS: https://github.com/charmbracelet/vhs
# Run: vhs docs/demo.tape

Output docs/demo.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"

Type "# MCP Security Guard Demo"
Sleep 500ms
Enter
Sleep 500ms

Type "# Quick audit of MCP servers"
Sleep 500ms
Enter
Sleep 500ms

Type "npx mcp-security-guard audit --help"
Sleep 500ms
Enter
Sleep 2s

Type "# Run the offline demo (no installation needed)"
Sleep 500ms
Enter
Sleep 500ms

Type "node scripts/offline-demo.mjs"
Sleep 500ms
Enter
Sleep 3s

Type "# The demo shows tool poisoning detection"
Sleep 1s
Enter
Sleep 1s

Type "# Add mcp-security-guard to your MCP config:"
Sleep 500ms
Enter
Sleep 500ms

Type '# { "mcpServers": { "mcp-security-guard": { "command": "npx", "args": ["-y", "mcp-security-guard"] } } }'
Sleep 2s
Enter
Sleep 1s

Type "# Star the repo: https://github.com/petrovicistefan/mcp-security-guard"
Sleep 2s
