// Mapping of every rule to the OWASP MCP Top 10 (2025): https://owasp.org/www-project-mcp-top-10/

export const OWASP_MCP: Record<string, string> = {
  MCP01: "Token Mismanagement & Secret Exposure",
  MCP02: "Privilege Escalation via Scope Creep",
  MCP03: "Tool Poisoning",
  MCP04: "Software Supply Chain Attacks & Dependency Tampering",
  MCP05: "Command Injection & Execution",
  MCP06: "Prompt Injection via Contextual Payloads",
  MCP07: "Insufficient Authentication & Authorization",
  MCP08: "Lack of Audit and Telemetry",
  MCP09: "Shadow MCP Servers",
  MCP10: "Context Injection & Over-Sharing",
};

const BY_RULE: [RegExp, string[]][] = [
  [/^config\/(plaintext-secret|secret-in-args|secret-in-url)$/, ["MCP01"]],
  [/^runtime\/secret-in-(args|output)$/, ["MCP01", "MCP10"]],
  [/^config\/docker-(privileged|broad-mount|host-network)$/, ["MCP02"]],
  [/^capability\/(destructive|filesystem-write)$/, ["MCP02"]],
  [/^capability\/command-execution$/, ["MCP05", "MCP02"]],
  [/^capability\/network-egress$/, ["MCP10"]],
  [/^flow\//, ["MCP10", "MCP06"]],
  [/^config\/(unpinned-package|docker-unpinned-image|pipe-to-shell|shell-wrapper)$/, ["MCP04"]],
  [/^supply-chain\//, ["MCP04"]],
  [/^feed\/package$/, ["MCP04"]],
  [/^feed\/tool$/, ["MCP03", "MCP04"]],
  [/^feed\/context$/, ["MCP03", "MCP04"]],
  [/^feed\/plugin$/, ["MCP04"]],
  [/^drift\/config-changed$/, ["MCP04"]],
  [/^drift\/tool-/, ["MCP03", "MCP04"]],
  [/^drift\/context-/, ["MCP03", "MCP04"]],
  [/^config\/(insecure-transport|invalid-url)$/, ["MCP07"]],
  [/^auth\//, ["MCP07"]],
  [/^config\/(duplicate-name|claude-ai-connector)$/, ["MCP09"]],
  [/^policy\/(blocked|unapproved)-plugin$/, ["MCP04", "MCP09"]],
  [/^policy\//, ["MCP09"]],
  // Skills, commands, CLAUDE.md and hooks are not MCP, but their risks map onto the same list.
  [/^context\/(instruction-override|conceal-from-user|invisible-characters|ansi-escape|hidden-comment)$/, ["MCP03", "MCP06"]],
  [/^context\/(exfil-command|credential-stealer)$/, ["MCP01", "MCP10"]],
  [/^context\/(sensitive-path|markdown-exfiltration)$/, ["MCP10"]],
  [/^context\/(pipe-to-shell|encoded-execution)$/, ["MCP05", "MCP04"]],
  [/^context\/(overbroad-tools|permission-weakening)$/, ["MCP02"]],
  [/^tool\/(instruction-override|role-hijack)$/, ["MCP03", "MCP06"]],
  [/^runtime\/injection-in-output$/, ["MCP06"]],
  [/^tool\/(sensitive-path|context-harvesting|exfiltration-wording|markdown-exfiltration)$/, ["MCP03", "MCP10"]],
  [/^tool\//, ["MCP03"]],
  [/^adversarial\/command-injection$/, ["MCP05"]],
  [/^adversarial\/path-traversal$/, ["MCP05", "MCP10"]],
  [/^adversarial\//, ["MCP05"]],
];

export function owaspFor(rule: string): string[] {
  return BY_RULE.find(([re]) => re.test(rule))?.[1] ?? [];
}

export function owaspLabel(rule: string): string {
  return owaspFor(rule)
    .map((id) => `${id} ${OWASP_MCP[id]}`)
    .join("; ");
}
