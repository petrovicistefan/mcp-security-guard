import { discoverServers, type DiscoveryResult } from "./config.js";
import { applyPolicy, auditPolicy, loadPolicy, type LoadedPolicy } from "./policy.js";
import { auditDuplicates, auditServerConfig } from "./rules/config-rules.js";
import type { Finding } from "./types.js";

export interface ConfigAudit extends DiscoveryResult {
  findings: Finding[];
  policy?: LoadedPolicy;
}

/** Static config audit shared by the MCP tool and the CLI. `projectOnly` keeps only the repo's .mcp.json, for deterministic CI runs. */
export function auditConfig(projectDir: string, opts: { projectOnly?: boolean } = {}): ConfigAudit {
  const discovered = discoverServers(projectDir);
  const servers = opts.projectOnly ? discovered.servers.filter((s) => s.scope === "project") : discovered.servers;
  const policy = loadPolicy(projectDir);
  const findings = applyPolicy([...servers.flatMap(auditServerConfig), ...auditDuplicates(servers), ...auditPolicy(servers, policy)], policy);
  return { ...discovered, servers, findings, policy };
}
